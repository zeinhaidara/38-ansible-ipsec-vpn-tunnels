"""Static checks on the role: template output, key handling, no secrets in git."""

import re
import subprocess
from pathlib import Path

import jinja2
import yaml

ROOT = Path(__file__).parent.parent
ROLE = ROOT / "roles" / "ipsec_tunnel"


def render(name: str, **overrides) -> str:
    defaults = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text())
    host = yaml.safe_load((ROOT / "host_vars" / "onprem-gw.example.com.yml").read_text())
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(ROLE / "templates"),
                             undefined=jinja2.StrictUndefined)
    return env.get_template(name).render({**defaults, **host, **overrides})


def test_swanctl_uses_certificates_not_psk():
    conf = render("swanctl.conf.j2")
    assert conf.count("auth = pubkey") == 2
    assert "psk" not in conf.lower()
    assert "secrets" not in conf
    assert 'id = "CN=onprem-gw.example.com"' in conf
    assert "cacerts = onprem-cloud-ca.crt" in conf


def test_swanctl_traffic_selectors():
    conf = render("swanctl.conf.j2", ipsec_tunnel_local_subnets=["192.168.10.0/24", "192.168.11.0/24"])
    assert "local_ts = 192.168.10.0/24,192.168.11.0/24" in conf
    assert "remote_ts = 10.20.0.0/16" in conf
    assert "remote_addrs = 203.0.113.20" in conf


def test_braces_balance():
    conf = render("swanctl.conf.j2")
    assert conf.count("{") == conf.count("}")


def test_timer_and_service_units():
    service = render("ipsec-healthcheck.service.j2")
    timer = render("ipsec-healthcheck.timer.j2")
    assert "ExecStart=/usr/local/sbin/ipsec-healthcheck onprem-cloud" in service
    assert "Type=oneshot" in service
    assert "OnUnitActiveSec=1min" in timer


def tasks():
    return yaml.safe_load((ROLE / "tasks" / "main.yml").read_text())


def test_private_key_is_0600_and_not_logged():
    [task] = [t for t in tasks() if "private" in str(t.get("ansible.builtin.copy", {}).get("dest"))]
    assert task["ansible.builtin.copy"]["mode"] == "0600"
    assert task["ansible.builtin.copy"]["owner"] == "root"
    assert task["no_log"] is True


def test_private_dir_is_0700():
    [task] = [t for t in tasks() if t["name"] == "Create swanctl directories"]
    modes = {i["path"]: i["mode"] for i in task["loop"]}
    assert modes["/etc/swanctl/private"] == "0700"


def test_no_failed_when_false_anywhere():
    for f in ROLE.rglob("*.yml"):
        assert not re.search(r"failed_when:\s*false", f.read_text()), f


def test_host_key_checking_stays_on():
    assert "host_key_checking = True" in (ROOT / "ansible.cfg").read_text()


def test_no_key_or_certificate_material_is_tracked():
    files = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True,
                           check=True).stdout.split()
    pattern = re.compile(r"-----BEGIN [A-Z ]*(PRIVATE KEY|CERTIFICATE)-----")
    offenders = [f for f in files if pattern.search((ROOT / f).read_text(errors="ignore"))]
    assert offenders == []
    assert not [f for f in files if f.endswith((".key", ".pem", ".crt", ".p12"))]
    assert not [f for f in files if f.endswith("vault.yml")]
