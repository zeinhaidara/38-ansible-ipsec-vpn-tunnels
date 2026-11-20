"""Run the health check script against a fake swanctl on PATH. Linux only."""

import os
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parent.parent / "roles" / "ipsec_tunnel" / "files" / "ipsec-healthcheck.sh"

UP = """onprem-cloud: #3, ESTABLISHED, IKEv2, 1a2b3c4d5e6f7a8b_i* 9a8b7c6d5e4f3a2b_r
  local  'CN=onprem-gw.example.com' @ 198.51.100.10[4500]
  remote 'CN=cloud-gw.example.com' @ 203.0.113.20[4500]
  onprem-cloud: #4, reqid 1, INSTALLED, TUNNEL, ESP:AES_GCM_16-256
    local  192.168.10.0/24
    remote 10.20.0.0/16
"""
CONNECTING = "onprem-cloud: #5, CONNECTING, IKEv2, 1a2b3c4d5e6f7a8b_i*\n"


def run(tmp_path, stdout="", code=0, args=("onprem-cloud",)):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    fake = bin_dir / "swanctl"
    (tmp_path / "out.txt").write_text(stdout)
    fake.write_text(f'#!/bin/sh\ncat "{tmp_path}/out.txt"\nexit {code}\n')
    fake.chmod(0o755)
    textfile = tmp_path / "textfile"
    textfile.mkdir(exist_ok=True)
    env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "TEXTFILE_DIR": str(textfile)}
    proc = subprocess.run(["bash", str(SCRIPT), *args], env=env, capture_output=True, text=True)
    metric = textfile / "ipsec_tunnel_onprem_cloud.prom"
    return proc, metric


def test_established_tunnel_reports_up(tmp_path):
    proc, metric = run(tmp_path, UP)
    assert proc.returncode == 0, proc.stderr
    assert 'ipsec_tunnel_up{tunnel="onprem-cloud"} 1' in metric.read_text()
    assert "ipsec_tunnel_check_timestamp_seconds" in metric.read_text()


def test_connecting_tunnel_reports_down(tmp_path):
    proc, metric = run(tmp_path, CONNECTING)
    assert proc.returncode == 1
    assert "down" in proc.stderr
    assert 'ipsec_tunnel_up{tunnel="onprem-cloud"} 0' in metric.read_text()


def test_no_sa_reports_down(tmp_path):
    proc, metric = run(tmp_path, "")
    assert proc.returncode == 1
    assert metric.read_text().count(" 0\n") == 1


def test_ike_up_but_child_missing_is_down(tmp_path):
    proc, _ = run(tmp_path, UP.replace("INSTALLED", "REKEYING"))
    assert proc.returncode == 1


def test_swanctl_failure_exits_2_and_reports_down(tmp_path):
    proc, metric = run(tmp_path, "connecting to 'unix:///var/run/charon.vici' failed", code=1)
    assert proc.returncode == 2
    assert "swanctl failed" in proc.stderr
    assert 'ipsec_tunnel_up{tunnel="onprem-cloud"} 0' in metric.read_text()


@pytest.mark.parametrize("args", [(), ("a", "b"), ("../etc/passwd",), ("Bad Name",)])
def test_bad_usage(tmp_path, args):
    proc, metric = run(tmp_path, UP, args=args)
    assert proc.returncode == 64
    assert not metric.exists()


def test_no_temp_files_left_behind(tmp_path):
    run(tmp_path, UP)
    leftovers = [p.name for p in (tmp_path / "textfile").iterdir() if p.name.startswith(".")]
    assert leftovers == []
