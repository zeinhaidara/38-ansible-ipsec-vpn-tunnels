#!/usr/bin/env bash
# Check one swanctl tunnel and publish its state for node_exporter.
# Exit codes: 0 up, 1 down, 2 swanctl failed, 64 bad usage.
set -euo pipefail

if [[ $# -ne 1 || ! $1 =~ ^[a-z0-9-]+$ ]]; then
  echo "usage: ipsec-healthcheck <tunnel-name>" >&2
  exit 64
fi

name=$1
textfile_dir=${TEXTFILE_DIR:-/var/lib/node_exporter/textfile_collector}
metric_file="$textfile_dir/ipsec_tunnel_${name//-/_}.prom"

write_metric() {
  local up=$1
  local tmp
  tmp=$(mktemp "$textfile_dir/.ipsec.XXXXXX")
  {
    echo "# HELP ipsec_tunnel_up 1 if the IKE SA is established and the child SA installed."
    echo "# TYPE ipsec_tunnel_up gauge"
    echo "ipsec_tunnel_up{tunnel=\"$name\"} $up"
    echo "# HELP ipsec_tunnel_check_timestamp_seconds Time of the last check."
    echo "# TYPE ipsec_tunnel_check_timestamp_seconds gauge"
    echo "ipsec_tunnel_check_timestamp_seconds{tunnel=\"$name\"} $(date +%s)"
  } > "$tmp"
  chmod 0644 "$tmp"
  # Rename so node_exporter never reads a half-written file.
  mv "$tmp" "$metric_file"
}

if ! output=$(swanctl --list-sas --ike "$name" 2>&1); then
  echo "error: swanctl failed for $name: $output" >&2
  write_metric 0
  exit 2
fi

if [[ $output == *"$name"*ESTABLISHED* && $output == *INSTALLED* ]]; then
  echo "tunnel $name is up"
  write_metric 1
  exit 0
fi

echo "tunnel $name is down" >&2
write_metric 0
exit 1
