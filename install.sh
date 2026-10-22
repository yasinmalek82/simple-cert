#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == --help || "${1:-}" == -h ]]; then
    echo 'Install simple-cert v0.1.0 on Ubuntu 22.04/24.04 or Debian 12/13.'
    echo 'Run as root on the mother server. No services or renewal timers are configured.'
    exit 0
fi
if (($#)); then
    echo 'Unknown argument. Use --help.' >&2
    exit 2
fi
if [[ "$(uname -s)" != Linux || "$EUID" -ne 0 ]]; then
    echo 'Run this installer as root on the Linux mother server.' >&2
    exit 1
fi
source /etc/os-release
case "${ID}:${VERSION_ID}" in
    ubuntu:22.04|ubuntu:24.04|debian:12|debian:13) ;;
    *) echo 'Supported systems: Ubuntu 22.04/24.04 and Debian 12/13.' >&2; exit 1 ;;
esac

echo 'Installing prerequisites for simple-cert...'
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 git openssl curl ca-certificates

work_dir="$(mktemp -d)"
trap 'rm -rf -- "$work_dir"' EXIT
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
    --connect-timeout 15 --max-time 120 \
    'https://raw.githubusercontent.com/yasinmalek82/simple-cert/v0.1.0/installer.py' \
    --output "$work_dir/installer.py"
python3 "$work_dir/installer.py"
