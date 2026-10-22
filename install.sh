#!/usr/bin/env bash
set -euo pipefail

supports_system() {
    if [[ "$1" == ubuntu && "$2" =~ ^([0-9]{2})\.(04|10)$ ]]; then
        ((10#${BASH_REMATCH[1]} >= 22))
    else
        [[ "$1" == debian && ( "$2" == 12 || "$2" == 13 ) ]]
    fi
}

if [[ "${1:-}" == --help || "${1:-}" == -h ]]; then
    echo 'Install simple-cert v0.1.1 on Ubuntu 22.04 or newer, or Debian 12/13.'
    echo 'Run as root on the mother server. No services or renewal timers are configured.'
    echo 'Read-only compatibility check: --check-system ID VERSION_ID'
    exit 0
fi
if [[ "${1:-}" == --check-system && "$#" == 3 ]]; then
    supports_system "$2" "$3"
    exit $?
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
if ! supports_system "${ID:-}" "${VERSION_ID:-}"; then
    echo "Detected system: ${ID:-unknown} ${VERSION_ID:-unknown}." >&2
    echo 'Supported systems: Ubuntu 22.04 or newer, and Debian 12/13.' >&2
    exit 1
fi

echo 'Installing prerequisites for simple-cert...'
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 git openssl curl ca-certificates

work_dir="$(mktemp -d)"
trap 'rm -rf -- "$work_dir"' EXIT
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
    --connect-timeout 15 --max-time 120 \
    'https://raw.githubusercontent.com/yasinmalek82/simple-cert/v0.1.1/installer.py' \
    --output "$work_dir/installer.py"
python3 "$work_dir/installer.py"
