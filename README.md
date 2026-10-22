# Simple Cert

Get a Let's Encrypt certificate through Cloudflare DNS, even when your domain points to a different server.

**Quick install** — Ubuntu 22.04 or newer (including 26.04/26.10), or Debian 12/13, on the mother server:

```bash
curl -fsSL https://raw.githubusercontent.com/yasinmalek82/simple-cert/v0.1.1/install.sh | sudo bash
```

Then open the interactive menu:

```bash
sudo simple-cert
```

If you are already root, omit `sudo`. The install command requires `curl`; on a minimal image run
`sudo apt-get update && sudo apt-get install -y curl ca-certificates` first.

The installer installs Python 3, Git, OpenSSL, curl and CA certificates. It installs the tool under
`/usr/local/lib/simple-cert/` and creates `/usr/local/bin/simple-cert`. Running the installer again
preserves saved credentials and certificates. Runtime Python dependencies: **standard library only**.

Ubuntu releases from 22.04 onward pass the version check, including interim releases. Installation
requires working distribution package repositories and Python 3.10 or newer. End-of-life releases
with archived repositories may fail during `apt-get`; the installer does not change your APT sources.
Both installation stages use the same tested compatibility policy. The original `v0.1.0` tag remains
unchanged; use the updated command above for newer Ubuntu releases.

Compatibility references: [Ubuntu release cycle](https://ubuntu.com/about/release-cycle),
[acme.sh platforms and prerequisites](https://github.com/acmesh-official/acme.sh#supported-platforms).

## First certificate

1. Choose **Issue certificate**. On first use, the menu asks for your email and Cloudflare API token.
2. Use a Cloudflare token with **Zone / DNS / Edit** and **Zone / Zone / Read**, restricted to the
   required zone(s). Enter it only at the hidden terminal prompt.
3. Enter `vpn.example.com`, `example.com` or `*.example.com`. For a normal domain, you can also include
   its wildcard in the same certificate.
4. Confirm issuance. After DNS validation, the tool displays the expiry date and the full paths to
   `fullchain.pem` and `key.pem`.

DNS must be hosted by Cloudflare and covered by the token. A/AAAA records can keep pointing anywhere;
no inbound HTTP port is required. Only the ACME challenge TXT records are created and removed.
Issuance uses the public Let's Encrypt service and accepts its
[subscriber agreement](https://letsencrypt.org/repository/). Public certificate names appear in
Certificate Transparency logs. The first use downloads the official ACME client from GitHub.

## Menu

```text
1. Issue certificate
2. List certificates and file paths
3. Renew certificate
4. Cloudflare settings
0. Exit
```

Renewal is **manual**. Choose option 3 periodically; acme.sh decides whether the certificate is due.
The tool does not force unnecessary renewals. A failed initial request remains in the list and can
be retried through option 3. A duplicate domain set is directed to renewal instead of another issue.
There are no cron jobs, systemd timers, panel API calls, service reloads or node operations.

## Files and privacy

Use the same OS user each time (the instructions above use root). Private state defaults to
`~/.local/share/simple-cert/`, which is `/root/.local/share/simple-cert/` when run as root.
An explicit private directory can be selected with `simple-cert --state-dir /your/private/path`.
Do not place it inside a repository or a public web directory.

```text
<state>/certificates/<certificate-id>/current/fullchain.pem
<state>/certificates/<certificate-id>/current/key.pem
```

The current link switches both files together only after checking the key match, requested DNS names
and validity dates with OpenSSL. Previous versions are retained. Pending issuance and publication
are recorded before their side effects; an interrupted operation may show an unfinished status.
The displayed active paths follow the actual published link. Inspect them before retrying after an
interruption; the tool does not roll back a certificate already published successfully.

Private directories use `0700`; configuration and key files use `0600`. Raw ACME output is suppressed.
acme.sh also saves the token privately in its configuration. Protect or encrypt backups of the entire
state directory. Never send the private key or token in chat, issues or shell arguments.

The dedicated [acme.sh](https://github.com/acmesh-official/acme.sh) engine is pinned to commit
`3688b094adffc1a52d3b994c586cd97caa2f0b85`. It is downloaded at runtime, is licensed separately under
GPL-3.0, and is not bundled in this repository. No existing acme.sh installation is adopted or changed.

The output is local certificate files. Copy them securely to your destination server and configure
your consumer there. The menu does not configure or verify a live TLS service. Keep running this tool
on the mother server; panel/node management TLS is outside its scope.

## If a request fails

Check token scope, the DNS zone's active Cloudflare nameservers, propagation, domain CAA restrictions,
network access and Let's Encrypt rate limits. Fix the cause before retrying. Old published files
remain available when a candidate is invalid or issuance fails. Concurrent writes are blocked.
Do not remove challenge records created by another running ACME client. If the process is forcibly
terminated, a leftover `_acme-challenge` TXT record may need manual cleanup.

## Development

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/pytest -q
.venv/bin/ruff check .
.venv/bin/ruff format --check .
bash -n install.sh
python3 simple_cert.py --help
```

Tests generate disposable certificates and substitute only external ACME/network boundaries. They do
not use real Cloudflare credentials, request public certificates or change system services. Installer
smoke checks use a temporary installation prefix and verify reinstall behavior. Live CA issuance and
the supported Linux deployment targets require separate runtime acceptance; offline tests do not
prove a real Cloudflare/CA transaction.
