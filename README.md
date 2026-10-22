# Simple Cert

Get a Let's Encrypt certificate through Cloudflare DNS, even when your domain points to a different server.

**Quick install** — Ubuntu 22.04 or newer (including 26.04/26.10), or Debian 12/13, on the mother server:

```bash
curl -fsSL https://raw.githubusercontent.com/yasinmalek82/simple-cert/v0.1.9/install.sh | sudo bash
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

The main menu displays the installed version beside `SIMPLE CERT`.

In an interactive SSH terminal, each menu opens at the top of a cleared screen. Operation results
and errors remain visible until you press Enter; then the menu is redrawn. Terminal scrollback is
preserved. Redirected output and terminals with an unset or `dumb` TERM stay plain, without screen
control sequences or extra Enter prompts.

```text
1. Issue node/config certificate
2. List node/config certificates and file paths
3. Renew node/config certificate
4. Cloudflare settings
5. Update simple-cert
6. Uninstall simple-cert
7. Panel HTTPS certificates (separate files)
0. Exit
```

Renewal is **manual**. Choose option 3 periodically; acme.sh decides whether the certificate is due.
The tool does not force unnecessary renewals. A failed initial request remains in the list and can
be retried through option 3. A duplicate domain set is directed to renewal instead of another issue.
There are no cron jobs, systemd timers, panel API calls, service reloads or node operations.

To view file contents, choose **2**, select a certificate by its number, then choose
**View fullchain.pem** or **View key.pem**. The viewer shows the selected certificate's published
files and returns to certificate details after Enter. Choose **0** to return to the main menu.
Copy only the PEM block between the `BEGIN` and `END` markers, including those markers.

Private keys require both an interactive input/output terminal and an explicit `yes` confirmation;
they cannot be displayed through redirected output. Viewing a key leaves it in terminal scrollback,
so use a private, unrecorded session. No file contents are added to application state or logs.

## Update and uninstall

Choose **5** to check the latest stable published GitHub release. Run the installed tool as root.
After you confirm with `yes`, the updater verifies the installer against GitHub's release-asset
SHA-256 digest; the installer also verifies the application checksum. The program is replaced in
the same location, with no directory per program version. The installed version is checked before
success is reported. The menu then exits; run `simple-cert` again to load the update.
Settings, ACME accounts, keys and all certificate versions are kept. A failed download or checksum
check leaves the existing installation in place. If an installation fails after replacement, inspect
`simple-cert --version` before retrying or rerun the bootstrap installer to repair it.

Choose **6** to uninstall. The menu shows the current program's version and path and asks you to
type `uninstall`. If it detects other recognized installations, it lists their versions and paths
and asks separately whether to remove them too; the default is to keep them. Cancelling the first
confirmation removes nothing. Uninstall preserves private state and certificates, including files
that may already be used by a service. It does not remove Python, OpenSSL or other system packages.

Discovery checks the running copy, the standard `/usr/local`, `/usr` and `~/.local` installation
prefixes, plus `simple-cert` commands on `PATH`. Recognition uses a matching installation manifest
or the exact published application hashes for versions 0.1.0 through 0.1.3. Source checkouts,
modified/unrecognized copies and unrelated files are left in place. The tool does not scan the
entire filesystem. Cleanup removes only recognized program files and their matching command links;
unknown files inside an installation directory are retained. The uninstall menu requires a terminal.

For releases older than 0.1.4, run the quick-install command above once to gain the Update menu.

## Files and privacy

Use the same OS user each time (the instructions above use root). Private state defaults to
`~/.local/share/simple-cert/`, which is `/root/.local/share/simple-cert/` when run as root.
An explicit private directory can be selected with `simple-cert --state-dir /your/private/path`.
Do not place it inside a repository or a public web directory.

```text
<state>/certificates/<domain>--<certificate-id>/current/fullchain.pem
<state>/certificates/<domain>--<certificate-id>/current/key.pem
```

New certificate folders include the first domain and a stable identifier, for example
`cloudisnap.yasin-ai-54.ir--<identifier>`. Wildcard-only certificates use `wildcard.example.com--<identifier>`.
The identifier distinguishes certificates with different domain sets. Domain labels longer than
200 characters are shortened to fit filesystem limits. Existing hash-only folders and registered
panel delivery paths remain unchanged and continue to renew. For an existing certificate, choose
**2 → select certificate → 3** and accept the new domain-based default to publish a readable panel path;
then update the paths in your Core manually. Earlier paths remain available and are also renewed.

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
on the mother server; changing active panel/node management TLS is outside its scope.

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
python3 tests/maintenance_acceptance.py
```

Tests generate disposable certificates and substitute only external ACME/network boundaries. They do
not use real Cloudflare credentials, request public certificates or change system services. Installer
smoke checks use a temporary installation prefix and verify reinstall behavior. Live CA issuance and
the supported Linux deployment targets require separate runtime acceptance; offline tests do not
prove a real Cloudflare/CA transaction.

The maintenance acceptance script uses only disposable installation prefixes and dummy preservation
markers. Its default mode checks the real terminal uninstall flow without network access.
The manually dispatched `Maintenance acceptance` workflow additionally exercises a real public
GitHub update as root into a temporary prefix, followed by uninstall; it never changes the runner's
system installation or uses Cloudflare credentials.

## Node/config Core file delivery through the mother panel

Run simple-cert on the **mother panel host**. After node/config issuance, a detected local PasarGuard
container offers an optional Core file delivery prompt. You can also use **2 → select certificate → 3**
to publish later or choose another directory. Confirm the displayed host and container filesystem paths
by typing `yes`. The default directory inside the panel is:

```text
/var/lib/pasarguard/certs/simple-cert/<domain>--<certificate-id>/current/fullchain.pem
/var/lib/pasarguard/certs/simple-cert/<domain>--<certificate-id>/current/key.pem
```

The detected `DATA_DIR` replaces `/var/lib/pasarguard` when configured. Paste the **container
filesystem paths** printed by the tool into the selected Core's Certificate file and Key file fields,
with **Serve on node disabled**. The master reads the PEMs and supplies certificate material
to the node; the Germany node does not need these file paths. This command only publishes
files. It does not edit Core settings, restart services or prove live node TLS.

Automatic detection supports running official `pasarguard/panel` Docker images on a local,
rootful Docker daemon without user namespace remapping. A writable bind mount or named
volume must cover the detected data directory. Remote Docker, native/systemd installations,
custom images and inaccessible readers need manual file placement. Root is usually required
on the host to set the panel reader's UID/GID. Docker must already be installed.

The tool resolves the most specific mount, refuses symlink paths, read-only mounts and
nonempty unmanaged directories, and verifies matching PEMs from inside the container using
the panel's default user. Keys have mode `0600`; no world-readable private keys are created.
This check assumes the panel processes use the container's configured default user.

The private source is retained for renewal. Successful manual renewal refreshes every
registered delivery destination. A failed reader check before publication keeps its previous
certificate pair, records a pending delivery and leaves the local renewal intact. Retry via
certificate details after correcting access. Selecting another directory retains earlier
deliveries because an existing Core may still reference them. Uninstall also retains these
files. Do not delete an older path until its Core references have been updated.

Docker acceptance uses an isolated Python fixture container with the official image-name
pattern and generated test certificates; it verifies real mounts, non-root file access and
renewal publication. It does not run a production PasarGuard panel or issue real certificates.

## Panel HTTPS certificates: a separate section

Choose **7** in the main menu for the website/dashboard certificate, separate from the
certificates used for node/config Core TLS. This submenu supports **1: issue**, **2: list and
view PEM files**, **3: manual renewal**, **4: refresh current HTTPS status**, and **0: return**.
Its files, ACME client state and certificate list are isolated under `<state>/panel-https/`. The Cloudflare account settings
from main-menu option 4 are shared. You can use a different domain for the panel.

An existing certificate configured manually in PasarGuard's `.env` is not imported or
replaced. The tool does not edit `.env`, change SSL environment settings, adopt existing
PEMs, attach files to the HTTPS listener, or restart/recreate any service. New panel
certificates are separate files only; using them for the running panel requires a deliberate
manual configuration change. Renewing them updates only the files managed in this section.
The panel section cannot publish files through the node/config Core delivery action.

**Host filesystem directory** means a directory on the mother server. **Container filesystem
directory** means the same mounted files as seen inside the PasarGuard Docker container.
These labels describe filesystem paths, not the panel's website URL, domain or IP. Depending
on Docker mount mapping, the two paths may be identical or different. Use the container path
printed by node/config delivery in the Core's Certificate file and Key file fields. This
file-copy operation does not configure the panel website's HTTPS certificate. Cancelling
before the `yes` confirmation publishes no certificate files to the selected destination.

## Inspecting the existing panel HTTPS certificate

Opening **7** first shows a read-only report for the existing panel configuration, including
certificate DNS names, expiry in UTC, days remaining, the configured certificate/key paths,
and host mount mappings. Read-only mounts and normal certificate live/archive symlinks are
supported. Certificate metadata is decoded with OpenSSL; the status inspector does not read
private key contents or import existing files into its certificate list.

The running official Docker container's `UVICORN_SSL_*` environment is preferred. If absent,
a Compose-labelled working directory's `.env` is a **configuration candidate**, explicitly
marked as not runtime-verified. With no detected container, `/opt/pasarguard/.env` is inspected
as the standard candidate. Env files are parsed for an allowlist of TLS/listener fields, never
sourced as shell code. Tokens, passwords, raw crontab lines and service commands are not printed.

**Renewal evidence** is associated with the configured host certificate path, not merely
with an installed program or a timer name:

- acme.sh: a matching `Le_RealFullChainPath` export record and a recognized cron/systemd job.
- Certbot: a matching renewal configuration's `fullchain` path and a recognized renewal job.
- The report distinguishes a schedule with an active scheduler, an inactive scheduler, unknown
  scheduler state, and a tracking record without a matching schedule. A missing match is reported
  as **unknown**, not as proof that no automation exists.
- Timer next-run time and last service result are shown when available. A default service result
  without a recorded exit timestamp is not presented as a completed renewal. Per-record reload
  hooks are reported as configured/not found; their commands are never executed.

The inspector reads current-user/system cron files and accessible cron spools, queries systemd
timer/service metadata, and checks standard acme.sh and Certbot records plus homes explicitly
referenced by recognized jobs. Only direct clients and simple env/shell wrappers are recognized.
Custom scripts, unusual homes, other containers/users, global deploy hooks and incomplete access
can prevent attribution. It does not execute renewal clients, hooks, inspected commands or services.
The systemd scan is bounded and unavailable/partial inspection is indicated. Reports are cached
while the submenu is open; choose **4** to refresh. Root is recommended for complete read access.

The current [official PasarGuard installer](https://github.com/PasarGuard/scripts/blob/main/pasarguard.sh)
uses acme.sh for its Let's Encrypt setup, installs a cron renewal job and registers a reload hook.
Pointing `UVICORN_SSL_CERTFILE`/`UVICORN_SSL_KEYFILE` at a manually obtained certificate does not
by itself establish an automatic renewal schedule. This report checks local evidence independently
of the installer defaults.

This is the certificate **configured on disk**. It does not prove that a running HTTPS process has
reloaded that file. Public URLs cannot be safely inferred from a wildcard/multi-domain certificate,
a bind address or a proxy/CDN configuration, so the public URL remains **not confirmed**. DNS names
in the certificate are displayed separately. External/live TLS and reverse-proxy certificates are
not probed. No existing certificate, `.env`, cron job, service or timer is changed.
