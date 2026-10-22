#!/usr/bin/env python3
"""Small Cloudflare DNS-01 certificate menu. Runtime: Python stdlib + OpenSSL."""

import argparse
import contextlib
import datetime as dt
import fcntl
import getpass
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
import warnings
from pathlib import Path

VERSION = "0.1.2"
ACME_COMMIT = "3688b094adffc1a52d3b994c586cd97caa2f0b85"
CA = "https://acme-v02.api.letsencrypt.org/directory"
MENU = """
  SIMPLE CERT
  Cloudflare DNS verification | Let's Encrypt
  ------------------------------------------------
  1. Issue certificate
  2. List certificates and file paths
  3. Renew certificate
  4. Cloudflare settings
  0. Exit
  ------------------------------------------------
"""


class Error(Exception):
    """A safe, operator-facing error without raw command output."""


def run(argv, *, env=None, cwd=None, allowed=(0,), timeout=1800, message=None):
    try:
        result = subprocess.run(
            argv,
            env=env,
            cwd=cwd,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise Error(message or "Command unavailable or timed out; private output suppressed.") from None
    if result.returncode not in allowed:
        raise Error(message or "Operation failed; private command output suppressed.")
    return result


def private_dir(path):
    if path.is_symlink():
        raise Error("A private directory must not be a symbolic link.")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)
    return path


def save(path, value):
    """Replace JSON atomically, with private permissions and durable intent."""
    private_dir(path.parent)
    descriptor, temporary = tempfile.mkstemp(prefix=".write-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w") as stream:
            json.dump(value, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        sync_dir(path.parent)
    finally:
        Path(temporary).unlink(missing_ok=True)


def sync_dir(path):
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def load(path):
    try:
        result = json.loads(path.read_text())
        if not isinstance(result, dict):
            raise ValueError
        return result
    except (ValueError, OSError):
        raise Error(
            "Cannot read saved settings or certificate state. Check the private state directory."
        ) from None


@contextlib.contextmanager
def locked(root):
    private_dir(root)
    descriptor = os.open(root / "operation.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Error("Another simple-cert operation is running. Try again when it finishes.") from None
        yield
    finally:
        os.close(descriptor)


def normalize_domains(values):
    domains = set()
    for value in values:
        raw = value.strip().lower().removesuffix(".")
        wildcard = raw.startswith("*.")
        raw = raw[2:] if wildcard else raw
        try:
            name = raw.encode("idna").decode("ascii")
        except UnicodeError:
            raise Error("Enter a DNS name, such as example.com or *.example.com.") from None
        labels = name.split(".")
        if (
            len(name) > 253
            or len(labels) < 2
            or all(part.isdigit() for part in labels)
            or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part) for part in labels)
        ):
            raise Error(
                "Enter a DNS name, such as example.com or *.example.com. URLs and IPs are not accepted."
            )
        domains.add(("*." if wildcard else "") + name)
    if not domains:
        raise Error("At least one domain is required.")
    return sorted(domains, key=lambda name: (name.startswith("*."), name))


def validate_pair(folder, domains, *, check_validity=True):
    cert, key = str(folder / "fullchain.pem"), str(folder / "key.pem")
    message = "Invalid or unreadable certificate/key files; old certificate retained."
    details = run(
        [
            "openssl",
            "x509",
            "-in",
            cert,
            "-noout",
            "-dates",
            "-ext",
            "subjectAltName",
        ],
        message=message,
    ).stdout.decode("ascii", errors="replace")
    public_cert = run(["openssl", "x509", "-in", cert, "-noout", "-pubkey"], message=message).stdout.strip()
    public_key = run(
        [
            "openssl",
            "pkey",
            "-in",
            key,
            "-pubout",
            "-passin",
            "pass:",
        ],
        message=message,
    ).stdout.strip()
    if public_cert != public_key:
        raise Error("Certificate and private key do not match; old certificate retained.")
    names = set(re.findall(r"DNS:([^,\s]+)", details))
    if not set(domains).issubset(names):
        raise Error("Certificate does not contain the requested DNS names; old certificate retained.")
    try:
        dates = dict(
            line.split("=", 1)
            for line in details.splitlines()
            if line.startswith(("notBefore=", "notAfter="))
        )
        start = dt.datetime.strptime(dates["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=dt.timezone.utc
        )
        end = dt.datetime.strptime(dates["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.timezone.utc)
    except (KeyError, ValueError):
        raise Error("Certificate validity dates could not be read.") from None
    if check_validity and not start <= dt.datetime.now(dt.timezone.utc) < end:
        raise Error("Certificate is expired or not yet valid; old certificate retained.")
    return {"expires_at": end.isoformat()}


class Manager:
    def __init__(self, root):
        self.root = Path(root).expanduser().absolute()
        private_dir(self.root)

    def config(self):
        path = self.root / "settings.json"
        if not path.exists():
            raise Error("Configure Cloudflare settings first (menu option 4).")
        result = load(path)
        if not result.get("email") or not result.get("token"):
            raise Error("Configure Cloudflare settings first (menu option 4).")
        return result

    def configure(self, email, token):
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email) or len(email) > 254:
            raise Error("Enter a valid ACME account email address.")
        if not token or len(token) > 1024 or any(char.isspace() or ord(char) < 32 for char in token):
            raise Error("Enter a valid Cloudflare API token without spaces or newlines.")
        with locked(self.root):
            save(self.root / "settings.json", {"email": email, "token": token})

    def harden(self):
        # acme.sh also saves DNS tokens in its own configuration files.
        for directory, _, files in os.walk(self.root, followlinks=False):
            Path(directory).chmod(0o700)
            for name in files:
                path = Path(directory) / name
                if not path.is_symlink():
                    path.chmod(0o600)

    def install_engine(self):
        engine = self.root / "engine"
        if (engine / "acme.sh").is_file():
            if not (engine / "revision").is_file() or (engine / "revision").read_text() != ACME_COMMIT:
                raise Error("Unexpected ACME engine revision. Restore the dedicated engine before retrying.")
            return
        print("Preparing the dedicated ACME client (first use only)...", flush=True)
        with tempfile.TemporaryDirectory(prefix="engine-", dir=self.root) as temporary:
            source = Path(temporary)
            run(["git", "init", str(source)])
            run(
                [
                    "git",
                    "-C",
                    str(source),
                    "fetch",
                    "--depth",
                    "1",
                    "https://github.com/acmesh-official/acme.sh.git",
                    ACME_COMMIT,
                ],
                timeout=300,
                message="Cannot download the ACME client. Check access to github.com.",
            )
            run(["git", "-C", str(source), "checkout", "--detach", "FETCH_HEAD"])
            actual = run(["git", "-C", str(source), "rev-parse", "HEAD"]).stdout.decode().strip()
            if actual != ACME_COMMIT:
                raise Error("ACME client revision verification failed.")
            # The engine remains private; it is always invoked through sh, never executed directly.
            shutil.copytree(source, engine, ignore=shutil.ignore_patterns(".git"))
            (engine / "revision").write_text(ACME_COMMIT)
        self.harden()

    def obtain(self, record, destination, renew=False):
        config = self.config()
        self.install_engine()
        env = {key: value for key, value in os.environ.items() if not key.startswith("CF_")}
        env.update({"CF_Token": config["token"], "LC_ALL": "C", "AUTO_UPGRADE": "0"})
        account = private_dir(self.root / "account")
        cert_home = private_dir(self.root / "acme-certificates" / record["id"])
        export = private_dir(self.root / "acme-exports" / record["id"])
        base = [
            "sh",
            str(self.root / "engine" / "acme.sh"),
            "--home",
            str(self.root / "engine"),
            "--config-home",
            str(account),
            "--cert-home",
            str(cert_home),
            "--server",
            CA,
            "--no-color",
        ]
        failure = (
            "ACME/Cloudflare operation failed or timed out. Check the token's Zone DNS Edit + Zone Read "
            "permissions, zone access, DNS propagation, CAA records and CA rate limits. "
            "Private ACME output is suppressed; existing certificates are retained."
        )
        try:
            if renew:
                run(
                    [*base, "--renew", "-d", record["domains"][0], "--ecc"],
                    env=env,
                    allowed=(0, 2),
                    message=failure,
                )
            else:
                run(
                    [*base, "--register-account", "--accountemail", config["email"]], env=env, message=failure
                )
                domains = [item for domain in record["domains"] for item in ("-d", domain)]
                run(
                    [*base, "--issue", "--dns", "dns_cf", "--keylength", "ec-256", *domains],
                    env=env,
                    allowed=(0, 2),
                    message=failure,
                )
            run(
                [
                    *base,
                    "--install-cert",
                    "-d",
                    record["domains"][0],
                    "--ecc",
                    "--fullchain-file",
                    str(export / "fullchain.pem"),
                    "--key-file",
                    str(export / "key.pem"),
                ],
                env=env,
                message=failure,
            )
            # acme.sh remembers export paths and rewrites them during renewal.
            # Never register a published version as an ACME export destination.
            for name in ("fullchain.pem", "key.pem"):
                shutil.copyfile(export / name, destination / name)
        finally:
            self.harden()

    def records(self):
        result = []
        for path in sorted((self.root / "certificates").glob("*/record.json")):
            record = load(path)
            record["active"] = (path.parent / "current" / "fullchain.pem").is_file()
            # The pointer is authoritative if interruption happened after publication.
            if record["active"]:
                record.update(validate_pair(path.parent / "current", record["domains"], check_validity=False))
            result.append(record)
        return result

    def issue(self, domains):
        domains = normalize_domains(domains)
        identifier = hashlib.sha256("\n".join(domains).encode()).hexdigest()[:24]
        with locked(self.root):
            self.config()
            folder = private_dir(self.root / "certificates" / identifier)
            path = folder / "record.json"
            if path.exists():
                raise Error("This domain set is already saved. Use Renew certificate (menu option 3).")
            return self._obtain({"id": identifier, "domains": domains}, folder, renew=False)

    def renew(self, identifier):
        if not re.fullmatch(r"[a-f0-9]{24}", identifier):
            raise Error("Invalid certificate selection.")
        with locked(self.root):
            self.config()
            folder = self.root / "certificates" / identifier
            record = load(folder / "record.json")
            # A failed first issuance can be retried without pretending a certificate already exists.
            active = (folder / "current" / "fullchain.pem").is_file()
            return self._obtain(record, folder, renew=record.get("issued", False) or active)

    def _obtain(self, record, folder, renew):
        record["operation"] = "renewing" if renew else "issuing"
        save(folder / "record.json", record)
        versions = private_dir(folder / "versions")
        version = private_dir(versions / uuid.uuid4().hex)
        link = folder / (".current-" + uuid.uuid4().hex)
        print("Validating DNS and requesting the certificate. This can take several minutes...", flush=True)
        try:
            self.obtain(record, version, renew=renew)
            metadata = validate_pair(version, record["domains"])
            for name in ("fullchain.pem", "key.pem"):
                path = version / name
                path.chmod(0o600)
                with path.open("rb") as stream:
                    os.fsync(stream.fileno())
            sync_dir(version)
            sync_dir(versions)
            record.update({"operation": "publishing", "candidate": version.name})
            save(folder / "record.json", record)
            link.symlink_to(Path("versions") / version.name)
            os.replace(link, folder / "current")
            sync_dir(folder)
            record.update(metadata)
            record.update({"operation": "complete", "issued": True})
            record.pop("candidate", None)
            save(folder / "record.json", record)
            return record
        except BaseException:
            # Preserve a published version even if the final state write was interrupted.
            if (folder / "current").resolve() != version:
                shutil.rmtree(version, ignore_errors=True)
            record["operation"] = "failed"
            save(folder / "record.json", record)
            raise
        finally:
            link.unlink(missing_ok=True)
            self.harden()


def settings_menu(manager):
    if not sys.stdin.isatty():
        raise Error("Settings must be entered in an interactive terminal; tokens use hidden input.")
    previous = manager.config() if (manager.root / "settings.json").exists() else {}
    print("\nCloudflare API token permissions: Zone > DNS > Edit and Zone > Zone > Read.")
    print("Limit the token to the DNS zone(s) you need. Never paste it into a shell command.")
    print("Your email is used for a Let's Encrypt account. Issuing accepts the CA's subscriber agreement.")
    print("Blank input keeps an existing setting.")
    email = input(f"Account email [{previous.get('email', 'not set')}]: ").strip() or previous.get(
        "email", ""
    )
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        try:
            token = getpass.getpass("Cloudflare API token (hidden): ").strip() or previous.get("token", "")
        except getpass.GetPassWarning:
            raise Error("A hidden token prompt is unavailable. Reopen an interactive SSH terminal.") from None
    manager.configure(email, token)
    print("Settings saved privately.")


def show(manager, record):
    folder = manager.root / "certificates" / record["id"] / "current"
    print("\nDomains: " + ", ".join(record["domains"]))
    print("Expires (UTC): " + record.get("expires_at", "not issued"))
    print("Last operation: " + record["operation"])
    if (folder / "fullchain.pem").is_file():
        print(f"Full chain: {folder / 'fullchain.pem'}\nPrivate key: {folder / 'key.pem'}")
        print("Local files only. Copy them to the destination service when needed.")


def menu(manager):
    while True:
        interactive = (
            sys.stdin.isatty() and sys.stdout.isatty() and os.environ.get("TERM", "") not in ("", "dumb")
        )
        if interactive:
            print("\033[2J\033[H", end="", flush=True)
        print(MENU)
        try:
            choice = input("Choose [0-4]: ").strip()
            if choice == "0":
                return
            if choice == "4":
                settings_menu(manager)
            elif choice == "1":
                if not (manager.root / "settings.json").exists():
                    settings_menu(manager)
                domains = normalize_domains([input("Domain (example.com or *.example.com): ")])
                if (
                    not domains[0].startswith("*.")
                    and input("Include *." + domains[0] + " as well? [y/N]: ").strip().lower() == "y"
                ):
                    domains.append("*." + domains[0])
                print("DNS must be hosted on Cloudflare. No A/AAAA or proxy changes are required.")
                if (
                    input("Issue a public Let's Encrypt certificate for these names? [y/N]: ").strip().lower()
                    == "y"
                ):
                    show(manager, manager.issue(domains))
            elif choice in ("2", "3"):
                records = manager.records()
                if not records:
                    print("No certificates saved yet.")
                else:
                    for index, record in enumerate(records, 1):
                        print(
                            f"{index}. {', '.join(record['domains'])} | {record.get('expires_at', 'not issued')} | {record['operation']}"
                        )
                        if choice == "2":
                            show(manager, record)
                    if choice == "3":
                        selection = input("Certificate number (0 to cancel): ").strip()
                        if selection == "0":
                            continue
                        if not selection.isdigit() or not 1 <= int(selection) <= len(records):
                            raise Error("Invalid certificate number.")
                        print("The ACME client renews only when due; no forced renewal is performed.")
                        show(manager, manager.renew(records[int(selection) - 1]["id"]))
            else:
                print("Invalid choice. Choose a number from 0 to 4.")
        except Error as error:
            print(f"\nError: {error}")
        except KeyboardInterrupt:
            print("\nCancelled. Any existing certificate files are retained.")
        except EOFError:
            print("\nGoodbye.")
            return
        if interactive:
            try:
                input("Press Enter to return to the menu...")
            except EOFError:
                print("\nGoodbye.")
                return
            except KeyboardInterrupt:
                print()


def main():
    parser = argparse.ArgumentParser(
        prog="simple-cert", description="Interactive Cloudflare DNS-01 certificate tool."
    )
    parser.add_argument("--version", action="version", version=f"simple-cert {VERSION}")
    parser.add_argument(
        "--state-dir",
        type=Path,
        default=Path.home() / ".local/share/simple-cert",
        help="Private state directory (default: ~/.local/share/simple-cert)",
    )
    args = parser.parse_args()
    os.umask(0o077)
    try:
        menu(Manager(args.state_dir))
    except Error as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    except OSError:
        print(
            "Error: Cannot access private files or a required command. Check permissions and disk space.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
