"""Offline acceptance tests: only the ACME/network boundary is substituted."""

import datetime as dt
import importlib.util
import json
import shutil
import subprocess
import sys
import warnings
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

SCRIPT = Path(__file__).resolve().parents[1] / "simple_cert.py"


@pytest.fixture
def app():
    assert SCRIPT.is_file(), "The standalone certificate tool is not implemented yet"
    spec = importlib.util.spec_from_file_location("simple_cert", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def pair(tmp_path):
    folder = tmp_path / "fixture"
    folder.mkdir()
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(hours=1))
        .not_valid_after(now + dt.timedelta(days=60))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("example.com"), x509.DNSName("*.example.com")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    (folder / "fullchain.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (folder / "key.pem").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return folder


@pytest.mark.parametrize(
    "value", ["", "https://example.com", "-example.com", "a..com", "../x", "foo.*.com", "localhost"]
)
def test_invalid_domains_are_rejected_before_acme(app, value):
    with pytest.raises(app.Error):
        app.normalize_domains([value])


def test_domains_are_normalized_and_wildcard_retained(app):
    assert app.normalize_domains(["EXAMPLE.com.", "*.example.com", "example.com"]) == [
        "example.com",
        "*.example.com",
    ]


def test_generated_pair_is_checked_for_names_and_key(app, pair, tmp_path):
    assert app.validate_pair(pair, ["example.com", "*.example.com"])["expires_at"]
    with pytest.raises(app.Error, match="DNS names"):
        app.validate_pair(pair, ["other.example.com"])
    other = ec.generate_private_key(ec.SECP256R1())
    (pair / "key.pem").write_bytes(
        other.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    with pytest.raises(app.Error, match="match"):
        app.validate_pair(pair, ["example.com"])


def test_settings_validate_and_are_private(app, tmp_path):
    manager = app.Manager(tmp_path / "state")
    with pytest.raises(app.Error):
        manager.configure("not-an-email", "token")
    manager.configure("admin@example.com", "secret-token")
    assert manager.config()["token"] == "secret-token"
    assert manager.root.stat().st_mode & 0o777 == 0o700
    assert (manager.root / "settings.json").stat().st_mode & 0o777 == 0o600
    with pytest.raises(app.Error):
        manager.configure("admin@example.com", "token\nwith-newline")


@pytest.fixture
def manager(app, tmp_path, pair, monkeypatch):
    tool = app.Manager(tmp_path / "state")
    tool.configure("admin@example.com", "secret-token")

    def obtain(record, destination, renew=False):
        # A saved operation intent must exist BEFORE the external ACME action.
        saved = json.loads((tool.root / "certificates" / record["id"] / "record.json").read_text())
        assert saved["operation"] == ("renewing" if renew else "issuing")
        for filename in ("fullchain.pem", "key.pem"):
            shutil.copyfile(pair / filename, destination / filename)

    monkeypatch.setattr(tool, "obtain", obtain)
    return tool


def test_issue_publishes_pair_and_lists_paths(manager):
    record = manager.issue(["example.com", "*.example.com"])
    listed = manager.records()
    assert len(listed) == 1
    current = manager.root / "certificates" / record["id"] / "current"
    assert current.is_symlink()
    assert (current / "key.pem").stat().st_mode & 0o777 == 0o600
    assert listed[0]["expires_at"]
    assert listed[0]["operation"] == "complete"


def test_successful_renew_retains_previous_version(manager):
    record = manager.issue(["example.com"])
    current = manager.root / "certificates" / record["id"] / "current"
    previous = current.resolve()
    manager.renew(record["id"])
    assert current.resolve() != previous
    assert (previous / "key.pem").is_file()


def test_failed_renew_preserves_active_pair_and_hides_raw_error(manager, app, monkeypatch, capsys):
    record = manager.issue(["example.com"])
    current = manager.root / "certificates" / record["id"] / "current"
    previous = current.resolve()

    def fail(*args, **kwargs):
        raise app.Error("Cloudflare validation failed. Check DNS permissions.")

    monkeypatch.setattr(manager, "obtain", fail)
    with pytest.raises(app.Error):
        manager.renew(record["id"])
    assert current.resolve() == previous
    assert manager.records()[0]["operation"] == "failed"
    assert "secret-token" not in capsys.readouterr().out


def test_bad_candidate_never_replaces_existing_pair(manager, app, monkeypatch):
    record = manager.issue(["example.com"])
    current = manager.root / "certificates" / record["id"] / "current"
    previous = current.resolve()

    def invalid(record, destination, renew=False):
        (destination / "fullchain.pem").write_text("invalid")
        (destination / "key.pem").write_text("invalid")

    monkeypatch.setattr(manager, "obtain", invalid)
    with pytest.raises(app.Error):
        manager.renew(record["id"])
    assert current.resolve() == previous


def test_acme_environment_and_arguments_do_not_expose_token(app, tmp_path, monkeypatch, pair):
    manager = app.Manager(tmp_path / "state")
    manager.configure("admin@example.com", "secret-token")
    engine = manager.root / "engine"
    engine.mkdir()
    (engine / "acme.sh").write_text("fixture")
    (engine / "revision").write_text(app.ACME_COMMIT)
    calls = []
    monkeypatch.setenv("CF_Key", "unwanted-global-key")

    def boundary(argv, **kwargs):
        calls.append((argv, kwargs))
        if "--install-cert" in argv:
            shutil.copyfile(pair / "fullchain.pem", argv[argv.index("--fullchain-file") + 1])
            shutil.copyfile(pair / "key.pem", argv[argv.index("--key-file") + 1])
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.setattr(app, "run", boundary)
    record = {"id": "test", "domains": ["example.com", "*.example.com"]}
    destination = tmp_path / "export"
    destination.mkdir()
    manager.obtain(record, destination)
    issue = next(item for item in calls if "--issue" in item[0])
    assert issue[0][issue[0].index("--dns") + 1] == "dns_cf"
    assert "*.example.com" in issue[0]
    for argv, kwargs in calls:
        assert "secret-token" not in " ".join(map(str, argv))
        assert kwargs["env"]["CF_Token"] == "secret-token"
        assert "CF_Key" not in kwargs["env"]


def test_command_failure_never_leaks_raw_output(app):
    with pytest.raises(app.Error) as error:
        app.run([sys.executable, "-c", "import sys; print('secret-token'); sys.exit(1)"])
    assert "secret-token" not in str(error.value)


def test_menu_handles_invalid_choice_and_exits(app, tmp_path, monkeypatch, capsys):
    values = iter(["invalid", "2", "0"])
    monkeypatch.setattr("builtins.input", lambda _: next(values))
    app.menu(app.Manager(tmp_path / "state"))
    output = capsys.readouterr().out
    assert "Invalid choice" in output
    assert "No certificates" in output


def test_lock_prevents_concurrent_writes(app, tmp_path):
    manager = app.Manager(tmp_path / "state")
    with app.locked(manager.root):
        with pytest.raises(app.Error, match="running"):
            with app.locked(manager.root):
                pytest.fail("The second writer must not acquire the lock")


def test_script_help_is_standalone(tmp_path):
    assert SCRIPT.is_file(), "The standalone certificate tool is not implemented yet"
    result = subprocess.run([sys.executable, str(SCRIPT), "--help"], cwd=tmp_path, capture_output=True)
    assert result.returncode == 0
    assert b"simple-cert" in result.stdout


def test_settings_require_terminal(app, tmp_path, monkeypatch):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    with pytest.raises(app.Error, match="terminal"):
        app.settings_menu(app.Manager(tmp_path / "state"))


def test_missing_settings_fail_before_network(app, tmp_path):
    with pytest.raises(app.Error, match="settings"):
        app.Manager(tmp_path / "state").issue(["example.com"])


def test_expired_certificate_can_be_listed_and_selected_for_renewal(manager, monkeypatch):
    record = manager.issue(["example.com"])

    # Move the validator's clock beyond expiry; the installed files remain real PEM.
    class FutureDateTime(dt.datetime):
        @classmethod
        def now(cls, tz=None):
            return super().now(tz) + dt.timedelta(days=90)

    # validate_pair's global namespace belongs to the imported fixture module.
    monkeypatch.setattr(manager.records.__globals__["dt"], "datetime", FutureDateTime)
    assert manager.records()[0]["id"] == record["id"]


def test_acme_export_paths_never_point_to_published_versions(app, tmp_path, monkeypatch, pair):
    manager = app.Manager(tmp_path / "state")
    manager.configure("admin@example.com", "secret-token")
    engine = manager.root / "engine"
    engine.mkdir()
    (engine / "acme.sh").write_text("fixture")
    (engine / "revision").write_text(app.ACME_COMMIT)
    destinations = []
    real_run = app.run

    def boundary(argv, **kwargs):
        if argv[0] == "openssl":
            return real_run(argv, **kwargs)
        if "--install-cert" in argv:
            for name, flag in [("fullchain.pem", "--fullchain-file"), ("key.pem", "--key-file")]:
                path = Path(argv[argv.index(flag) + 1])
                destinations.append(path)
                shutil.copyfile(pair / name, path)
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.setattr(app, "run", boundary)
    record = manager.issue(["example.com"])
    active = manager.root / "certificates" / record["id"] / "current"
    assert all(path.parent != active.resolve() for path in destinations)
    for path in destinations:
        path.write_text("ACME automatically updates its saved export paths on renewal")
    assert (active / "fullchain.pem").read_bytes() == (pair / "fullchain.pem").read_bytes()


def test_interrupted_publication_uses_existing_certificate_for_renewal(manager, monkeypatch):
    record = manager.issue(["example.com"])
    path = manager.root / "certificates" / record["id"] / "record.json"
    record.pop("issued")
    record["operation"] = "publishing"
    path.write_text(json.dumps(record))
    obtain = manager.obtain

    def check_renew(record, destination, renew=False):
        assert renew, "A published certificate must use renewal after interrupted metadata write"
        return obtain(record, destination, renew=renew)

    monkeypatch.setattr(manager, "obtain", check_renew)
    manager.renew(record["id"])


def test_hidden_input_never_falls_back_to_echo(app, tmp_path, monkeypatch):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _: "admin@example.com")

    def unavailable(_):
        warnings.warn("Cannot control echo", app.getpass.GetPassWarning)
        pytest.fail("Token entry must stop before a visible fallback prompt")

    monkeypatch.setattr(app.getpass, "getpass", unavailable)
    with pytest.raises(app.Error, match="hidden"):
        app.settings_menu(app.Manager(tmp_path / "state"))
