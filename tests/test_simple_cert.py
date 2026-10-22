"""Offline acceptance tests: only the ACME/network boundary is substituted."""

import datetime as dt
import importlib.util
import json
import os
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


@pytest.mark.parametrize("purpose", ["core", "panel"])
def test_acme_export_paths_never_point_to_published_versions(app, tmp_path, monkeypatch, pair, purpose):
    manager = app.Manager(tmp_path / "state", purpose=purpose)
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
    if purpose == "panel":
        assert all(path.is_relative_to(tmp_path / "state/panel-https") for path in destinations)
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


def test_interactive_menu_clears_and_keeps_results_until_enter(app, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setenv("TERM", "xterm-256color")
    values = iter(["2", "", "invalid", "", "0"])
    prompts = []

    def answer(prompt):
        prompts.append(prompt)
        return next(values)

    monkeypatch.setattr("builtins.input", answer)
    app.menu(app.Manager(tmp_path / "state"))
    output = capsys.readouterr().out
    assert output.startswith("\033[2J\033[H")
    assert output.count("\033[2J\033[H") == 3
    assert "No certificates" in output
    assert "Invalid choice" in output
    assert prompts == [
        "Choose [0-7]: ",
        "Press Enter to return to the menu...",
        "Choose [0-7]: ",
        "Press Enter to return to the menu...",
        "Choose [0-7]: ",
    ]


@pytest.mark.parametrize("tty, term", [(False, "xterm"), (True, "dumb"), (True, "")])
def test_redirected_or_dumb_menu_stays_plain_and_does_not_pause(
    app, tmp_path, monkeypatch, capsys, tty, term
):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: tty)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: tty)
    monkeypatch.setenv("TERM", term)
    values = iter(["2", "0"])
    prompts = []

    def answer(prompt):
        prompts.append(prompt)
        return next(values)

    monkeypatch.setattr("builtins.input", answer)
    app.menu(app.Manager(tmp_path / "state"))
    assert "\033" not in capsys.readouterr().out
    assert prompts == ["Choose [0-7]: ", "Choose [0-7]: "]


def test_interactive_error_is_readable_before_redraw(app, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setenv("TERM", "xterm")
    manager = app.Manager(tmp_path / "state")

    def fail():
        raise app.Error("Example safe failure")

    monkeypatch.setattr(manager, "records", fail)
    values = iter(["2", "", "0"])
    monkeypatch.setattr("builtins.input", lambda _: next(values))
    app.menu(manager)
    output = capsys.readouterr().out
    assert "Error: Example safe failure" in output
    assert output.count("\033[2J\033[H") == 2


def test_selected_certificate_viewer_shows_both_files(manager, app, pair, monkeypatch, capsys):
    record = manager.issue(["example.com"])
    capsys.readouterr()
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setenv("TERM", "xterm")
    values = iter(["1", "", "2", "yes", "", "0"])
    monkeypatch.setattr("builtins.input", lambda _: next(values))
    assert hasattr(app, "certificate_menu"), "Certificate file viewer is not implemented yet"
    app.certificate_menu(manager, record)
    output = capsys.readouterr().out
    assert (pair / "fullchain.pem").read_text().strip() in output
    assert (pair / "key.pem").read_text().strip() in output


@pytest.mark.parametrize("terminal, consent", [(True, ""), (True, "no"), (False, "yes")])
def test_private_key_requires_terminal_and_explicit_consent(
    manager, app, pair, monkeypatch, capsys, terminal, consent
):
    record = manager.issue(["example.com"])
    capsys.readouterr()
    monkeypatch.setattr(sys.stdin, "isatty", lambda: terminal)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: terminal)
    monkeypatch.setattr("builtins.input", lambda _: consent)
    assert hasattr(app, "display_file"), "Certificate file viewer is not implemented yet"
    try:
        app.display_file(manager, record, "key.pem")
    except app.Error:
        pass
    assert (pair / "key.pem").read_text().strip() not in capsys.readouterr().out


def test_list_selection_opens_certificate_viewer(manager, app, monkeypatch, capsys):
    manager.issue(["example.com"])
    capsys.readouterr()
    values = iter(["2", "1", "1", "0", "0"])
    monkeypatch.setattr("builtins.input", lambda _: next(values))
    app.menu(manager)
    assert "-----BEGIN CERTIFICATE-----" in capsys.readouterr().out


def test_file_viewer_cannot_read_settings_or_missing_files(manager, app, monkeypatch):
    record = manager.issue(["example.com"])
    assert hasattr(app, "display_file"), "Certificate file viewer is not implemented yet"
    with pytest.raises(app.Error):
        app.display_file(manager, record, "../../settings.json")
    folder = manager.root / "certificates" / record["id"] / "current"
    (folder / "fullchain.pem").unlink()
    with pytest.raises(app.Error, match="published"):
        app.display_file(manager, record, "fullchain.pem")


@pytest.fixture
def panel(app, tmp_path, monkeypatch):
    assert hasattr(app, "docker_panels"), "Panel delivery is not implemented yet"
    data = tmp_path / "panel-data"
    data.mkdir()
    raw = {
        "Id": "fixture-panel",
        "Name": "/mother",
        "State": {"Running": True},
        "Config": {
            "Image": "pasarguard/panel:fixture",
            "Env": ["DATA_DIR=/panel-data", "API_KEY=private-fixture"],
        },
        "HostConfig": {"UsernsMode": ""},
        "Mounts": [{"Type": "bind", "Source": str(data), "Destination": "/panel-data", "RW": True}],
    }
    target = app.docker_panels([raw])[0]
    monkeypatch.setattr(app, "discover_panels", lambda: [target])
    real_run = app.run

    def boundary(argv, **kwargs):
        if argv[0] == "openssl":
            return real_run(argv, **kwargs)
        if argv[:2] == ["docker", "info"]:
            return subprocess.CompletedProcess(argv, 0, b"[]", b"")
        assert argv[:3] == ["docker", "exec", "fixture-panel"]
        if "geteuid" in argv[5]:
            output = f"{os.geteuid()}:{os.getegid()}".encode()
        else:
            files = [data / Path(path).relative_to("/panel-data") for path in argv[6:]]
            import hashlib

            output = " ".join(hashlib.sha256(path.read_bytes()).hexdigest() for path in files).encode()
        return subprocess.CompletedProcess(argv, 0, output, b"")

    monkeypatch.setattr(app, "run", boundary)
    return target, data


def test_panel_discovery_ignores_nodes_and_never_retains_credentials(app, panel):
    target, _ = panel
    assert "private-fixture" not in json.dumps(target)
    assert app.docker_panels([{"Config": {"Image": "pasarguard/node:latest"}}]) == []


def test_delivery_publishes_mapped_paths_and_private_matching_files(manager, app, panel, pair):
    target, data = panel
    record = manager.issue(["example.com"])
    directory = "/panel-data/certs/simple-cert/" + record["id"]
    result = app.publish_delivery(manager, record, target, directory)
    current = data / "certs/simple-cert" / record["id"] / "current"
    assert current.is_symlink()
    assert (current / "fullchain.pem").read_bytes() == (pair / "fullchain.pem").read_bytes()
    assert (current / "key.pem").stat().st_mode & 0o777 == 0o600
    assert result["deliveries"][0]["status"] == "complete"
    assert result["deliveries"][0]["directory"] == directory


def test_nested_readonly_mount_and_traversal_are_blocked(app, panel):
    target, _ = panel
    target["mounts"].append(
        {"Source": "/unrelated", "Destination": "/panel-data/certs", "Type": "bind", "RW": False}
    )
    with pytest.raises(app.Error):
        app.panel_location(target, "/panel-data/certs/example")
    with pytest.raises(app.Error):
        app.panel_location(target, "/panel-data/../outside")


def test_delivery_cancel_does_not_create_destination(manager, app, panel, monkeypatch):
    target, data = panel
    record = manager.issue(["example.com"])
    values = iter(["", "no"])
    monkeypatch.setattr("builtins.input", lambda _: next(values))
    app.delivery_menu(manager, record, [target])
    assert not (data / "certs").exists()


def test_new_delivery_path_retains_previous_managed_path(manager, app, panel):
    target, data = panel
    record = manager.issue(["example.com"])
    app.publish_delivery(manager, record, target, "/panel-data/certs/first")
    record = app.publish_delivery(manager, record, target, "/panel-data/certs/second")
    assert len(record["deliveries"]) == 2
    assert (data / "certs/first/current/key.pem").is_file()
    assert (data / "certs/second/current/key.pem").is_file()


def test_renewal_refreshes_registered_delivery(manager, app, panel):
    target, data = panel
    record = manager.issue(["example.com"])
    app.publish_delivery(manager, record, target, "/panel-data/certs/selected")
    current = data / "certs/selected/current"
    previous = current.resolve()
    result = manager.renew(record["id"])
    assert current.resolve() != previous
    assert previous.is_dir()
    assert result["deliveries"][0]["status"] == "complete"


def test_failed_delivery_keeps_previous_pair_and_marks_pending(manager, app, panel, monkeypatch):
    target, data = panel
    record = manager.issue(["example.com"])
    app.publish_delivery(manager, record, target, "/panel-data/certs/selected")
    current = data / "certs/selected/current"
    previous = current.resolve()

    def unreadable(*args):
        raise app.Error("Fixture reader unavailable")

    monkeypatch.setattr(app, "panel_reader_check", unreadable)
    result = manager.renew(record["id"])
    assert current.resolve() == previous
    assert result["operation"] == "complete"
    assert result["deliveries"][0]["status"] == "pending"


def test_unmanaged_directory_and_symlink_are_never_overwritten(manager, app, panel):
    target, data = panel
    record = manager.issue(["example.com"])
    unknown = data / "existing"
    unknown.mkdir()
    (unknown / "key.pem").write_text("unrelated-key-marker")
    with pytest.raises(app.Error):
        app.publish_delivery(manager, record, target, "/panel-data/existing")
    assert (unknown / "key.pem").read_text() == "unrelated-key-marker"
    (data / "symlink").symlink_to(unknown)
    with pytest.raises(app.Error):
        app.publish_delivery(manager, record, target, "/panel-data/symlink/new")


def test_issue_menu_offers_panel_delivery_after_success(manager, app, panel, monkeypatch):
    seen = []
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(app, "clear_screen", lambda: False)
    monkeypatch.setattr(app, "delivery_menu", lambda manager, record, targets: seen.append(record["id"]))
    values = iter(["1", "example.com", "", "y", "y", "0"])
    monkeypatch.setattr("builtins.input", lambda _: next(values))
    app.menu(manager)
    assert seen == [manager.records()[0]["id"]]


def test_certificate_details_offer_later_publication(manager, app, monkeypatch):
    record = manager.issue(["example.com"])
    seen = []
    monkeypatch.setattr(app, "delivery_menu", lambda manager, record: seen.append(record["id"]) or record)
    values = iter(["3", "0"])
    monkeypatch.setattr("builtins.input", lambda _: next(values))
    app.certificate_menu(manager, record)
    assert seen == [record["id"]]


def test_mount_change_blocks_renewal_delivery_to_new_host(manager, app, panel, tmp_path):
    target, data = panel
    record = manager.issue(["example.com"])
    app.publish_delivery(manager, record, target, "/panel-data/certs/selected")
    other = tmp_path / "replacement-mount"
    other.mkdir()
    target["mounts"][0]["Source"] = str(other)
    result = manager.renew(record["id"])
    assert not (other / "certs").exists()
    assert (data / "certs/selected/current/key.pem").is_file()
    assert result["operation"] == "complete"
    assert result["deliveries"][0]["status"] == "pending"


def test_private_state_cannot_be_used_as_delivery_mount(manager, app, panel):
    target, _ = panel
    record = manager.issue(["example.com"])
    target["mounts"][0]["Source"] = str(manager.root)
    with pytest.raises(app.Error):
        app.publish_delivery(manager, record, target, "/panel-data/delivery")
    assert not (manager.root / "delivery").exists()


@pytest.mark.parametrize("option", ["rootless", "userns"])
def test_namespaced_docker_cannot_publish(manager, app, panel, monkeypatch, option):
    target, _ = panel
    monkeypatch.setattr(app, "run", lambda *a, **k: subprocess.CompletedProcess(a, 0, option.encode(), b""))
    with pytest.raises(app.Error, match="rootful"):
        app.panel_reader_identity(target)


def test_new_certificate_folders_identify_domain_and_remain_renewable(manager, pair):
    normal = manager.issue(["example.com"])
    wildcard = manager.issue(["*.example.com"])
    combined = manager.issue(["example.com", "*.example.com"])
    assert normal["id"].startswith("example.com--")
    assert wildcard["id"].startswith("wildcard.example.com--")
    assert combined["id"].startswith("example.com--")
    assert len({record["id"] for record in (normal, wildcard, combined)}) == 3
    for record in (normal, wildcard, combined):
        manager.renew(record["id"])
        current = manager.root / "certificates" / record["id"] / "current"
        assert (current / "fullchain.pem").read_bytes() == (pair / "fullchain.pem").read_bytes()
    assert len(manager.records()) == 3


def test_legacy_hashed_folder_stays_renewable_and_blocks_duplicate_issue(manager, app):
    record = manager.issue(["example.com"])
    import hashlib

    legacy = hashlib.sha256(b"example.com").hexdigest()[:24]
    old = manager.root / "certificates" / legacy
    folder = manager.root / "certificates" / record["id"]
    if folder != old:
        folder.rename(old)
    record["id"] = legacy
    app.save(old / "record.json", record)
    previous = (old / "current").resolve()
    result = manager.renew(legacy)
    assert result["id"] == legacy
    assert (old / "current").resolve() != previous
    assert previous.is_dir()
    with pytest.raises(app.Error, match="already saved"):
        manager.issue(["example.com"])
    assert len(manager.records()) == 1


def test_panel_default_for_existing_certificate_contains_domain(manager, app, panel, monkeypatch, capsys):
    target, data = panel
    record = manager.issue(["example.com"])
    legacy = "a379a6f6eeafb9a55e378c11"
    folder = manager.root / "certificates" / record["id"]
    folder.rename(folder.parent / legacy)
    record["id"] = legacy
    app.save(folder.parent / legacy / "record.json", record)
    values = iter(["", "yes"])
    monkeypatch.setattr("builtins.input", lambda _: next(values))
    result = app.delivery_menu(manager, record, [target])
    directory = result["deliveries"][0]["directory"]
    assert Path(directory).name.startswith("example.com--")
    assert (data / Path(directory).relative_to("/panel-data") / "current/key.pem").is_file()
    assert directory + "/current/fullchain.pem" in capsys.readouterr().out


@pytest.mark.parametrize("identifier", ["../outside", "/etc/passwd", "example.com--../key", "..", "a" * 300])
def test_folder_identifiers_cannot_escape_certificate_state(manager, app, identifier):
    with pytest.raises(app.Error, match="Invalid certificate selection"):
        manager.renew(identifier)


def test_long_domain_folder_stays_within_filesystem_component_limit(app):
    domain = ".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 57])
    name = app.certificate_identifier([domain])
    assert len(name.encode("ascii")) <= 255
    assert name.startswith("a" * 63 + "." + "b" * 63)


@pytest.fixture
def panel_https_manager(manager, app, pair, monkeypatch):
    tool = app.Manager(manager.root, purpose="panel")

    def obtain(record, destination, renew=False):
        saved = app.load(tool.root / "certificates" / record["id"] / "record.json")
        assert saved["purpose"] == "panel"
        for name in ("fullchain.pem", "key.pem"):
            shutil.copyfile(pair / name, destination / name)

    monkeypatch.setattr(tool, "obtain", obtain)
    return tool


def test_panel_https_has_separate_storage_and_renewal(manager, panel_https_manager, app):
    core_record = manager.issue(["example.com"])
    core_current = manager.root / "certificates" / core_record["id"] / "current"
    original = core_current.resolve()
    panel_record = panel_https_manager.issue(["example.com"])
    assert panel_https_manager.root == manager.root / "panel-https"
    assert panel_https_manager.config() == manager.config()
    assert panel_record["purpose"] == "panel"
    assert manager.records()[0]["purpose"] == "core"
    panel_https_manager.renew(panel_record["id"])
    assert core_current.resolve() == original
    assert len(manager.records()) == len(panel_https_manager.records()) == 1


def test_panel_https_cannot_publish_into_core_paths(panel_https_manager, app, panel):
    target, data = panel
    record = panel_https_manager.issue(["example.com"])
    with pytest.raises(app.Error, match="node/config"):
        app.publish_delivery(panel_https_manager, record, target, "/panel-data/certs/forbidden")
    assert not (data / "certs").exists()


def test_panel_https_viewer_cannot_offer_core_delivery(panel_https_manager, app, monkeypatch, capsys):
    record = panel_https_manager.issue(["example.com"])
    values = iter(["3", "0"])
    monkeypatch.setattr("builtins.input", lambda _: next(values))
    app.certificate_menu(panel_https_manager, record)
    output = capsys.readouterr().out
    assert "Publish/change" not in output
    assert "Invalid" in output


def test_panel_https_menu_keeps_existing_env_and_certificates(manager, app, pair, tmp_path, monkeypatch):
    existing = tmp_path / "existing-panel"
    existing.mkdir()
    (existing / ".env").write_text(
        "UVICORN_SSL_CERTFILE=/existing/fullchain.pem\nUVICORN_SSL_KEYFILE=/existing/key.pem\n"
    )
    for name in ("fullchain.pem", "key.pem"):
        shutil.copyfile(pair / name, existing / name)
    before = {path.name: (path.read_bytes(), path.stat().st_mode) for path in existing.iterdir()}

    def obtain(self, record, destination, renew=False):
        for name in ("fullchain.pem", "key.pem"):
            shutil.copyfile(pair / name, destination / name)

    def forbidden_discovery():
        pytest.fail("Panel HTTPS must not discover or publish Core certificates")

    monkeypatch.setattr(app.Manager, "obtain", obtain)
    monkeypatch.setattr(app, "discover_panels", forbidden_discovery)
    monkeypatch.setattr(app, "clear_screen", lambda: False)
    values = iter(["7", "1", "example.com", "", "y", "2", "1", "1", "0", "3", "1", "0", "0"])
    monkeypatch.setattr("builtins.input", lambda _: next(values))
    app.menu(manager)
    panel_manager = app.Manager(manager.root, purpose="panel")
    assert len(panel_manager.records()) == 1
    assert manager.records() == []
    assert {path.name: (path.read_bytes(), path.stat().st_mode) for path in existing.iterdir()} == before


def test_core_delivery_refuses_existing_manual_panel_certificate_files(
    manager, app, panel, pair, monkeypatch
):
    target, data = panel
    existing = data / "certs/panel-https"
    existing.mkdir(parents=True)
    for name in ("fullchain.pem", "key.pem"):
        shutil.copyfile(pair / name, existing / name)
    (data / ".env").write_text("UVICORN_SSL_CERTFILE=/panel-data/certs/panel-https/fullchain.pem\n")
    before = {path: (path.read_bytes(), path.stat().st_mode) for path in [data / ".env", *existing.iterdir()]}
    record = manager.issue(["example.com"])
    values = iter(["/panel-data/certs/panel-https", "yes"])
    monkeypatch.setattr("builtins.input", lambda _: next(values))
    with pytest.raises(app.Error, match="owned"):
        app.delivery_menu(manager, record, [target])
    assert {path: (path.read_bytes(), path.stat().st_mode) for path in before} == before
    assert not (existing / "current").exists()
