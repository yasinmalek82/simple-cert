"""Operator-facing navigation and certificate-specific actions."""

import json
import shutil

import pytest
from test_simple_cert import app as app
from test_simple_cert import generate_pair
from test_simple_cert import manager as manager
from test_simple_cert import pair as pair


def test_main_groups_certificates_settings_and_maintenance(app, manager, monkeypatch, capsys):
    answers = iter(["1", "2", "0", "0"])
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    app.menu(manager)
    output = capsys.readouterr().out
    assert "Program maintenance" in output
    assert "Settings and automation" in output
    assert "No certificates" in output


def test_certificate_details_can_renew_without_changing_paths(app, manager, monkeypatch, capsys):
    record = manager.issue(["example.com"])
    answers = iter(["4", "0"])
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    app.certificate_menu(manager, record)
    output = capsys.readouterr().out
    assert "Unchanged" in output
    assert "Versions:" in output
    assert "Automatic renewal: disabled" in output


def test_certificate_enrollment_is_explicit_and_can_be_disabled(app, manager, monkeypatch):
    record = manager.issue(["example.com"])
    # Service registration is an external boundary; record enrollment remains real.
    monkeypatch.setattr(app, "install_automation", lambda manager: None)
    answers = iter(["5", "yes", "5", "yes", "0"])
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    app.certificate_menu(manager, record)
    saved = json.loads((manager.root / "certificates" / record["id"] / "record.json").read_text())
    assert saved["automation"]["enabled"] is False


def test_certificate_details_show_missing_private_key(app, manager, monkeypatch, capsys):
    record = manager.issue(["example.com"])
    (manager.root / "certificates" / record["id"] / "current/key.pem").unlink()
    monkeypatch.setattr("builtins.input", lambda _: "0")
    app.certificate_menu(manager, record)
    assert "File status: invalid" in capsys.readouterr().out


@pytest.mark.parametrize("purpose", ["core", "panel"])
def test_archive_menu_hides_wildcard_and_restores_it_without_reenrolling(
    app, pair, tmp_path, monkeypatch, capsys, purpose
):
    section = app.Manager(tmp_path / "state", purpose=purpose)
    section.configure("admin@example.com", "fixture-token")
    exact_pair = generate_pair(tmp_path / "exact", ("example.com",))

    def export(record, destination, renew=False):
        source = pair if "*.example.com" in record["domains"] else exact_pair
        for filename in ("fullchain.pem", "key.pem"):
            shutil.copyfile(source / filename, destination / filename)

    monkeypatch.setattr(section, "obtain", export)
    monkeypatch.setattr(app, "show_panel_https_status", lambda: "")
    wildcard = section.issue(["example.com", "*.example.com"])
    single = section.issue(["example.com"])
    app.set_automation(section, wildcard["id"], True)
    current = section.root / "certificates" / wildcard["id"] / "current"
    before = {name: (current / name).read_bytes() for name in ("fullchain.pem", "key.pem")}
    version = current.resolve()

    def menu(*answers):
        steps = iter(answers)
        monkeypatch.setattr("builtins.input", lambda _: next(steps, "0"))
        app.section_menu(section)
        return capsys.readouterr().out

    assert "Certificate archived" in menu("2", "1", "8", "yes", "0")
    assert [record["id"] for record in section.records()] == [single["id"]]
    assert "*.example.com" not in menu("3", "0", "0")
    assert current.resolve() == version
    assert {name: (current / name).read_bytes() for name in before} == before
    assert section.read_record(wildcard["id"])["automation"]["enabled"] is False
    with pytest.raises(app.Error, match="archived"):
        section.renew(wildcard["id"])
    with pytest.raises(app.Error, match="archived"):
        app.set_automation(section, wildcard["id"], True)
    with pytest.raises(app.Error, match="archived"):
        section.issue(["example.com", "*.example.com"])

    restored = menu("6", "1", "8", "yes", "0")
    assert "example.com, *.example.com" in restored
    assert "Certificate restored" in restored
    assert {record["id"] for record in section.records()} == {wildcard["id"], single["id"]}
    assert section.read_record(wildcard["id"])["automation"]["enabled"] is False


def test_archive_requires_confirmation_and_refuses_unfinished_operation(app, manager, monkeypatch, capsys):
    record = manager.issue(["example.com"])
    path = manager.root / "certificates" / record["id"] / "record.json"

    def archive(confirm):
        answers = iter(["8", confirm, "0"])
        monkeypatch.setattr("builtins.input", lambda _: next(answers))
        app.certificate_menu(manager, record)
        return capsys.readouterr().out

    before = path.read_bytes()
    assert "Archive cancelled" in archive("no")
    assert path.read_bytes() == before

    record["operation"] = "unknown"
    app.save(path, record)
    before = path.read_bytes()
    assert "Reconcile the unfinished certificate operation" in archive("yes")
    assert path.read_bytes() == before


@pytest.mark.parametrize("purpose", ["core", "panel"])
@pytest.mark.parametrize("confirmation", ["", "delete"])
def test_delete_removes_only_selected_managed_certificate(app, tmp_path, monkeypatch, purpose, confirmation):
    state = tmp_path / "state"
    section = app.Manager(state, purpose=purpose)
    section.configure("admin@example.com", "fixture-token")
    fixture = generate_pair(tmp_path / "exact", ("example.com",))

    def export(record, destination, renew=False):
        for filename in ("fullchain.pem", "key.pem"):
            shutil.copyfile(fixture / filename, destination / filename)

    monkeypatch.setattr(section, "obtain", export)
    record = section.issue(["example.com"])
    other = app.Manager(state, purpose="core" if purpose == "panel" else "panel")
    monkeypatch.setattr(other, "obtain", export)
    other.issue(["example.com"])
    app.set_automation(section, record["id"], True)
    if purpose == "panel":
        section.set_archived(record["id"], True)
    delivery = tmp_path / "delivered"
    shutil.copytree(fixture, delivery)
    record = section.read_record(record["id"])
    record["deliveries"] = [
        {
            "kind": "systemd",
            "name": "panel",
            "directory": str(delivery),
            "host_directory": str(delivery),
            "status": "complete",
        }
    ]
    folder = section.root / "certificates" / record["id"]
    app.save(folder / "record.json", record)
    workspaces = [section.root / kind / record["id"] for kind in ("acme-certificates", "acme-exports")]
    for path in workspaces:
        shutil.copytree(fixture, path)

    answers = iter(["9", confirmation, "0"])
    monkeypatch.setattr("builtins.input", lambda _: next(answers, "0"))
    app.certificate_menu(section, record)

    deleted = confirmation == "delete"
    assert (folder / "record.json").exists() is not deleted
    assert (folder / "current").is_symlink() is not deleted
    assert (folder / "versions").exists() is not deleted
    assert all(path.exists() is not deleted for path in workspaces)
    assert (delivery / "key.pem").read_bytes() == (fixture / "key.pem").read_bytes()
    assert other.records()[0]["active"]
    assert section.config()["email"] == "admin@example.com"
    if deleted:
        assert section.issue(["example.com"])["operation"] == "complete"


def test_normal_delete_does_not_discard_unfinished_certificate(app, manager, monkeypatch, capsys):
    record = manager.issue(["example.com", "*.example.com"])
    record["operation"] = "unknown"
    folder = manager.root / "certificates" / record["id"]
    app.save(folder / "record.json", record)
    answers = iter(["9", "delete", "0"])
    monkeypatch.setattr("builtins.input", lambda _: next(answers, "0"))

    app.certificate_menu(manager, record)

    assert "Try option 6 to recover" in capsys.readouterr().out
    assert (folder / "current/key.pem").is_file()
    assert manager.read_record(record["id"])["operation"] == "unknown"


@pytest.mark.parametrize("busy", [False, True])
def test_discard_interrupted_issuance_allows_retry_only_after_operation_unlocks(
    app, manager, monkeypatch, capsys, busy
):
    domains = ["example.com", "*.example.com"]
    obtain = manager.obtain

    def interrupt(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(manager, "obtain", interrupt)
    with pytest.raises(KeyboardInterrupt):
        manager.issue(domains)
    monkeypatch.setattr(manager, "obtain", obtain)
    record = manager.records()[0]
    with pytest.raises(app.OutcomeUnknown, match="No new validated ACME export"):
        manager.reconcile(record["id"])

    answers = iter(["9", "discard", "0"])
    monkeypatch.setattr("builtins.input", lambda _: next(answers, "0"))
    if busy:
        with app.certificate_lock(manager, record["id"]):
            app.certificate_menu(manager, record)
        assert "Another simple-cert operation is running" in capsys.readouterr().out
        assert manager.read_record(record["id"])["operation"] == "unknown"
    else:
        app.certificate_menu(manager, record)
        assert manager.records() == []
        assert manager.issue(domains)["operation"] == "complete"


@pytest.mark.parametrize("confirmation, expected_calls", [("", 1), ("retry", 2)])
def test_recovery_menu_retries_first_issuance_with_same_record(
    app, manager, monkeypatch, capsys, confirmation, expected_calls
):
    domains = ["example.com", "*.example.com"]
    obtain = manager.obtain
    calls = []

    def interrupt_once(record, directory, renew=False):
        calls.append((record["id"], list(record["domains"]), renew))
        if len(calls) == 1:
            raise KeyboardInterrupt
        return obtain(record, directory, renew=renew)

    monkeypatch.setattr(manager, "obtain", interrupt_once)
    with pytest.raises(KeyboardInterrupt):
        manager.issue(domains)
    record = manager.records()[0]
    answers = iter(["6", confirmation, "0"])
    monkeypatch.setattr("builtins.input", lambda _: next(answers, "0"))
    app.certificate_menu(manager, record)

    assert calls == [(record["id"], domains, False)] * expected_calls
    assert manager.read_record(record["id"])["operation"] == ("complete" if confirmation else "unknown")
    assert "Retry issuance" in capsys.readouterr().out


def test_retry_cannot_replace_published_certificate(app, manager, monkeypatch, capsys):
    domains = ["example.com", "*.example.com"]
    record = manager.issue(domains)
    folder = manager.root / "certificates" / record["id"]

    def interrupt(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(manager, "obtain", interrupt)
    with pytest.raises(KeyboardInterrupt):
        manager.renew(record["id"])
    original = (folder / "current").resolve()
    answers = iter(["6", "0"])
    monkeypatch.setattr("builtins.input", lambda _: next(answers, "0"))
    app.certificate_menu(manager, record)
    assert "Retry issuance" not in capsys.readouterr().out
    assert (folder / "current").resolve() == original


def test_interrupted_delete_cannot_be_restored_and_can_resume(app, manager, monkeypatch, capsys):
    record = manager.issue(["example.com", "*.example.com"])
    folder = manager.root / "certificates" / record["id"]
    rmtree = shutil.rmtree

    def fail(path, *args, **kwargs):
        if path == folder / "versions":
            raise PermissionError("fixture")
        return rmtree(path, *args, **kwargs)

    monkeypatch.setattr(shutil, "rmtree", fail)
    with pytest.raises(app.Error, match="Could not finish deletion"):
        manager.delete(record["id"])
    with pytest.raises(app.Error, match="deletion"):
        manager.set_archived(record["id"], False)
    monkeypatch.setattr(shutil, "rmtree", rmtree)
    answers = iter(["7", "1", "9", "delete", "0"])
    monkeypatch.setattr("builtins.input", lambda _: next(answers, "0"))
    app.section_menu(manager)

    assert "Resume deletion" in capsys.readouterr().out
    assert not (folder / "record.json").exists()


def test_duplicate_issue_opens_existing_certificate_without_calling_ca(manager, app, monkeypatch, capsys):
    domains = ["example.com", "*.example.com"]
    record = manager.issue(domains)
    monkeypatch.setattr(manager, "obtain", lambda *a, **k: pytest.fail("Duplicate must not contact CA"))
    answers = iter(["1", "example.com", "y", "0", "0"])
    monkeypatch.setattr("builtins.input", lambda _: next(answers, "0"))
    app.section_menu(manager)
    assert "Domains: example.com, *.example.com" in capsys.readouterr().out
    assert manager.records()[0]["id"] == record["id"]


@pytest.mark.parametrize("change", ["busy", "prepared"])
def test_retry_confirmation_rechecks_lock_and_recovery_files(app, manager, monkeypatch, pair, change):
    domains = ["example.com", "*.example.com"]

    def interrupt(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(manager, "obtain", interrupt)
    with pytest.raises(KeyboardInterrupt):
        manager.issue(domains)
    record = manager.read_record(manager.records()[0]["id"])
    with pytest.raises(app.RecoveryUnavailable) as failure:
        manager.reconcile(record["id"])
    assert failure.value.can_retry
    monkeypatch.setattr(manager, "obtain", lambda *a, **k: pytest.fail("Must not contact the CA"))
    if change == "busy":
        with app.certificate_lock(manager, record["id"]), pytest.raises(app.Busy):
            manager.retry_issuance(record["id"], expected=record)
    else:
        candidate = manager.root / "certificates" / record["id"] / "versions" / record["candidate"]
        for name in ("fullchain.pem", "key.pem"):
            shutil.copyfile(pair / name, candidate / name)
        with pytest.raises(app.Error, match="Recovery files are available"):
            manager.retry_issuance(record["id"], expected=record)
        assert manager.reconcile(record["id"])["operation"] == "complete"


def test_prepared_certificate_survives_interrupted_recovery(app, manager, monkeypatch):
    obtain = manager.obtain

    def interrupt_after_export(record, destination, renew=False):
        obtain(record, destination, renew=renew)
        raise KeyboardInterrupt

    monkeypatch.setattr(manager, "obtain", interrupt_after_export)
    with pytest.raises(KeyboardInterrupt):
        manager.issue(["example.com", "*.example.com"])
    record = manager.records()[0]
    folder = manager.root / "certificates" / record["id"]
    replace = app.os.replace

    def fail_pointer(source, destination):
        if destination == folder / "current":
            raise OSError("fixture")
        return replace(source, destination)

    monkeypatch.setattr(app.os, "replace", fail_pointer)
    with pytest.raises(OSError, match="fixture"):
        manager.reconcile(record["id"])
    monkeypatch.setattr(app.os, "replace", replace)
    monkeypatch.setattr(manager, "obtain", lambda *a, **k: pytest.fail("Must not contact the CA"))
    assert manager.reconcile(record["id"])["operation"] == "complete"


def test_recovery_keeps_published_candidate_with_aliased_state_parent(app, manager, tmp_path):
    record = manager.issue(["example.com", "*.example.com"])
    folder = manager.root / "certificates" / record["id"]
    current = folder / "current"
    version = current.resolve()
    record["operation"] = "publishing"
    record["candidate"] = version.name
    app.save(folder / "record.json", record)
    alias = tmp_path / "alias"
    alias.symlink_to(manager.root.parent, target_is_directory=True)
    aliased = app.Manager(alias / manager.root.name)

    assert aliased.reconcile(record["id"])["operation"] == "complete"
    assert current.resolve() == version
    assert (current / "key.pem").is_file()
