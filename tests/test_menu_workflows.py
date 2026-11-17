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


def test_delete_refuses_unfinished_certificate(app, manager, monkeypatch, capsys):
    record = manager.issue(["example.com", "*.example.com"])
    record["operation"] = "unknown"
    folder = manager.root / "certificates" / record["id"]
    app.save(folder / "record.json", record)
    answers = iter(["9", "delete", "0"])
    monkeypatch.setattr("builtins.input", lambda _: next(answers, "0"))

    app.certificate_menu(manager, record)

    assert "Reconcile the unfinished certificate operation" in capsys.readouterr().out
    assert (folder / "current/key.pem").is_file()
    assert manager.read_record(record["id"])["operation"] == "unknown"
