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
