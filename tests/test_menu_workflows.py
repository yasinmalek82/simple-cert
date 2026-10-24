"""Operator-facing navigation and certificate-specific actions."""

import json

from test_simple_cert import app as app
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
