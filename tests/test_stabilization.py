"""Regression coverage for publication, state isolation and local Docker selection."""

import json
import os
import subprocess

import pytest
from test_simple_cert import app as app
from test_simple_cert import manager as manager
from test_simple_cert import pair as pair
from test_simple_cert import panel as panel


def test_unchanged_renewal_retains_pointer_and_version_count(manager):
    record = manager.issue(["example.com"])
    folder = manager.root / "certificates" / record["id"]
    before = (folder / "current").readlink()
    result = manager.renew(record["id"])
    assert (folder / "current").readlink() == before
    assert len(list((folder / "versions").iterdir())) == 1
    assert result["result"] == "unchanged"


def test_corrupt_record_does_not_hide_healthy_certificates(manager, capsys):
    good = manager.issue(["example.com"])
    bad = manager.root / "certificates" / ("a" * 24)
    bad.mkdir()
    (bad / "record.json").write_text("{}")
    assert [r["id"] for r in manager.records()] == [good["id"]]
    assert "unreadable certificate record" in capsys.readouterr().out.lower()


def test_missing_key_is_reported_without_hiding_other_records(manager):
    record = manager.issue(["example.com"])
    folder = manager.root / "certificates" / record["id"]
    (folder / "current/key.pem").unlink()
    records = manager.records()
    assert records[0]["id"] == record["id"]
    assert records[0]["file_status"] == "invalid"


def test_delivery_versions_are_traversable_with_real_cli_umask(manager, app, panel):
    target, data = panel
    record = manager.issue(["example.com"])
    previous = os.umask(0o077)
    try:
        app.publish_delivery(manager, record, target, "/panel-data/certs/umask")
    finally:
        os.umask(previous)
    assert (data / "certs/umask/versions").stat().st_mode & 0o777 == 0o711


def test_context_override_cannot_bypass_remote_docker_block(app, monkeypatch):
    monkeypatch.setenv("DOCKER_HOST", "unix:///var/run/docker.sock")
    monkeypatch.setenv("DOCKER_CONTEXT", "remote-review")

    def boundary(argv, **kwargs):
        assert "ps" not in argv and "exec" not in argv
        return subprocess.CompletedProcess(
            argv, 0, json.dumps([{"Endpoints": {"docker": {"Host": "ssh://remote"}}}]).encode(), b""
        )

    monkeypatch.setattr(app, "run", boundary)
    assert app.discover_panels() == []


def test_separate_acme_config_home_is_used_for_renewal_attribution(app, tmp_path):
    certificate = tmp_path / "fullchain.pem"
    certificate.touch()
    config = tmp_path / "private/account/example.com_ecc/example.com.conf"
    config.parent.mkdir(parents=True)
    config.write_text(f"Le_RealFullChainPath='{certificate}'\nLe_Domain='example.com'\n")
    job = app.renewal_command("/opt/acme/acme.sh --cron --home /opt/acme --config-home /private/account")
    matches = app.inspect_renewal(
        {"host_certfile": str(certificate)},
        [{**job, "source": "fixture", "active": True}],
        system_root=tmp_path,
    )
    assert matches[0]["state"] == "scheduled"


def test_unknown_acme_result_is_reconciled_without_repeating_issuance(manager, app, monkeypatch):
    record = manager.issue(["example.com"])
    path = manager.root / "certificates" / record["id"] / "record.json"
    original = manager.obtain

    def interrupted(record, destination, renew=False):
        original(record, destination, renew=renew)
        raise app.OutcomeUnknown("ACME command interrupted; outcome unknown.")

    monkeypatch.setattr(manager, "obtain", interrupted)
    with pytest.raises(app.OutcomeUnknown):
        manager.renew(record["id"])
    assert json.loads(path.read_text())["operation"] == "unknown"
    monkeypatch.setattr(manager, "obtain", lambda *a, **k: pytest.fail("Must reconcile before CA access"))
    result = manager.reconcile(record["id"])
    assert result["operation"] == "complete"
    assert result["result"] == "unchanged"


def test_certificate_lock_excludes_other_writer(app, manager):
    record = manager.issue(["example.com"])
    with app.certificate_lock(manager, record["id"]):
        with pytest.raises(app.Error, match="running"):
            manager.renew(record["id"])


def test_delivery_reconciliation_does_not_republish_identical_files(manager, app, panel):
    target, data = panel
    record = manager.issue(["example.com"])
    record = app.publish_delivery(manager, record, target, "/panel-data/certs/recovery")
    current = data / "certs/recovery/current"
    before = current.readlink()
    path = manager.root / "certificates" / record["id"] / "record.json"
    record["deliveries"][0]["status"] = "published-unverified"
    record["deliveries"][0]["candidate"] = before.name
    app.save(path, record)
    result = app.refresh_deliveries(manager, record)
    assert result["deliveries"][0]["status"] == "complete"
    assert current.readlink() == before


def test_manual_recovery_clears_scheduler_unknown_outcome(manager, app, monkeypatch):
    record = manager.issue(["example.com"])
    path = manager.root / "certificates" / record["id"] / "record.json"
    record["operation"] = "unknown"
    record["candidate"] = (path.parent / "current").resolve().name
    record["schedule"] = {"attempt_id": "fixture", "outcome": "unknown", "day": "2026-10-24", "attempts": 1}
    app.save(path, record)
    monkeypatch.setattr(manager, "obtain", lambda *a, **k: pytest.fail("Recovery must not contact CA"))
    result = manager.reconcile(record["id"])
    assert result["schedule"]["outcome"] == "done"


def test_corrupt_automation_settings_are_isolated(manager, app, capsys):
    record = manager.issue(["example.com"])
    path = manager.root / "certificates" / record["id"] / "record.json"
    record["automation"] = []
    app.save(path, record)
    assert manager.records() == []
    assert "unreadable certificate record" in capsys.readouterr().out.lower()


def test_export_copy_failure_after_acme_success_is_not_a_definite_failure(manager, app, monkeypatch, pair):
    record = manager.issue(["example.com"])
    monkeypatch.setattr(manager, "obtain", app.Manager.obtain.__get__(manager))
    monkeypatch.setattr(manager, "install_engine", lambda: None)
    real_run = app.run

    def acme(argv, **kwargs):
        if argv[0] == "openssl":
            return real_run(argv, **kwargs)
        if "--install-cert" in argv:
            for flag, name in (("--fullchain-file", "fullchain.pem"), ("--key-file", "key.pem")):
                app.Path(argv[argv.index(flag) + 1]).write_bytes((pair / name).read_bytes())
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.setattr(app, "run", acme)

    def no_space(*a, **k):
        raise OSError("Fixture: export copy failed")

    monkeypatch.setattr(app.shutil, "copyfile", no_space)
    with pytest.raises(app.OutcomeUnknown):
        manager.renew(record["id"])
    assert manager.read_record(record["id"])["operation"] == "unknown"
