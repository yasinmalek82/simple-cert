"""Offline scheduled renewal: real state/files and substituted external boundaries."""

import datetime as dt
import json
import shutil

import pytest
from test_simple_cert import app as app
from test_simple_cert import manager as manager
from test_simple_cert import pair as pair


def at(hour=0, minute=30):
    # UTC 00:30 is 04:00 Tehran.
    return dt.datetime(2026, 10, 24, hour, minute, tzinfo=dt.timezone.utc)


def prepare(manager, app, monkeypatch, pair):
    record = manager.issue(["example.com"])
    app.set_automation(manager, record["id"], True)

    def obtain(self, record, destination, renew=False):
        for name in ("fullchain.pem", "key.pem"):
            shutil.copyfile(pair / name, destination / name)

    monkeypatch.setattr(app.Manager, "obtain", obtain)
    return record


def saved(manager, record):
    return json.loads((manager.root / "certificates" / record["id"] / "record.json").read_text())


def test_worker_outside_window_and_unselected_certificate_never_calls_acme(manager, app, monkeypatch):
    record = manager.issue(["example.com"])
    monkeypatch.setattr(app.Manager, "obtain", lambda *a, **k: pytest.fail("No CA call authorized"))
    assert app.worker(manager.settings_root, now=at()) == 0
    app.set_automation(manager, record["id"], True)
    assert app.worker(manager.settings_root, now=at(9)) == 0
    assert "schedule" not in saved(manager, record)


def test_worker_checks_once_per_day_and_does_not_publish_identical_files(manager, app, monkeypatch, pair):
    record = prepare(manager, app, monkeypatch, pair)
    folder = manager.root / "certificates" / record["id"]
    previous = (folder / "current").readlink()
    assert app.worker(manager.settings_root, now=at()) == 0
    monkeypatch.setattr(app.Manager, "obtain", lambda *a, **k: pytest.fail("Already checked today"))
    assert app.worker(manager.settings_root, now=at(0, 40)) == 0
    assert (folder / "current").readlink() == previous
    assert saved(manager, record)["schedule"]["attempts"] == 1
    assert saved(manager, record)["schedule"]["outcome"] == "done"


def test_worker_retries_definite_failures_only_in_later_slots_and_stops_after_three(
    manager, app, monkeypatch, pair
):
    record = prepare(manager, app, monkeypatch, pair)

    def fail(*a, **k):
        raise app.Error("Private external details must never be copied to notices")

    monkeypatch.setattr(app.Manager, "obtain", fail)
    for instant, count in [(at(), 1), (at(0, 31), 1), (at(0, 40), 2), (at(0, 50), 3), (at(0, 55), 3)]:
        app.worker(manager.settings_root, now=instant)
        assert saved(manager, record)["schedule"]["attempts"] == count
    assert "Private external" not in (manager.root / "notifications.json").read_text()


def test_unknown_result_holds_next_day_without_reissuing(manager, app, monkeypatch, pair):
    record = prepare(manager, app, monkeypatch, pair)

    def unknown(*a, **k):
        raise app.OutcomeUnknown("Unknown result")

    monkeypatch.setattr(app.Manager, "obtain", unknown)
    app.worker(manager.settings_root, now=at())
    monkeypatch.setattr(
        app.Manager, "obtain", lambda *a, **k: pytest.fail("Unknown result must stay on hold")
    )
    app.worker(manager.settings_root, now=at() + dt.timedelta(days=1))
    assert saved(manager, record)["schedule"]["outcome"] == "unknown"


def test_worker_does_not_overlap_existing_worker(manager, app):
    with app.locked(manager.settings_root / "worker"):
        assert app.worker(manager.settings_root, now=at()) == 0


def test_automation_cannot_enroll_unissued_or_invalid_certificate(manager, app):
    record = manager.issue(["example.com"])
    (manager.root / "certificates" / record["id"] / "current/key.pem").unlink()
    with pytest.raises(app.Error):
        app.set_automation(manager, record["id"], True)


def test_notification_delivery_failure_does_not_repeat_renewal(manager, app, monkeypatch, pair):
    record = prepare(manager, app, monkeypatch, pair)
    app.enqueue_notice(
        manager.settings_root, "fixture-event", "Certificate test; manual activation required."
    )
    app.configure_telegram(manager.settings_root, "12345:fixture-token", "-10012345")
    monkeypatch.setattr(app, "send_telegram", lambda *a, **k: (_ for _ in ()).throw(app.Error("unavailable")))
    app.worker(manager.settings_root, now=at())
    assert saved(manager, record)["schedule"]["outcome"] == "done"
    monkeypatch.setattr(app.Manager, "obtain", lambda *a, **k: pytest.fail("No duplicate renewal"))
    monkeypatch.setattr(app, "send_telegram", lambda *a, **k: None)
    app.worker(manager.settings_root, now=at(0, 40))
    queue = json.loads((manager.root / "notifications.json").read_text())
    assert queue["fixture-event"]["sent"] is True


def test_expiry_alerts_are_deduplicated_and_secrets_not_in_queue(manager, app):
    record = manager.issue(["example.com"])
    instant = dt.datetime.fromisoformat(record["expires_at"]) - dt.timedelta(days=2)
    app.expiry_notice(manager, record, instant)
    app.expiry_notice(manager, record, instant)
    queue = json.loads((manager.root / "notifications.json").read_text())
    assert len(queue) == 1
    text = json.dumps(queue)
    assert "example.com" in text
    assert "secret-token" not in text and "PRIVATE KEY" not in text


def test_completed_check_can_retry_pending_delivery_without_ca_request(manager, app, monkeypatch, pair):
    record = prepare(manager, app, monkeypatch, pair)
    app.worker(manager.settings_root, now=at())
    path = manager.root / "certificates" / record["id"] / "record.json"
    state = json.loads(path.read_text())
    state["deliveries"] = [
        {
            "kind": "docker",
            "name": "fixture",
            "directory": "/panel-data/test",
            "host_directory": "/tmp/fixture",
            "status": "pending",
        }
    ]
    path.write_text(json.dumps(state))
    monkeypatch.setattr(app.Manager, "obtain", lambda *a, **k: pytest.fail("Delivery retry must not call CA"))
    monkeypatch.setattr(app, "discover_panels", lambda: [])
    app.worker(manager.settings_root, now=at(0, 40))
    queue = json.loads((manager.root / "notifications.json").read_text())
    assert any("Delivery pending" in event["message"] for event in queue.values())


def test_completed_publication_notice_is_recovered_after_worker_crash(manager, app, monkeypatch, pair):
    record = prepare(manager, app, monkeypatch, pair)
    app.worker(manager.settings_root, now=at())
    path = manager.root / "certificates" / record["id"] / "record.json"
    state = json.loads(path.read_text())
    state["result"] = "changed"
    path.write_text(json.dumps(state))
    monkeypatch.setattr(app.Manager, "obtain", lambda *a, **k: pytest.fail("No repeated CA action"))
    app.worker(manager.settings_root, now=at(0, 40))
    queue = json.loads((manager.root / "notifications.json").read_text())
    assert any("renewed files" in event["message"] for event in queue.values())


def test_crash_after_local_completion_reconciles_in_progress_schedule(manager, app, monkeypatch, pair):
    record = prepare(manager, app, monkeypatch, pair)
    path = manager.root / "certificates" / record["id"] / "record.json"
    state = json.loads(path.read_text())
    state["schedule"] = {
        "attempt_id": "interrupted",
        "day": "2026-10-24",
        "attempts": 1,
        "slot": 0,
        "outcome": "in progress",
    }
    path.write_text(json.dumps(state))
    monkeypatch.setattr(
        app.Manager, "obtain", lambda *a, **k: pytest.fail("Completed files need no CA request")
    )
    assert app.worker(manager.settings_root, now=at(0, 40)) == 0
    assert saved(manager, record)["schedule"]["outcome"] == "done"


def test_previous_failed_day_is_reported_before_next_daily_attempt(manager, app, monkeypatch, pair):
    prepare(manager, app, monkeypatch, pair)

    def fail(*a, **k):
        raise app.Error("Fixture definite failure")

    monkeypatch.setattr(app.Manager, "obtain", fail)
    app.worker(manager.settings_root, now=at())
    app.worker(manager.settings_root, now=at() + dt.timedelta(days=1))
    queue = json.loads((manager.root / "notifications.json").read_text())
    assert any("unresolved renewal failure" in event["message"] for event in queue.values())
