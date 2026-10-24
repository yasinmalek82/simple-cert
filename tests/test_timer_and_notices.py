"""Timer ownership and private notifications, without host service changes."""

import importlib.util
import json
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
from test_simple_cert import app as app


@pytest.fixture
def installation(app, tmp_path, monkeypatch):
    source = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("installer", source / "installer.py")
    installer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(installer)
    prefix = tmp_path / "prefix"
    installer.install_file(source / "simple_cert.py", prefix)
    monkeypatch.setattr(app, "__file__", str(prefix / "lib/simple-cert/simple_cert.py"))
    monkeypatch.setattr(app, "AUTOMATION_DIR", tmp_path / "etc/simple-cert")
    units = tmp_path / "units"
    units.mkdir()
    monkeypatch.setattr(app, "SYSTEMD_DIR", units)
    monkeypatch.setattr(app, "require_systemd", lambda: None)
    calls = []

    def boundary(argv, **kwargs):
        assert argv[0] == "systemctl"
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, b"active", b"")

    monkeypatch.setattr(app, "run", boundary)
    return app.Manager(tmp_path / "state"), prefix, calls


def test_timer_is_opt_in_and_owned_by_one_installation_and_state(app, installation, tmp_path):
    manager, prefix, calls = installation
    assert not app.AUTOMATION_DIR.exists()
    app.install_automation(manager)
    owner = json.loads((app.AUTOMATION_DIR / "automation.json").read_text())
    assert owner["state"] == str(manager.settings_root)
    service = (app.SYSTEMD_DIR / "simple-cert-renew.service").read_text()
    assert "--worker" in service and str(manager.root) in service
    assert str(prefix / "lib/simple-cert/simple_cert.py") in service
    timer = (app.SYSTEMD_DIR / "simple-cert-renew.timer").read_text()
    assert "Asia/Tehran" in timer and "Persistent=false" in timer
    with pytest.raises(app.Error, match="another"):
        app.install_automation(app.Manager(tmp_path / "other-state"))
    assert owner == json.loads((app.AUTOMATION_DIR / "automation.json").read_text())


def test_uninstall_stops_owned_worker_and_timer_but_preserves_state(app, installation):
    manager, prefix, calls = installation
    app.install_automation(manager)
    settings = manager.root / "settings.json"
    settings.write_text("preserve-me")
    identified = app.identify_installation(prefix / "lib/simple-cert/simple_cert.py")
    app.remove_installation(identified)
    assert not (app.SYSTEMD_DIR / "simple-cert-renew.timer").exists()
    assert not (app.SYSTEMD_DIR / "simple-cert-renew.service").exists()
    assert any("stop" in call and "simple-cert-renew.service" in call for call in calls)
    assert settings.read_text() == "preserve-me"


def test_unknown_timer_is_never_overwritten(app, installation):
    manager, _, _ = installation
    timer = app.SYSTEMD_DIR / "simple-cert-renew.timer"
    timer.write_text("unrelated timer")
    with pytest.raises(app.Error):
        app.install_automation(manager)
    assert timer.read_text() == "unrelated timer"


def test_telegram_uses_post_and_hides_error_body_and_token(app, monkeypatch):
    received = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            received.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"ok":true}')

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    original = app.urllib.request.OpenerDirector.open

    def localhost(self, request, **kwargs):
        assert request.full_url == "https://api.telegram.org/bot12345:fixture-token/sendMessage"
        request.full_url = f"http://127.0.0.1:{server.server_port}/sendMessage"
        return original(self, request, **kwargs)

    monkeypatch.setattr(app.urllib.request.OpenerDirector, "open", localhost)
    try:
        app.send_telegram({"token": "12345:fixture-token", "chat_id": "-123"}, "Safe fixture notice")
    finally:
        server.shutdown()
        thread.join()
        server.server_close()
    assert received == [{"chat_id": "-123", "text": "Safe fixture notice", "disable_web_page_preview": True}]


def test_telegram_error_body_and_token_are_not_in_operator_error(app, monkeypatch):
    import urllib.error

    def denied(self, request, **kwargs):
        raise urllib.error.HTTPError(request.full_url, 403, "PRIVATE fixture-token", {}, None)

    monkeypatch.setattr(app.urllib.request.OpenerDirector, "open", denied)
    with pytest.raises(app.Error) as error:
        app.send_telegram({"token": "12345:fixture-token", "chat_id": "-123"}, "Fixture notice")
    assert "fixture-token" not in str(error.value)
    assert "PRIVATE" not in str(error.value)


def test_redirect_cannot_forward_telegram_credentials(app):
    with pytest.raises(app.Error, match="Redirect refused"):
        app.NoRedirect().redirect_request(None, None, 302, "move", {}, "https://unrelated.invalid")
