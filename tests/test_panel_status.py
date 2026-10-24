"""Read-only inspection of existing panel PEMs and associated renewal schedules."""

import datetime as dt
import json
import shutil

import pytest
from test_simple_cert import app as app
from test_simple_cert import pair as pair


@pytest.fixture
def installed_panel(app, pair, tmp_path, monkeypatch):
    root = tmp_path / "server"
    data = root / "var/lib/pasarguard"
    data.mkdir(parents=True)
    certs = data / "certs/panel.example.com"
    certs.mkdir(parents=True)
    for name in ("fullchain.pem", "key.pem"):
        shutil.copyfile(pair / name, certs / name)
    target = {
        "kind": "docker",
        "id": "fixture-panel",
        "name": "mother",
        "data": "/var/lib/pasarguard",
        "https": {
            "UVICORN_SSL_CERTFILE": "/var/lib/pasarguard/certs/panel.example.com/fullchain.pem",
            "UVICORN_SSL_KEYFILE": "/var/lib/pasarguard/certs/panel.example.com/key.pem",
            "UVICORN_HOST": "0.0.0.0",
            "UVICORN_PORT": "8000",
        },
        "mounts": [{"Source": str(data), "Destination": "/var/lib/pasarguard", "Type": "bind", "RW": False}],
    }
    monkeypatch.setattr(app, "discover_panels", lambda: [target])
    return root, target, certs


def test_status_reads_existing_readonly_mount_and_does_not_change_pems(app, installed_panel, capsys):
    _, target, certs = installed_panel
    before = {p.name: (p.read_bytes(), p.stat().st_mode) for p in certs.iterdir()}
    status = app.inspect_panel_https(target)
    assert status["domains"] == ["*.example.com", "example.com"]
    assert dt.datetime.fromisoformat(status["expires_at"]) > dt.datetime.now(dt.timezone.utc)
    assert 58 <= status["days_remaining"] <= 60
    assert status["host_certfile"] == str(certs / "fullchain.pem")
    assert status["source"] == "running container environment"
    assert {p.name: (p.read_bytes(), p.stat().st_mode) for p in certs.iterdir()} == before
    assert "PRIVATE KEY" not in capsys.readouterr().out


def test_acme_schedule_requires_matching_export_record_and_active_cron(app, installed_panel):
    root, target, certs = installed_panel
    acme = root / "root/.acme.sh/example.com_ecc"
    acme.mkdir(parents=True)
    (acme / "example.com.conf").write_text(
        f"Le_RealFullChainPath='{certs / 'fullchain.pem'}'\nLe_ReloadCmd='encoded-hook'\nCF_Token='secret-fixture'\n"
    )
    status = app.inspect_panel_https(target)
    jobs = [{"client": "acme.sh", "home": "/root/.acme.sh", "source": "root crontab", "active": True}]
    result = app.inspect_renewal(status, jobs, system_root=root)
    assert result[0]["state"] == "scheduled"
    assert result[0]["source"] == "root crontab"
    assert result[0]["reload_hook"] == "configured (not executed)"
    assert "secret-fixture" not in json.dumps(result)
    jobs[0]["active"] = False
    assert app.inspect_renewal(status, jobs, system_root=root)[0]["state"] == "scheduler inactive"
    (acme / "example.com.conf").write_text("Le_RealFullChainPath='/unrelated/fullchain.pem'\n")
    assert app.inspect_renewal(status, jobs, system_root=root) == []


def test_certbot_timer_correlates_with_configured_certificate(app, installed_panel):
    root, target, certs = installed_panel
    renewal = root / "etc/letsencrypt/renewal"
    renewal.mkdir(parents=True)
    (renewal / "example.com.conf").write_text(
        f"fullchain = {certs / 'fullchain.pem'}\n[renewalparams]\nauthenticator = nginx\n"
    )
    status = app.inspect_panel_https(target)
    jobs = [
        {
            "client": "certbot",
            "home": "/etc/letsencrypt",
            "source": "certbot.timer",
            "active": True,
            "next_run": "tomorrow",
            "last_result": "success",
            "last_run": "yesterday",
        }
    ]
    result = app.inspect_renewal(status, jobs, system_root=root)
    assert result[0]["state"] == "scheduled"
    assert result[0]["source"] == "certbot.timer"
    assert result[0]["next_run"] == "tomorrow"
    assert result[0]["last_result"] == "success"


def test_installed_client_or_unrelated_timer_is_not_proof_of_panel_renewal(app, installed_panel):
    root, target, _ = installed_panel
    (root / "root/.acme.sh").mkdir(parents=True)
    status = app.inspect_panel_https(target)
    assert app.inspect_renewal(status, [], system_root=root) == []


def test_cron_parser_does_not_execute_or_print_commands_and_ignores_reboot(app):
    text = '0 2 * * * "/root/.acme.sh"/acme.sh --cron --home "/root/.acme.sh" > /dev/null\n'
    jobs = app.parse_renewal_cron(text, source="root crontab", active=True)
    assert jobs == [{"client": "acme.sh", "home": "/root/.acme.sh", "source": "root crontab", "active": True}]
    assert (
        app.parse_renewal_cron(text.replace("0 2 * * *", "@reboot"), source="root crontab", active=True) == []
    )
    assert app.parse_renewal_cron("# " + text, source="root crontab", active=True) == []


def test_status_handles_missing_files_without_guessing_public_url(app, installed_panel):
    _, target, certs = installed_panel
    (certs / "fullchain.pem").unlink()
    status = app.inspect_panel_https(target)
    assert status["state"] == "certificate unavailable"
    assert status["public_url"] == "not confirmed"


def test_option_seven_shows_readonly_status_before_prompt(app, tmp_path, monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(app, "show_panel_https_status", lambda: calls.append("status"))
    values = iter(["2", "0", "0"])

    def answer(prompt):
        if prompt == "Choose [0-5]: ":
            assert calls == ["status"]
        return next(values)

    monkeypatch.setattr("builtins.input", answer)
    app.menu(app.Manager(tmp_path / "state"))
    assert calls == ["status"]


def test_echoed_command_and_domain_scoped_job_are_not_global_renewal_evidence(app, installed_panel):
    assert app.renewal_command("echo /root/.acme.sh/acme.sh --cron --home /root/.acme.sh") is None
    assert app.renewal_command("/root/.acme.sh/acme.sh --renew") is None
    root, target, certs = installed_panel
    home = root / "root/.acme.sh/example.com_ecc"
    home.mkdir(parents=True)
    (home / "example.com.conf").write_text(
        f"Le_RealFullChainPath='{certs / 'fullchain.pem'}'\nLe_Domain='example.com'\n"
    )
    job = app.renewal_command("/root/.acme.sh/acme.sh --renew -d unrelated.com --home /root/.acme.sh")
    result = app.inspect_renewal(
        app.inspect_panel_https(target), [{**job, "source": "root crontab", "active": True}], system_root=root
    )
    assert result[0]["state"] == "tracking record only"


def test_docker_tls_discovery_handles_null_labels_without_guessing_env_file(app):
    target = app.docker_panels(
        [
            {
                "Id": "fixture",
                "Name": "/mother",
                "State": {"Running": True},
                "Config": {
                    "Image": "pasarguard/panel:fixture",
                    "Labels": None,
                    "Env": ["UVICORN_SSL_CERTFILE=/public/cert.pem", "CF_Token=hidden-fixture"],
                },
            }
        ]
    )[0]
    assert target["https"] == {"UVICORN_SSL_CERTFILE": "/public/cert.pem"}
    assert target["env_file"] is None
    assert "hidden-fixture" not in json.dumps(target)


def test_timer_job_collection_checks_command_not_unit_name(app, installed_panel, monkeypatch):
    import subprocess

    root, _, _ = installed_panel

    def boundary(argv, **kwargs):
        assert argv[0] in ("systemctl", "crontab")
        output = b""
        if argv[1] == "list-timers":
            output = b"tomorrow - today - custom.timer custom.service\n"
        elif argv[1:3] == ["show", "custom.timer"]:
            output = b"ActiveState=active\nUnit=custom.service\nNextElapseUSecRealtime=tomorrow\n"
        elif argv[1:3] == ["show", "custom.service"]:
            output = b"ExecStart={ path=/usr/bin/certbot ; argv[]=/usr/bin/certbot -q renew ; ignore_errors=no ; }\nResult=success\nExecMainExitTimestamp=yesterday\n"
        elif argv[1] == "is-active":
            output = b"active\n"
        return subprocess.CompletedProcess(argv, 0, output, b"")

    monkeypatch.setattr(app, "run", boundary)
    jobs = app.renewal_jobs(system_root=root)
    assert jobs == [
        {
            "client": "certbot",
            "home": "/etc/letsencrypt",
            "source": "custom.timer",
            "active": True,
            "next_run": "tomorrow",
            "last_result": "success",
            "last_run": "yesterday",
        }
    ]


def test_env_file_is_not_sourced_and_secrets_are_not_retained(app, installed_panel):
    _, target, certs = installed_panel
    env = certs.parent / ".env"
    sentinel = certs.parent / "must-not-exist"
    env.write_text(
        f'UVICORN_SSL_CERTFILE="{target["https"]["UVICORN_SSL_CERTFILE"]}"\n'
        f'UVICORN_SSL_KEYFILE="{target["https"]["UVICORN_SSL_KEYFILE"]}"\n'
        f'CF_Token="secret-fixture"\nDANGEROUS=$(touch "{sentinel}")\n'
    )
    target["https"] = {}
    target["env_file"] = str(env)
    before = env.read_bytes(), env.stat().st_mode
    status = app.inspect_panel_https(target)
    assert status["source"] == "env file (runtime configuration not verified)"
    assert status["state"] == "valid configured PEM"
    assert "secret-fixture" not in json.dumps(status)
    assert not sentinel.exists()
    assert (env.read_bytes(), env.stat().st_mode) == before


def test_configured_certificate_can_be_expired_and_symlinked(app, installed_panel, monkeypatch):
    _, target, certs = installed_panel
    archive = certs / "archive.pem"
    (certs / "fullchain.pem").rename(archive)
    (certs / "fullchain.pem").symlink_to("archive.pem")

    class Future(dt.datetime):
        @classmethod
        def now(cls, tz=None):
            return super().now(tz) + dt.timedelta(days=90)

    monkeypatch.setattr(app.dt, "datetime", Future)
    status = app.inspect_panel_https(target)
    assert status["state"] == "expired"
    assert status["days_remaining"] < 0


def test_status_scan_failure_does_not_block_panel_menu(app, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(app, "discover_panels", lambda: [{"kind": "native", "name": "fixture", "https": {}}])

    def unavailable(**kwargs):
        raise PermissionError("secret-fixture")

    monkeypatch.setattr(app, "renewal_jobs", unavailable)
    values = iter(["2", "0", "0"])
    monkeypatch.setattr("builtins.input", lambda _: next(values))
    app.menu(app.Manager(tmp_path / "state"))
    output = capsys.readouterr().out
    assert "PANEL HTTPS CERTIFICATES" in output
    assert "secret-fixture" not in output


def test_panel_status_refresh_is_explicit_and_menu_redraw_uses_cached_report(app, tmp_path, monkeypatch):
    calls = []

    def report():
        calls.append("scan")
        return "read-only report"

    monkeypatch.setattr(app, "show_panel_https_status", report)
    monkeypatch.setattr(app, "clear_screen", lambda: False)
    values = iter(["2", "2", "5", "0", "0"])
    monkeypatch.setattr("builtins.input", lambda _: next(values))
    app.menu(app.Manager(tmp_path / "state"))
    assert calls == ["scan", "scan"]


def test_never_run_timer_does_not_report_default_success_as_completed_renewal(
    app, installed_panel, monkeypatch
):
    import subprocess

    root, _, _ = installed_panel

    def boundary(argv, **kwargs):
        output = b""
        if argv[1] == "list-timers":
            output = b"n/a n/a n/a certbot.timer certbot.service\n"
        elif argv[1:3] == ["show", "certbot.timer"]:
            output = b"ActiveState=active\nUnit=certbot.service\n"
        elif argv[1:3] == ["show", "certbot.service"]:
            output = b"ExecStart={ path=/usr/bin/certbot ; argv[]=/usr/bin/certbot renew ; ignore_errors=no ; }\nResult=success\nExecMainExitTimestamp=\n"
        return subprocess.CompletedProcess(argv, 0, output, b"")

    monkeypatch.setattr(app, "run", boundary)
    assert app.renewal_jobs(system_root=root)[0]["last_result"] == "not recorded"
