"""Parse generated units/calendar using real systemd tools when available."""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from test_simple_cert import app as app


@pytest.mark.skipif(not shutil.which("systemd-analyze"), reason="Requires Linux systemd-analyze")
def test_systemd_accepts_units_and_tehran_retry_calendar(app, tmp_path):
    units = app.automation_units(Path(sys.executable), tmp_path / "private state")
    for name, text in units.items():
        (tmp_path / name).write_text(text)
    # This only parses temporary files; it never installs/enables/starts a unit.
    result = subprocess.run(
        [
            "systemd-analyze",
            "verify",
            str(tmp_path / "simple-cert-renew.service"),
            str(tmp_path / "simple-cert-renew.timer"),
        ],
        capture_output=True,
    )
    assert result.returncode == 0, result.stderr.decode()
    calendar = subprocess.run(
        [
            "systemd-analyze",
            "calendar",
            "--iterations=3",
            "--base-time=2026-10-24 00:00:00 UTC",
            "*-*-* 04:00,10,20:00 Asia/Tehran",
        ],
        capture_output=True,
        env={**os.environ, "TZ": "UTC", "LC_ALL": "C"},
    )
    assert calendar.returncode == 0, calendar.stderr.decode()
    output = calendar.stdout.decode()
    assert "00:30:00" in output and "00:40:00" in output and "00:50:00" in output
