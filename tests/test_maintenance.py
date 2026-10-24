"""Application maintenance uses temporary prefixes and fixture release responses."""

import hashlib
import importlib.util
import json
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def import_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


@pytest.fixture
def app():
    result = import_module("simple_cert", ROOT / "simple_cert.py")
    assert hasattr(result, "identify_installation"), "Application maintenance is not implemented yet"
    return result


@pytest.fixture
def installed(tmp_path):
    installer = import_module("installer", ROOT / "installer.py")
    prefix = tmp_path / "prefix"
    installer.install_file(ROOT / "simple_cert.py", prefix)
    return prefix


def test_installer_records_ownership_and_replaces_in_place(app, installed):
    script = installed / "lib/simple-cert/simple_cert.py"
    identified = app.identify_installation(script)
    assert identified["prefix"] == installed
    assert identified["version"] == app.VERSION
    marker = json.loads((script.parent / "installation.json").read_text())
    assert marker["sha256"] == hashlib.sha256(script.read_bytes()).hexdigest()
    assert len(list(script.parent.glob("simple_cert*.py"))) == 1


def test_discovery_deduplicates_aliases_and_rejects_unknown_code(app, installed, tmp_path, monkeypatch):
    script = installed / "lib/simple-cert/simple_cert.py"
    alias = tmp_path / "alias"
    alias.symlink_to(script)
    unknown = tmp_path / "unknown/lib/simple-cert/simple_cert.py"
    unknown.parent.mkdir(parents=True)
    unknown.write_text("print('unrelated tool')")
    monkeypatch.setattr(app, "candidate_scripts", lambda: [script, alias, unknown])
    copies = app.discover_installations()
    assert [item["script"] for item in copies] == [script]


def test_known_legacy_release_without_marker_is_detected(app, tmp_path):
    script = tmp_path / "legacy/lib/simple-cert/simple_cert.py"
    script.parent.mkdir(parents=True)
    # Read a real previous release when running from Git; a source archive can omit history.
    result = subprocess.run(
        ["git", "-c", f"safe.directory={ROOT}", "show", "v0.1.3:simple_cert.py"],
        cwd=ROOT,
        capture_output=True,
    )
    if result.returncode:
        pytest.skip("Legacy history fixture is available in a full Git checkout")
    script.write_bytes(result.stdout)
    assert app.identify_installation(script)["version"] == "0.1.3"


def test_uninstall_removes_only_owned_program_files(app, installed, tmp_path):
    script = installed / "lib/simple-cert/simple_cert.py"
    extra = script.parent / "keep-me.txt"
    extra.write_text("unrelated file")
    state = tmp_path / "state"
    state.mkdir()
    (state / "settings.json").write_text("private-settings-marker")
    (state / "key.pem").write_text("private-key-marker")
    app.remove_installation(app.identify_installation(script))
    assert not script.exists()
    assert not (installed / "bin/simple-cert").is_symlink()
    assert not (script.parent / "installation.json").exists()
    assert extra.read_text() == "unrelated file"
    assert (state / "settings.json").read_text() == "private-settings-marker"
    assert (state / "key.pem").read_text() == "private-key-marker"


@pytest.mark.parametrize("answer, other_removed", [("", False), ("yes", True)])
def test_uninstall_asks_before_removing_other_installations(
    app, installed, tmp_path, monkeypatch, answer, other_removed
):
    installer = import_module("installer", ROOT / "installer.py")
    other = tmp_path / "other"
    installer.install_file(ROOT / "simple_cert.py", other)
    script = installed / "lib/simple-cert/simple_cert.py"
    other_script = other / "lib/simple-cert/simple_cert.py"
    monkeypatch.setattr(app, "__file__", str(script))
    monkeypatch.setattr(app, "candidate_scripts", lambda: [script, other_script])
    monkeypatch.setattr(app.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(app.sys.stdout, "isatty", lambda: True)
    values = iter(["uninstall", answer])
    monkeypatch.setattr("builtins.input", lambda _: next(values))
    assert app.uninstall_menu(app.Manager(tmp_path / "state"))
    assert not script.exists()
    assert other_script.exists() is not other_removed


def test_cancelled_uninstall_changes_nothing(app, installed, tmp_path, monkeypatch):
    script = installed / "lib/simple-cert/simple_cert.py"
    monkeypatch.setattr(app, "__file__", str(script))
    monkeypatch.setattr(app, "candidate_scripts", lambda: [script])
    monkeypatch.setattr(app.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(app.sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _: "no")
    assert not app.uninstall_menu(app.Manager(tmp_path / "state"))
    assert script.exists()


def test_changed_program_is_not_deleted(app, installed):
    script = installed / "lib/simple-cert/simple_cert.py"
    identified = app.identify_installation(script)
    script.write_text("unrelated replacement")
    with pytest.raises(app.Error):
        app.remove_installation(identified)
    assert script.read_text() == "unrelated replacement"


def test_update_checks_release_digest_then_replaces_same_prefix(app, installed, tmp_path, monkeypatch):
    script = installed / "lib/simple-cert/simple_cert.py"
    monkeypatch.setattr(app, "__file__", str(script))
    monkeypatch.setattr(app.os, "geteuid", lambda: 0)
    monkeypatch.setattr(app, "VERSION", "0.1.3")
    data = (ROOT / "installer.py").read_bytes()
    release = {
        "tag_name": "v0.1.10",
        "draft": False,
        "prerelease": False,
        "assets": [{"name": "installer.py", "digest": "sha256:" + hashlib.sha256(data).hexdigest()}],
    }
    monkeypatch.setattr(
        app, "download", lambda url: json.dumps(release).encode() if "/releases/latest" in url else data
    )
    monkeypatch.setattr("builtins.input", lambda _: "yes")

    real_run = app.run

    def install(argv, **kwargs):
        if argv[-1] == "--version":
            return real_run(argv, **kwargs)
        assert argv[-2:] == ["--prefix", str(installed)]
        # Exercise a real isolated installation at the subprocess boundary.
        installer = import_module("downloaded_installer", Path(argv[1]))
        installer.install_file(ROOT / "simple_cert.py", installed)
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.setattr(app, "run", install)
    assert app.update_menu(app.Manager(tmp_path / "state"))
    assert script.is_file()
    assert len(list(script.parent.glob("simple_cert*.py"))) == 1


def test_bad_update_digest_keeps_current_installation(app, installed, tmp_path, monkeypatch):
    script = installed / "lib/simple-cert/simple_cert.py"
    old = script.read_bytes()
    monkeypatch.setattr(app, "__file__", str(script))
    monkeypatch.setattr(app.os, "geteuid", lambda: 0)
    release = {
        "tag_name": "v99.0.0",
        "draft": False,
        "prerelease": False,
        "assets": [{"name": "installer.py", "digest": "sha256:" + "0" * 64}],
    }
    monkeypatch.setattr(
        app,
        "download",
        lambda url: json.dumps(release).encode() if "/releases/latest" in url else b"untrusted code",
    )
    monkeypatch.setattr("builtins.input", lambda _: "yes")
    with pytest.raises(app.Error, match="checksum"):
        app.update_menu(app.Manager(tmp_path / "state"))
    assert script.read_bytes() == old


def test_latest_installed_version_does_not_download_installer(app, installed, tmp_path, monkeypatch):
    monkeypatch.setattr(app, "__file__", str(installed / "lib/simple-cert/simple_cert.py"))
    monkeypatch.setattr(app.os, "geteuid", lambda: 0)
    release = {"tag_name": "v" + app.VERSION, "draft": False, "prerelease": False, "assets": []}

    def download(url):
        assert url.endswith("/releases/latest")
        return json.dumps(release).encode()

    monkeypatch.setattr(app, "download", download)
    assert not app.update_menu(app.Manager(tmp_path / "state"))


def test_update_refuses_program_changed_during_download(app, installed, tmp_path, monkeypatch):
    script = installed / "lib/simple-cert/simple_cert.py"
    monkeypatch.setattr(app, "__file__", str(script))
    monkeypatch.setattr(app.os, "geteuid", lambda: 0)
    data = (ROOT / "installer.py").read_bytes()
    release = {
        "tag_name": "v99.0.0",
        "draft": False,
        "prerelease": False,
        "assets": [{"name": "installer.py", "digest": "sha256:" + hashlib.sha256(data).hexdigest()}],
    }

    def download(url):
        if url.endswith("/releases/latest"):
            return json.dumps(release).encode()
        script.write_text("unrelated replacement")
        return data

    monkeypatch.setattr(app, "download", download)
    monkeypatch.setattr("builtins.input", lambda _: "yes")
    with pytest.raises(app.Error, match="changed"):
        app.update_menu(app.Manager(tmp_path / "state"))
    assert script.read_text() == "unrelated replacement"


def test_update_does_not_claim_success_when_installer_does_nothing(app, installed, tmp_path, monkeypatch):
    script = installed / "lib/simple-cert/simple_cert.py"
    monkeypatch.setattr(app, "__file__", str(script))
    monkeypatch.setattr(app.os, "geteuid", lambda: 0)
    data = (ROOT / "installer.py").read_bytes()
    release = {
        "tag_name": "v99.0.0",
        "draft": False,
        "prerelease": False,
        "assets": [{"name": "installer.py", "digest": "sha256:" + hashlib.sha256(data).hexdigest()}],
    }
    monkeypatch.setattr(
        app, "download", lambda url: json.dumps(release).encode() if "/releases/latest" in url else data
    )
    monkeypatch.setattr("builtins.input", lambda _: "yes")
    real_run = app.run
    monkeypatch.setattr(
        app,
        "run",
        lambda argv, **kwargs: (
            real_run(argv, **kwargs)
            if argv[-1] == "--version"
            else subprocess.CompletedProcess(argv, 0, b"", b"")
        ),
    )
    with pytest.raises(app.Error, match="version"):
        app.update_menu(app.Manager(tmp_path / "state"))
