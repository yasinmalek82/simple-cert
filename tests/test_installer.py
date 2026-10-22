"""Installation smoke uses a temporary prefix, without network or root."""

import importlib.util
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_install_and_reinstall_preserve_private_state(tmp_path):
    installer = ROOT / "installer.py"
    assert installer.is_file(), "The standalone installer is not implemented yet"
    spec = importlib.util.spec_from_file_location("installer", installer)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    state = tmp_path / "home/.local/share/simple-cert"
    state.mkdir(parents=True)
    (state / "settings.json").write_text("private-state-marker")
    prefix = tmp_path / "prefix"
    for _ in range(2):
        module.install_file(ROOT / "simple_cert.py", prefix)
        result = subprocess.run([str(prefix / "bin/simple-cert"), "--version"], capture_output=True)
        assert result.returncode == 0
        assert result.stdout.strip() == b"simple-cert 0.1.0"
        result = subprocess.run(
            [str(prefix / "bin/simple-cert"), "--state-dir", str(state)],
            input=b"2\n0\n",
            capture_output=True,
            cwd=tmp_path,
        )
        assert result.returncode == 0
        assert b"No certificates" in result.stdout
    assert (state / "settings.json").read_text() == "private-state-marker"


def test_installer_rejects_wrong_download_before_replacing(tmp_path):
    installer = ROOT / "installer.py"
    assert installer.is_file(), "The standalone installer is not implemented yet"
    spec = importlib.util.spec_from_file_location("installer", installer)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with pytest.raises(module.InstallError, match="checksum"):
        module.verify_download(b"truncated or unexpected source")
    assert not (tmp_path / "bin/simple-cert").exists()


def test_release_checksum_accepts_the_shipped_script():
    spec = importlib.util.spec_from_file_location("installer", ROOT / "installer.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.verify_download((ROOT / "simple_cert.py").read_bytes())


def test_malformed_upgrade_retains_installed_program(tmp_path):
    spec = importlib.util.spec_from_file_location("installer", ROOT / "installer.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    prefix = tmp_path / "prefix"
    module.install_file(ROOT / "simple_cert.py", prefix)
    old = (prefix / "bin/simple-cert").read_bytes()
    source = tmp_path / "broken.py"
    source.write_text("raise RuntimeError('invalid package')")
    with pytest.raises(module.InstallError):
        module.install_file(source, prefix)
    assert (prefix / "bin/simple-cert").read_bytes() == old
