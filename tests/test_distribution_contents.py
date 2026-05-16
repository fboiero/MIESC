import io
import re
import tarfile
import zipfile
from pathlib import Path

from scripts.check_distribution_contents import main

PLATFORM_IMPORT_RE = re.compile(
    r"(^|\s)(from|import)\s+"
    r"(webapp|src\.licensing|src\.dashboard|vscode_extension|platform\.licensing)\b"
    r"|webapp\.|src\.licensing\.|src\.dashboard\."
)

CORE_SOURCE_GLOBS = (
    "miesc/**/*.py",
    "src/**/*.py",
    "scripts/**/*.py",
    "benchmarks/**/*.py",
    "examples/**/*.py",
)


def _write_wheel(path, members):
    with zipfile.ZipFile(path, "w") as wheel:
        for member in members:
            if isinstance(member, tuple):
                name, payload = member
            else:
                name, payload = member, ""
            wheel.writestr(name, payload)


def _write_sdist(path, members):
    with tarfile.open(path, "w:gz") as archive:
        for member in members:
            if isinstance(member, tuple):
                name, text = member
                payload = text.encode()
            else:
                name = member
                payload = b""
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))


def test_distribution_content_check_accepts_clean_artifacts(tmp_path, monkeypatch):
    _write_wheel(
        tmp_path / "miesc-5.4.0-py3-none-any.whl",
        [
            "miesc/__init__.py",
            "src/adapters/slither_adapter.py",
            "miesc-5.4.0.dist-info/METADATA",
        ],
    )
    _write_sdist(
        tmp_path / "miesc-5.4.0.tar.gz",
        [
            "miesc-5.4.0/miesc/__init__.py",
            "miesc-5.4.0/src/adapters/slither_adapter.py",
            "miesc-5.4.0/miesc.egg-info/PKG-INFO",
        ],
    )

    monkeypatch.setattr("sys.argv", ["check_distribution_contents.py", str(tmp_path)])

    assert main() == 0


def test_distribution_content_check_rejects_test_packages(tmp_path, monkeypatch):
    _write_wheel(
        tmp_path / "miesc-5.4.0-py3-none-any.whl",
        ["src/tests/__init__.py"],
    )

    monkeypatch.setattr("sys.argv", ["check_distribution_contents.py", str(tmp_path)])

    assert main() == 1


def test_distribution_content_check_rejects_duplicate_artifacts(tmp_path, monkeypatch):
    _write_sdist(
        tmp_path / "miesc-5.4.0.tar.gz",
        [
            "miesc-5.4.0/src/adapters 2/slither_adapter.py",
            "miesc-5.4.0/miesc.egg-info/PKG-INFO 2",
        ],
    )

    monkeypatch.setattr("sys.argv", ["check_distribution_contents.py", str(tmp_path)])

    assert main() == 1


def test_distribution_content_check_rejects_platform_components(tmp_path, monkeypatch):
    _write_wheel(
        tmp_path / "miesc-5.4.0-py3-none-any.whl",
        [
            "webapp/package.json",
            ".streamlit/config.toml",
            "src/dashboard/app.py",
            "src/licensing/manager.py",
            "vscode-extension/package.json",
            "streamlit_app.py",
        ],
    )

    monkeypatch.setattr("sys.argv", ["check_distribution_contents.py", str(tmp_path)])

    assert main() == 1


def test_distribution_content_check_rejects_platform_metadata(tmp_path, monkeypatch):
    _write_wheel(
        tmp_path / "miesc-5.4.0-py3-none-any.whl",
        [
            (
                "miesc-5.4.0.dist-info/METADATA",
                "Name: miesc\nProvides-Extra: web\nRequires-Dist: streamlit>=1.0\n",
            ),
        ],
    )
    _write_sdist(
        tmp_path / "miesc-5.4.0.tar.gz",
        [
            (
                "miesc-5.4.0/miesc.egg-info/PKG-INFO",
                "Name: miesc\nProvides-Extra: web\nRequires-Dist: streamlit>=1.0\n",
            ),
        ],
    )

    monkeypatch.setattr("sys.argv", ["check_distribution_contents.py", str(tmp_path)])

    assert main() == 1


def test_core_source_does_not_import_platform_modules():
    offenders = []
    for pattern in CORE_SOURCE_GLOBS:
        for path in Path(".").glob(pattern):
            if "__pycache__" in path.parts:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            if PLATFORM_IMPORT_RE.search(text):
                offenders.append(str(path))

    assert offenders == []
