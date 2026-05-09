import tarfile
import zipfile

from scripts.check_distribution_contents import main


def _write_wheel(path, members):
    with zipfile.ZipFile(path, "w") as wheel:
        for member in members:
            wheel.writestr(member, "")


def _write_sdist(path, members):
    with tarfile.open(path, "w:gz") as archive:
        for member in members:
            payload = b""
            info = tarfile.TarInfo(member)
            info.size = len(payload)
            archive.addfile(info)


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
