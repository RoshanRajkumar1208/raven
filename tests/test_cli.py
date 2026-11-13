"""Command-line behaviour: help, errors, shortcuts."""

from raven_api import __version__
from raven_api.cli import main


def test_no_arguments_prints_help(capsys):
    assert main([]) == 0
    assert "usage: raven" in capsys.readouterr().out


def test_version(capsys):
    try:
        main(["--version"])
    except SystemExit as exc:
        assert exc.code == 0
    assert __version__ in capsys.readouterr().out


def test_checks_lists_every_check(capsys):
    from raven_api.checks import CHECK_CLASSES

    assert main(["checks", "--no-color"]) == 0
    out = capsys.readouterr().out
    for cls in CHECK_CLASSES:
        assert cls.id in out and "Limits:" in out


def test_list_sends_nothing(demo, example, capsys):
    demo.seen.clear()
    assert main(["list", example("demo-openapi.yaml"), "--target", demo.base, "--no-color"]) == 0
    assert demo.seen == []
    assert "8 endpoints. Nothing was sent." in capsys.readouterr().out


def test_shortcut_without_scan_word(demo, example, tmp_path):
    out = tmp_path / "o"
    assert main([example("demo-urls.txt"), "--target", demo.base, "--only", "RAV-H02", "-o", str(out), "-q", "--no-color"]) == 0
    assert (out / "report.html").exists()


def test_friendly_errors(capsys, tmp_path, example):
    assert main(["scan", str(tmp_path / "missing.yaml"), "--no-color"]) == 2
    assert "File not found" in capsys.readouterr().err
    assert main(["scan", example("demo-openapi.yaml"), "--only", "RAV-XYZ", "--no-color"]) == 2
    assert "Unknown check" in capsys.readouterr().err
    assert main(["scan", example("demo-openapi.yaml"), "--format", "pdf", "--no-color"]) == 2
    assert "Unknown report format" in capsys.readouterr().err
    assert main(["scan", example("demo-openapi.yaml"), "--api-key", "novalue", "--no-color"]) == 2
    assert "NAME=VALUE" in capsys.readouterr().err
    assert main(["scan", example("demo-openapi.yaml"), "--target", "staging.example.com", "--no-color"]) == 2
    assert "http://" in capsys.readouterr().err
