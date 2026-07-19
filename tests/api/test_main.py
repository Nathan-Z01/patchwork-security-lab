from __future__ import annotations

from types import SimpleNamespace

import pytest

from patchwork_api import __main__ as api_main


def test_main_passes_explicit_bind_options_without_ignoring_argv(monkeypatch) -> None:
    observed = {}

    def run(application, **options):
        observed["application"] = application
        observed.update(options)

    monkeypatch.setattr(
        api_main.importlib,
        "import_module",
        lambda name: SimpleNamespace(run=run),
    )

    api_main.main(["--host", "127.0.0.2", "--port", "8877"])

    assert observed == {
        "application": "patchwork_api.app:app",
        "host": "127.0.0.2",
        "port": 8877,
        "reload": False,
    }


def test_help_exits_without_importing_uvicorn(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        api_main.importlib,
        "import_module",
        lambda name: pytest.fail("--help must not start the server"),
    )

    with pytest.raises(SystemExit) as exc_info:
        api_main.main(["--help"])

    assert exc_info.value.code == 0
    assert "--host" in capsys.readouterr().out
