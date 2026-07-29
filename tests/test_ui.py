"""Smoke tests for the optional Streamlit UI (skipped when streamlit is not installed)."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from yagtha.exporter import BUNDLE_FILES, REPORT, bundle_zip

APP = Path(__file__).resolve().parent.parent / "app" / "streamlit_app.py"


def test_bundle_zip_is_deterministic_and_safe() -> None:
    data = bundle_zip("rule", {REPORT: "# r\n"})
    assert data == bundle_zip("rule", {REPORT: "# r\n"})
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        assert archive.namelist() == ["rule/report.md"]
        assert archive.read("rule/report.md") == b"# r\n"
    from yagtha.errors import ExportError

    with pytest.raises(ExportError):
        bundle_zip("../x", {REPORT: ""})
    with pytest.raises(ExportError):
        bundle_zip("rule", {"../evil": ""})
    assert "report.md" in BUNDLE_FILES


def test_app_runs_the_sample_rule() -> None:
    testing = pytest.importorskip("streamlit.testing.v1")
    app = testing.AppTest.from_file(str(APP), default_timeout=30)
    app.run()
    assert not app.exception
    app.sidebar.button[0].click().run()
    assert not app.exception
    assert app.metric[0].value == "PASSED"
    assert "YAGTHA report: Mimikatz" in app.markdown[0].value or any(
        "YAGTHA report: Mimikatz" in m.value for m in app.markdown
    )
