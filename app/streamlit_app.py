"""YAGTHA web UI (optional).

Run from the project folder:

    pip install -e ".[ui]"
    streamlit run app/streamlit_app.py

Everything runs in memory: uploaded rules and events are validated with the
same limits as the CLI, nothing is written to disk, and the bundle is offered
as a zip download.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import streamlit as st

from yagtha.errors import YagthaError
from yagtha.events import MAX_EVENTS_BYTES, load_events, validate_events
from yagtha.exporter import bundle_name, bundle_zip
from yagtha.mutations import list_mutations
from yagtha.pipeline import RunResult, bundle_files, run_pipeline
from yagtha.rule_loader import MAX_RULE_BYTES, read_rule_text

DATA = Path(__file__).resolve().parent.parent / "data"
RULES = DATA / "rules"
BENIGN = DATA / "benign_events" / "benign.json"


def read_upload(upload: Any, limit: int, what: str) -> str:
    """Text of an uploaded file, refusing anything over ``limit`` bytes."""
    if upload.size > limit:
        raise YagthaError(f"{what} is larger than {limit} bytes")
    try:
        return str(upload.getvalue().decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise YagthaError(f"{what} is not UTF-8 text") from exc


def events_from_upload(upload: Any, what: str) -> list[Any]:
    """Validated events from an uploaded JSON file."""
    try:
        data = json.loads(read_upload(upload, MAX_EVENTS_BYTES, what))
    except json.JSONDecodeError as exc:
        raise YagthaError(f"{what} is not valid JSON: {exc}") from exc
    return list(validate_events(data))


def inputs() -> tuple[str, str, list[Any], list[Any], list[str]] | None:
    """Sidebar: rule, events, benign events and mutations. None until all are given."""
    st.sidebar.header("Input")
    source = st.sidebar.radio("Rule", ["Sample rule", "Upload my own"])
    if source == "Sample rule":
        names = sorted(p.stem for p in RULES.glob("*.yml"))
        stem = st.sidebar.selectbox("Sample", names, index=names.index("mimikatz"))
        rule_text = read_rule_text(RULES / f"{stem}.yml")
        events = list(load_events(DATA / "malicious_events" / f"{stem}.json"))
        name = stem
    else:
        rule_file = st.sidebar.file_uploader("Sigma rule (.yml)", type=["yml", "yaml"])
        events_file = st.sidebar.file_uploader("Events the rule should catch (.json)", type="json")
        if rule_file is None or events_file is None:
            st.info("Upload a rule and its events in the sidebar, or pick a sample rule.")
            return None
        rule_text = read_upload(rule_file, MAX_RULE_BYTES, "rule file")
        events = events_from_upload(events_file, "events file")
        name = bundle_name(Path(rule_file.name))
    if st.sidebar.checkbox("Use the built-in benign events", value=True):
        benign = list(load_events(BENIGN))
    else:
        benign_file = st.sidebar.file_uploader("Benign events (.json)", type="json")
        benign = events_from_upload(benign_file, "benign file") if benign_file else []
    all_names = [m.name for m in list_mutations()]
    chosen = st.sidebar.multiselect("Mutations", all_names, default=all_names)
    return name, rule_text, events, benign, chosen


def show(name: str, result: RunResult) -> None:
    """Results: headline numbers, then tabs with details and the download."""
    before, after = result.verification.original, result.verification.improved
    changed = result.improvement.changed
    cols = st.columns(3)
    cols[0].metric("Verdict", result.verdict.value)
    cols[1].metric(
        "Variants evading",
        f"{len(after.evaded) if changed else len(before.evaded)} of {len(before.variants)}",
        delta=f"{len(after.evaded) - len(before.evaded)}" if changed else None,
        delta_color="inverse",
    )
    hits = (
        result.verification.benign_hits_improved
        if changed
        else (result.verification.benign_hits_original)
    )
    cols[2].metric("Benign events matched", f"{len(hits)} of {result.verification.benign_total}")
    files = bundle_files(result)
    report, evasions, rule, download = st.tabs(["Report", "Evasions", "Improved rule", "Download"])
    with report:
        st.markdown(files["report.md"])
    with evasions:
        rows = [
            {
                "event": f.event_index,
                "mutation": f.mutation_name,
                "selection": f.condition,
                "field": f.field,
                "confidence": f.confidence.value,
                "why": f.reason,
                "still visible in": ", ".join(f.remaining_signals),
            }
            for f in before.findings
        ]
        if rows:
            st.dataframe(rows, use_container_width=True)
        else:
            st.success("No variant evaded the rule.")
        for note in result.improvement.unresolved:
            st.warning(f"Not fixed: {note}")
    with rule:
        if changed:
            st.code(result.improvement.yaml_text, language="yaml")
        else:
            st.write(result.improvement.rationale)
    with download:
        st.download_button(
            "Download bundle (.zip)",
            data=bundle_zip(name, files),
            file_name=f"yagtha-{name}.zip",
            mime="application/zip",
        )


def main() -> None:
    st.set_page_config(page_title="YAGTHA", layout="wide")
    st.title("YAGTHA (يقظة)")
    st.caption(
        "Test how robust a Sigma rule is against simple attacker changes, and fix it with proof."
    )
    try:
        given = inputs()
        if given is None:
            return
        name, rule_text, events, benign, chosen = given
        if st.sidebar.button("Run", type="primary"):
            st.session_state["result"] = (name, run_pipeline(rule_text, events, benign, chosen))
    except YagthaError as exc:
        st.error(str(exc))
        return
    if "result" in st.session_state:
        show(*st.session_state["result"])


main()
