"""A usable evidence desk: preview inventory, query explicitly, inspect and export."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re

import pandas as pd
import streamlit as st

from dependency_workbench import __version__
from dependency_workbench.i18n import diagnostic, location_text, text
from dependency_workbench.manifests import parse_manifest
from dependency_workbench.osv import OSVClient, SnapshotClient
from dependency_workbench.report import csv_report, markdown_report, scan, summary_text

ROOT = Path(__file__).resolve().parent


def remember_choice(state_key, widget_key):
    """Retain a canonical choice independently of locale-specific widgets."""
    st.session_state[state_key] = st.session_state[widget_key]


lang = "en" if st.session_state.get("ui_language") == "English" else "zh"
t = lambda key, **values: text(key, lang, **values)
d = lambda value: diagnostic(value, lang)
st.set_page_config(page_title=t("page_title"), page_icon="◉", layout="wide")
st.markdown("""
<style>
.stApp{background:#f7f5f0;color:#273344;}
.block-container{max-width:1320px;padding-top:2.7rem;padding-bottom:3rem;}
[data-testid="stSidebar"]{background:#e9edf0;border-right:1px solid #d1d8de;}
h1,h2,h3{color:#273344;letter-spacing:-.025em;}
.hero{padding-bottom:24px;margin-bottom:22px;border-bottom:1px solid #d6d8d5;}
.hero h1{font:600 42px Georgia,'Noto Serif CJK SC','SimSun',serif;margin:14px 0;line-height:1.3;}
.hero p{font-size:15px;color:#6e7680;line-height:1.8;margin-bottom:0;}
.overline{font:11px 'Cascadia Code',Consolas,monospace;letter-spacing:.17em;color:#a46431;}
.brand{font:600 23px Georgia,'SimSun',serif;letter-spacing:-.02em;color:#33485c;}
[data-testid="stMetric"]{padding:17px 20px;border:1px solid #d9dedf;border-top:3px solid #b8814d;background:#fffdf9;border-radius:4px;}
[data-testid="stMetricValue"]{font-family:Georgia,serif;color:#33485c;}
.foot{font-size:11px;color:#77818a;border-top:1px solid #d6d8d5;padding-top:18px;margin-top:32px;line-height:1.8;}
.stButton button,.stDownloadButton button{border-radius:4px;min-height:41px;}
</style>
""", unsafe_allow_html=True)

with st.sidebar:
    st.selectbox(t("language"), ["简体中文", "English"], key="ui_language")
    st.markdown(f'<div class="brand">◉ {t("brand")}</div>', unsafe_allow_html=True)
    st.caption(f"DEPENDENCY DESK / {__version__}")
    st.divider()
    # Locale-specific widget IDs refresh frontend option strings. Canonical values
    # preserve choices and scan fingerprints independently of display widgets.
    source_keys = {"Python 示例": "python_example", "npm 示例": "npm_example", "上传清单": "upload", "粘贴清单": "paste"}
    source_widget = "source" if lang == "zh" else "source_en"
    if "selected_source" not in st.session_state:
        st.session_state.selected_source = st.session_state.get("source", "Python 示例")
    st.session_state[source_widget] = st.session_state.selected_source
    source = st.radio(t("source"), list(source_keys), format_func=lambda value: t(source_keys[value]), key=source_widget, on_change=remember_choice, args=("selected_source", source_widget))
    data = None
    filename = ""
    if source == "Python 示例":
        filename = "requirements-demo.txt"
        data = (ROOT / "samples" / filename).read_bytes()
    elif source == "npm 示例":
        filename = "package-lock.json"
        data = (ROOT / "samples" / filename).read_bytes()
    elif source == "上传清单":
        upload = st.file_uploader(t("upload_label"), type=["txt", "json"], max_upload_size=5, key="upload")
        if upload:
            data, filename = upload.getvalue(), upload.name
    else:
        pasted = st.text_area(t("content"), value="requests==2.19.1\nidna==3.7", height=140, key="paste")
        data = pasted.encode()
        filename = "pasted.json" if pasted.lstrip().startswith(("{", "[")) else "requirements.txt"
    st.caption(t("input_limit"))
    st.markdown("**" + t("scope_heading") + "**")
    production = st.checkbox(t("production"), value=False, key="production")
    excluded_names = st.text_input(t("exclude"), placeholder=t("exclude_placeholder"), key="exclude")
    st.caption(t("scope_hint"))
    st.markdown("**" + t("mode_heading") + "**")
    mode_state = f"selected_mode_{source}"
    mode_widget = f"mode_{source}" + ("_en" if lang == "en" else "")
    if mode_state not in st.session_state:
        st.session_state[mode_state] = st.session_state.get(f"mode_{source}", "离线演示快照" if source.endswith("示例") else "联网检查")
    st.session_state[mode_widget] = st.session_state[mode_state]
    mode = st.radio(t("data_source"), ["联网检查", "离线演示快照"], format_func=lambda value: t("live" if value == "联网检查" else "snapshot"), key=mode_widget, on_change=remember_choice, args=(mode_state, mode_widget))
    refresh = st.checkbox(t("refresh"), key="refresh", disabled=mode != "联网检查")
    if mode == "联网检查":
        st.caption(t("live_hint"))
    else:
        st.caption(t("snapshot_hint"))
    run_clicked = st.button(t("run_live" if mode == "联网检查" else "run_snapshot"), type="primary", width="stretch", key="scan")
    st.divider()
    st.caption(t("sidebar_note"))

st.markdown(f"""
<div class="hero"><div class="overline">DEPENDENCY EVIDENCE / FROM INVENTORY TO ACTION</div>
<h1>{t("hero_title")}</h1>
<p>{t("hero_body")}</p></div>
""", unsafe_allow_html=True)

if data is None:
    st.info(t("empty_input"))
    st.stop()
try:
    parsed = parse_manifest(data, filename)
except ValueError as error:
    st.error(t("parse_error", error=d(error)))
    st.stop()

excluded_set = {name.casefold() for name in re.split(r"[,，\s]+", excluded_names) if name}
excluded = [p.key for p in parsed.packages if p.name.casefold() in excluded_set or (production and p.dev)]
selected = replace(parsed, packages=[p for p in parsed.packages if p.key not in excluded])
fingerprint = hashlib.sha256(data + json.dumps([source, mode, sorted(excluded), refresh], ensure_ascii=False).encode()).hexdigest()
if st.session_state.get("active_fingerprint") != fingerprint:
    st.session_state.pop("report", None)
    st.session_state.active_fingerprint = fingerprint

st.caption(t("inventory_caption", filename=filename, format=parsed.format, total=len(parsed.packages), selected=len(selected.packages)))
with st.expander(t("scope_expander"), expanded="report" not in st.session_state):
    if selected.packages:
        st.dataframe(pd.DataFrame([{t("ecosystem"): p.ecosystem, t("package"): p.name, t("version"): p.version, t("dev"): p.dev, t("locations"): "; ".join(location_text(location, parsed.format, lang) for location in p.locations)} for p in selected.packages]), hide_index=True, width="stretch", height=180)
    if parsed.skipped:
        st.warning(t("unresolved_warning", count=len(parsed.skipped)))
        st.dataframe(pd.DataFrame([{t("location"): location_text(item["location"], parsed.format, lang), t("reason"): d(item["reason"])} for item in parsed.skipped]), hide_index=True, width="stretch")
    if excluded:
        st.caption(t("excluded_caption") + ", ".join(excluded))

if run_clicked:
    if not selected.packages:
        st.error(t("no_packages"))
    else:
        with st.spinner(t("spinner")):
            client = SnapshotClient(ROOT / "samples" / "osv-snapshot.json") if mode == "离线演示快照" else OSVClient(cache_dir=ROOT / ".cache" / "osv", cache_ttl=0 if refresh else 86400)
            report = scan(selected, client, excluded)
            report["manifest_sha256"] = hashlib.sha256(data).hexdigest()
            st.session_state.report = report

if "report" not in st.session_state:
    st.info(t("before_scan"))
    st.stop()

report = st.session_state.report
summary = report["summary"]
if report["mode"] == "snapshot":
    captured = datetime.fromisoformat(report["snapshot_at"].replace("Z", "+00:00")).astimezone(timezone(timedelta(hours=8)))
    st.info(t("snapshot_at", time=captured.strftime("%Y-%m-%d %H:%M")))
else:
    checked = datetime.fromisoformat(report["checked_at"]).astimezone(timezone(timedelta(hours=8)))
    st.caption(t("live_at", time=checked.strftime("%Y-%m-%d %H:%M"), count=report["cached_advisories"]))
if report["status"] == "partial":
    st.warning(t("partial", unresolved=summary["unresolved_entries"], queries=summary["query_errors"], details=summary["detail_errors"]))

columns = st.columns(4, gap="small")
for column, label, value in zip(columns, ["queried_metric", "affected_metric", "vulnerabilities_metric", "unresolved_metric"], [summary["queried_dependencies"], summary["affected_dependencies"], summary["unique_vulnerabilities"], summary["unresolved_entries"]]):
    column.metric(t(label), str(value))

st.subheader(t("findings_heading"))
search_col, severity_col = st.columns([2, 1])
search = search_col.text_input(t("search"), placeholder=t("search_placeholder"), key="search")
levels = severity_col.multiselect(t("severity_filter"), ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"], default=["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"], key="levels")
findings = [f for f in report["findings"] if f["severity"] in levels and search.casefold() in " ".join([f["dependency"], f["vulnerability"], " ".join(f["aliases"]), f["summary"], f["details_excerpt"]]).casefold()]
if findings:
    st.dataframe(pd.DataFrame([{t("severity"): f["severity"], t("dependency"): f["dependency"], t("vulnerability"): f["vulnerability"], t("fixed"): ", ".join(f["fixed_versions"]) or t("not_listed"), t("summary"): summary_text(f, lang)} for f in findings]), hide_index=True, width="stretch", height=min(330, 40 + 35 * len(findings)))
    selected_index = st.selectbox(t("open_evidence"), list(range(len(findings))), format_func=lambda index: f"{findings[index]['vulnerability']} · {findings[index]['dependency']}", key="evidence")
    evidence = findings[selected_index]
    left, right = st.columns([2.1, 1], gap="large")
    with left:
        st.markdown("**" + t("excerpt_heading") + "**")
        st.text_area(t("evidence_content"), value=evidence["details_excerpt"] or summary_text(evidence, lang), height=180, disabled=True, key=f"excerpt_{evidence['vulnerability']}_{evidence['dependency']}")
    with right:
        st.markdown("**" + t("fix_heading") + "**")
        st.write(", ".join(evidence["fixed_versions"]) or t("no_fix"))
        st.caption(t("fix_hint"))
        for index, url in enumerate(evidence["evidence_urls"], 1):
            st.link_button(t("original_link", index=index), url, width="stretch")
        st.caption(t("modified") + evidence["advisory_modified"])
        if not evidence["details_complete"]:
            st.warning(t("missing_details"))
elif report["findings"]:
    st.info(t("no_filter_results"))
else:
    st.info(t("no_findings"))

with st.expander(t("status_expander")):
    st.dataframe(pd.DataFrame([{t("package_dependency"): p["key"], t("status"): d(p["query_status"]), t("match_count"): p["vulnerability_count"], t("error"): d(p["query_error"])} for p in report["packages"]]), hide_index=True, width="stretch")
    if report["detail_errors"]:
        st.dataframe(pd.DataFrame([{t("advisory"): identifier, t("error"): d(error)} for identifier, error in report["detail_errors"].items()]), hide_index=True, width="stretch")
    if report["withdrawn_ids"]:
        st.write(t("withdrawn") + ", ".join(report["withdrawn_ids"]))

st.subheader(t("download_heading"))
download_cols = st.columns(3)
download_cols[0].download_button(t("download_md"), markdown_report(report, lang=lang).encode("utf-8"), file_name="dependency-report.md", mime="text/markdown", width="stretch", key="download_md")
download_cols[1].download_button(t("download_json"), json.dumps(report, ensure_ascii=False, indent=2).encode("utf-8"), file_name="dependency-report.json", mime="application/json", width="stretch", key="download_json")
download_cols[2].download_button(t("download_csv"), csv_report(report, lang=lang), file_name="dependency-report.csv", mime="text/csv", width="stretch", key="download_csv")
st.caption(t("download_hint"))
st.markdown(f'<div class="foot">DEPENDENCY EVIDENCE WORKBENCH / v{__version__}<br>{t("footer")}</div>', unsafe_allow_html=True)
