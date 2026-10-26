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
from dependency_workbench.manifests import parse_manifest
from dependency_workbench.osv import OSVClient, SnapshotClient
from dependency_workbench.report import csv_report, markdown_report, scan

ROOT = Path(__file__).resolve().parent
st.set_page_config(page_title="依赖证据台 · Dependency Desk", page_icon="◉", layout="wide")
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
    st.markdown('<div class="brand">◉ 依赖证据台</div>', unsafe_allow_html=True)
    st.caption(f"DEPENDENCY DESK / {__version__}")
    st.divider()
    source = st.radio("01　导入清单", ["Python 示例", "npm 示例", "上传清单", "粘贴清单"], key="source")
    data = None
    filename = ""
    if source == "Python 示例":
        filename = "requirements-demo.txt"
        data = (ROOT / "samples" / filename).read_bytes()
    elif source == "npm 示例":
        filename = "package-lock.json"
        data = (ROOT / "samples" / filename).read_bytes()
    elif source == "上传清单":
        upload = st.file_uploader("requirements.txt / pip list JSON / package-lock.json", type=["txt", "json"], max_upload_size=5, key="upload")
        if upload:
            data, filename = upload.getvalue(), upload.name
    else:
        text = st.text_area("清单内容", value="requests==2.19.1\nidna==3.7", height=140, key="paste")
        data = text.encode()
        filename = "pasted.json" if text.lstrip().startswith(("{", "[")) else "requirements.txt"
    st.caption("不安装或执行依赖。最多 5 MB、2,000 个唯一依赖版本。")
    st.markdown("**02　检查范围**")
    production = st.checkbox("排除 npm 开发依赖", value=False, key="production")
    excluded_names = st.text_input("排除包名（逗号分隔）", placeholder="例如 internal-library", key="exclude")
    st.caption("可先排除内部包；Python 文本清单不包含 dev 标签。")
    st.markdown("**03　检查方式**")
    mode = st.radio("数据来源", ["联网检查", "离线演示快照"], index=1 if source.endswith("示例") else 0, key=f"mode_{source}")
    refresh = st.checkbox("重新获取公告，不用缓存", key="refresh", disabled=mode != "联网检查")
    if mode == "联网检查":
        st.caption("点击后仅向 api.osv.dev 发送所选包名、生态和版本，不上传清单原文。")
    else:
        st.caption("快照来自真实 OSV 公告，仅覆盖内置示例版本，不代表当前实时结果。")
    run_clicked = st.button("开始联网检查" if mode == "联网检查" else "运行离线演示", type="primary", width="stretch", key="scan")
    st.divider()
    st.caption("公开资料 · 不需要 API 密钥\n\n已知漏洞匹配 ≠ 已验证可利用")

st.markdown("""
<div class="hero"><div class="overline">DEPENDENCY EVIDENCE / FROM INVENTORY TO ACTION</div>
<h1>每一项依赖，都有据可查。</h1>
<p>从清单核对已知漏洞，保留版本、公告与修复参考。把未检查的部分，也放进报告。</p></div>
""", unsafe_allow_html=True)

if data is None:
    st.info("上传或粘贴依赖清单。准备体验时，可先使用左侧的 Python / npm 示例。")
    st.stop()
try:
    parsed = parse_manifest(data, filename)
except ValueError as error:
    st.error(str(error))
    st.stop()

excluded_set = {name.casefold() for name in re.split(r"[,，\s]+", excluded_names) if name}
excluded = [p.key for p in parsed.packages if p.name.casefold() in excluded_set or (production and p.dev)]
selected = replace(parsed, packages=[p for p in parsed.packages if p.key not in excluded])
fingerprint = hashlib.sha256(data + json.dumps([source, mode, sorted(excluded), refresh], ensure_ascii=False).encode()).hexdigest()
if st.session_state.get("active_fingerprint") != fingerprint:
    st.session_state.pop("report", None)
    st.session_state.active_fingerprint = fingerprint

st.caption(f"当前文件：{filename}　·　格式：{parsed.format}　·　唯一依赖版本 {len(parsed.packages)} 个，选中 {len(selected.packages)} 个")
with st.expander("检查范围与未解析项", expanded="report" not in st.session_state):
    if selected.packages:
        st.dataframe(pd.DataFrame([{"生态": p.ecosystem, "包名": p.name, "版本": p.version, "开发依赖": p.dev, "出现位置": "; ".join(p.locations)} for p in selected.packages]), hide_index=True, width="stretch", height=180)
    if parsed.skipped:
        st.warning(f"有 {len(parsed.skipped)} 条声明无法确定精确版本，本次不会检查这些声明。")
        st.dataframe(pd.DataFrame(parsed.skipped).rename(columns={"location": "位置", "reason": "原因"}), hide_index=True, width="stretch")
    if excluded:
        st.caption("本次排除：" + ", ".join(excluded))

if run_clicked:
    if not selected.packages:
        st.error("当前没有可检查的精确依赖版本，请先调整清单或排除规则。")
    else:
        with st.spinner("正在核验依赖版本并读取公告证据……"):
            client = SnapshotClient(ROOT / "samples" / "osv-snapshot.json") if mode == "离线演示快照" else OSVClient(cache_dir=ROOT / ".cache" / "osv", cache_ttl=0 if refresh else 86400)
            report = scan(selected, client, excluded)
            report["manifest_sha256"] = hashlib.sha256(data).hexdigest()
            st.session_state.report = report

if "report" not in st.session_state:
    st.info("确认范围后点击左侧检查按钮。不会解析的条目会单独列出；不会自行读取嵌套文件。")
    st.stop()

report = st.session_state.report
summary = report["summary"]
if report["mode"] == "snapshot":
    captured = datetime.fromisoformat(report["snapshot_at"].replace("Z", "+00:00")).astimezone(timezone(timedelta(hours=8)))
    st.info(f"离线真实公告快照 · 获取于 {captured:%Y-%m-%d %H:%M}（北京时间）。检查你的项目时请切换联网模式。")
else:
    checked = datetime.fromisoformat(report["checked_at"]).astimezone(timezone(timedelta(hours=8)))
    st.caption(f"OSV 实时版本匹配 · {checked:%Y-%m-%d %H:%M}（北京时间） · 复用公告缓存 {report['cached_advisories']} 条")
if report["status"] == "partial":
    st.warning(f"结果不完整：未解析 {summary['unresolved_entries']} 项、查询失败 {summary['query_errors']} 项、详情未齐 {summary['detail_errors']} 项。具体原因已写入 JSON / Markdown / CSV。")

columns = st.columns(4, gap="small")
for column, label, value in zip(columns, ["检查依赖版本", "受影响依赖版本", "去重漏洞", "未解析声明"], [summary["queried_dependencies"], summary["affected_dependencies"], summary["unique_vulnerabilities"], summary["unresolved_entries"]]):
    column.metric(label, str(value))

st.subheader("漏洞与修复参考")
search_col, severity_col = st.columns([2, 1])
search = search_col.text_input("按 CVE、包名或关键词过滤", placeholder="例如 CVE-2021、minimist、redirect", key="search")
levels = severity_col.multiselect("公告风险级别", ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"], default=["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"], key="levels")
findings = [f for f in report["findings"] if f["severity"] in levels and search.casefold() in " ".join([f["dependency"], f["vulnerability"], " ".join(f["aliases"]), f["summary"], f["details_excerpt"]]).casefold()]
if findings:
    st.dataframe(pd.DataFrame([{"级别": f["severity"], "依赖版本": f["dependency"], "漏洞": f["vulnerability"], "公告修复边界": ", ".join(f["fixed_versions"]) or "未列出", "摘要": f["summary"]} for f in findings]), hide_index=True, width="stretch", height=min(330, 40 + 35 * len(findings)))
    selected_index = st.selectbox("打开一条证据", list(range(len(findings))), format_func=lambda index: f"{findings[index]['vulnerability']} · {findings[index]['dependency']}", key="evidence")
    evidence = findings[selected_index]
    left, right = st.columns([2.1, 1], gap="large")
    with left:
        st.markdown("**公告原文摘录**")
        st.text_area("证据内容", value=evidence["details_excerpt"] or evidence["summary"], height=180, disabled=True, key=f"excerpt_{evidence['vulnerability']}_{evidence['dependency']}")
    with right:
        st.markdown("**修复参考与来源**")
        st.write(", ".join(evidence["fixed_versions"]) or "公告未列出修复边界")
        st.caption("可能包含多个维护分支，请结合当前分支与兼容性选择；不会自动改写依赖。")
        for index, url in enumerate(evidence["evidence_urls"], 1):
            st.link_button(f"查看 OSV 原始公告 {index}", url, width="stretch")
        st.caption("公告更新时间：" + evidence["advisory_modified"])
        if not evidence["details_complete"]:
            st.warning("命中已保留，但部分详情未取得。")
elif report["findings"]:
    st.info("当前筛选没有匹配的漏洞条目，可清空关键词或调整级别。")
else:
    st.info("本次未返回有效漏洞匹配；请同时查看范围、查询状态和未解析项。未命中不等于无漏洞。")

with st.expander("逐包查询状态 / 未完成详情 / 已撤回公告"):
    st.dataframe(pd.DataFrame([{"依赖": p["key"], "状态": p["query_status"], "去重命中": p["vulnerability_count"], "错误": p["query_error"]} for p in report["packages"]]), hide_index=True, width="stretch")
    if report["detail_errors"]:
        st.json(report["detail_errors"])
    if report["withdrawn_ids"]:
        st.write("已撤回：" + ", ".join(report["withdrawn_ids"]))

st.subheader("带走这份证据")
download_cols = st.columns(3)
download_cols[0].download_button("↓ Markdown 报告", markdown_report(report).encode("utf-8"), file_name="dependency-report.md", mime="text/markdown", width="stretch", key="download_md")
download_cols[1].download_button("↓ JSON 完整记录", json.dumps(report, ensure_ascii=False, indent=2).encode("utf-8"), file_name="dependency-report.json", mime="application/json", width="stretch", key="download_json")
download_cols[2].download_button("↓ CSV 结果清单", csv_report(report), file_name="dependency-report.csv", mime="text/csv", width="stretch", key="download_csv")
st.caption("报告保留未解析、排除范围与查询异常。缓存只保存公开公告，不保存上传清单。")
st.markdown('<div class="foot">DEPENDENCY EVIDENCE WORKBENCH / v0.1.0<br>公开漏洞记录核验，不验证利用条件或升级兼容性。代码 Apache-2.0；示例公告数据保留来源与 CC BY 4.0 署名。</div>', unsafe_allow_html=True)
