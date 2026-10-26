"""Evidence reports distinguish no match, incomplete coverage, and missing details."""

import csv
from datetime import datetime, timezone
import io
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
from urllib.parse import quote, urlsplit

from . import __version__
from .i18n import diagnostic, location_text, text

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


def safe_url(value):
    if not isinstance(value, str):
        return ""
    try:
        parsed = urlsplit(value)
        return value if parsed.scheme in {"https", "http"} and parsed.netloc and not parsed.username and not parsed.password and not re.search(r"[\s<>\x00-\x1f]", value) else ""
    except ValueError:
        return ""


def _severity(record):
    metadata = record.get("database_specific")
    label = str(metadata.get("severity", "")).upper() if isinstance(metadata, dict) else "UNKNOWN"
    label = "MEDIUM" if label == "MODERATE" else label
    return label if label in SEVERITY_RANK else "UNKNOWN"


def _package_matches(affected, package):
    value = affected.get("package", {})
    normalized = lambda s: re.sub(r"[-_.]+", "-", str(s)).lower() if package.ecosystem == "PyPI" else str(s)
    return value.get("ecosystem") == package.ecosystem and normalized(value.get("name")) == normalized(package.name)


def scan(parsed, client, excluded=0):
    excluded_items = list(excluded) if isinstance(excluded, (list, tuple)) else []
    excluded_count = len(excluded_items) if excluded_items else int(excluded or 0)
    queried = client.query(parsed.packages)
    ids = sorted({advisory_id for result in queried.values() for advisory_id in result.ids})
    records, detail_errors = {}, {}
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = {pool.submit(client.advisory, advisory_id): advisory_id for advisory_id in ids[:200]}
        for future in as_completed(futures):
            advisory_id = futures[future]
            try:
                record = future.result()
                if not isinstance(record, dict) or record.get("id") != advisory_id or not isinstance(record.get("affected", []), list):
                    raise ValueError("公告响应结构错误")
                records[advisory_id] = record
            except Exception as error:
                detail_errors[advisory_id] = str(error)[:180] or "详情获取失败"
    detail_errors.update({advisory_id: "超过每次 200 个公告详情上限" for advisory_id in ids[200:]})
    withdrawn = {advisory_id for advisory_id, record in records.items() if record.get("withdrawn")}
    parent = {}

    def find(item):
        parent.setdefault(item, item)
        if parent[item] != item:
            parent[item] = find(parent[item])
        return parent[item]

    for advisory_id in ids:
        if advisory_id in withdrawn:
            continue
        record = records.get(advisory_id, {})
        aliases = record.get("aliases", [])
        aliases = aliases if isinstance(aliases, list) else []
        for alias in [advisory_id] + [a for a in aliases if isinstance(a, str) and a]:
            parent[find(alias)] = find(advisory_id)
    groups = {}
    for identifier in list(parent):
        groups.setdefault(find(identifier), set()).add(identifier)
    canonical = {root: next(iter(sorted(x for x in members if x.startswith("CVE-"))), sorted(members)[0]) for root, members in groups.items()}
    findings, package_rows = [], []
    for package in parsed.packages:
        result = queried[package.key]
        active_ids = [identifier for identifier in result.ids if identifier not in withdrawn]
        roots = sorted({find(identifier) for identifier in active_ids})
        for root in roots:
            source_ids = sorted(identifier for identifier in ids if identifier not in withdrawn and identifier in parent and find(identifier) == root)
            evidence_records = [records[identifier] for identifier in source_ids if identifier in records]
            evidence_records.sort(key=lambda record: (not record["id"].startswith("GHSA-"), record["id"]))
            fixed = set()
            references = set()
            for record in evidence_records:
                for affected in record.get("affected", []):
                    if isinstance(affected, dict) and _package_matches(affected, package):
                        for version_range in affected.get("ranges", []):
                            if isinstance(version_range, dict) and version_range.get("type") in {"SEMVER", "ECOSYSTEM"}:
                                fixed.update(str(event["fixed"]) for event in version_range.get("events", []) if isinstance(event, dict) and event.get("fixed"))
                references.update(url for reference in record.get("references", []) if isinstance(reference, dict) and (url := safe_url(reference.get("url"))))
            severity = max((_severity(record) for record in evidence_records), key=lambda label: SEVERITY_RANK[label], default="UNKNOWN")
            first = evidence_records[0] if evidence_records else {}
            findings.append({
                "dependency": package.key, "ecosystem": package.ecosystem, "package": package.name, "version": package.version,
                "vulnerability": canonical[root], "aliases": sorted(groups[root]), "source_ids": source_ids,
                "severity": severity, "summary": str(first.get("summary") or first.get("details") or "命中公告，详情未取得")[:350],
                "details_excerpt": str(first.get("details", ""))[:8000], "fixed_versions": sorted(fixed),
                "evidence_urls": ["https://osv.dev/vulnerability/" + quote(identifier, safe="") for identifier in source_ids],
                "references": sorted(references), "advisory_modified": str(first.get("modified", "")),
                "details_complete": all(identifier not in detail_errors for identifier in source_ids), "locations": list(package.locations),
            })
        status = "查询失败" if result.error else ("命中公告" if roots else ("仅命中已撤回公告" if result.ids else "未命中"))
        package_rows.append({**package.to_dict(), "key": package.key, "query_status": status, "vulnerability_count": len(roots), "query_error": result.error})
    findings.sort(key=lambda finding: (-SEVERITY_RANK[finding["severity"]], finding["package"], finding["vulnerability"]))
    query_errors = sum(bool(result.error) for result in queried.values())
    return {
        "application": "依赖漏洞核验工作台", "version": __version__, "checked_at": datetime.now(timezone.utc).isoformat(), "manifest_format": parsed.format,
        "mode": getattr(client, "mode", "unknown"), "snapshot_at": getattr(client, "snapshot_at", ""),
        "status": "partial" if parsed.skipped or query_errors or detail_errors or not parsed.packages else "complete",
        "summary": {"queried_dependencies": len(parsed.packages), "affected_dependencies": len({f["dependency"] for f in findings}),
                    "unique_vulnerabilities": len({f["vulnerability"] for f in findings}), "findings": len(findings),
                    "unresolved_entries": len(parsed.skipped), "excluded_dependencies": excluded_count,
                    "query_errors": query_errors, "detail_errors": len(detail_errors), "withdrawn_records": len(withdrawn)},
        "packages": package_rows, "findings": findings, "unresolved": parsed.skipped, "excluded_packages": excluded_items,
        "detail_errors": detail_errors, "withdrawn_ids": sorted(withdrawn),
        "network_requests": getattr(client, "requests", 0), "cached_advisories": getattr(client, "cache_hits", 0),
        "scope": "按 OSV 对精确依赖版本的公开记录匹配；未验证安装状态、可达性、利用条件或升级兼容性。未命中不等于无漏洞。",
        "fix_note": "修复参考是匹配包公告中列出的边界，可能包含多个分支；不是保证兼容的升级建议。",
    }


def _md(value):
    return str(value).replace("\\", "\\\\").replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;").replace("[", "\\[").replace("]", "\\]").replace("\r", " ").replace("\n", " ")


def summary_text(finding, lang="zh"):
    """Localize the generated empty-detail placeholder, never other advisory text."""
    value = finding["summary"]
    return diagnostic(value, lang) if value == "命中公告，详情未取得" and not finding["details_excerpt"] else value


def markdown_report(report, lang="zh"):
    """Render readable text in the requested language without mutating JSON data."""
    t = lambda key, **values: text(key, lang, **values)
    d = lambda value: diagnostic(value, lang)
    summary = report["summary"]
    lines = ["# " + t("report_title"), "", t("report_metadata", time=report["checked_at"], mode=report["mode"], status=report["status"]), "",
             t("report_summary", queried=summary["queried_dependencies"], affected=summary["affected_dependencies"], vulnerabilities=summary["unique_vulnerabilities"]),
             t("report_gaps", unresolved=summary["unresolved_entries"], excluded=summary["excluded_dependencies"], queries=summary["query_errors"], details=summary["detail_errors"]), "",
             t("report_table"), "| --- | --- | --- | --- |"]
    for finding in report["findings"]:
        lines.append("| " + " | ".join(_md(value) for value in [finding["dependency"], finding["severity"], finding["vulnerability"], ", ".join(finding["fixed_versions"]) or t("not_listed")]) + " |")
    for finding in report["findings"]:
        lines.extend(["", "## " + _md(finding["vulnerability"]) + " / " + _md(finding["dependency"]), "", _md(summary_text(finding, lang)), ""])
        lines.extend("- " + t("evidence") + url for url in finding["evidence_urls"])
    if report["unresolved"]:
        lines.extend(["", "## " + t("unresolved_heading"), ""] + ["- " + _md(location_text(item["location"], report["manifest_format"], lang)) + ": " + _md(d(item["reason"])) for item in report["unresolved"]])
    errors = ["- " + _md(p["key"]) + ": " + _md(d(p["query_error"])) for p in report["packages"] if p["query_error"]]
    errors += ["- " + _md(identifier) + ": " + _md(d(error)) for identifier, error in report["detail_errors"].items()]
    if errors:
        lines.extend(["", "## " + t("errors_heading"), ""] + errors)
    if report["excluded_packages"]:
        lines.extend(["", "## " + t("excluded_heading"), ""] + ["- " + _md(item) for item in report["excluded_packages"]])
    lines.extend(["", d(report["scope"]), "", d(report["fix_note"]), ""])
    return "\n".join(lines)


def csv_report(report, lang="zh"):
    """Render localized columns and notes while keeping source identifiers intact."""
    t = lambda key: text(key, lang)
    d = lambda value: diagnostic(value, lang)
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\n")
    def write_row(values):
        writer.writerow(["'" + str(value) if str(value).startswith(("\t", "\r", "\n")) or re.match(r"^\s*[=+@-]", str(value)) else value for value in values])

    write_row([t("csv_completeness"), t("csv_type"), t("package_dependency"), t("vulnerability"), t("severity"), t("fixed"), t("csv_url"), t("csv_note")])
    for finding in report["findings"]:
        values = [report["status"], t("csv_match"), finding["dependency"], finding["vulnerability"], finding["severity"], ", ".join(finding["fixed_versions"]), " ".join(finding["evidence_urls"]), t("csv_details_complete" if finding["details_complete"] else "csv_details_missing")]
        write_row(values)
    for package in report["packages"]:
        if package["query_error"] or not package["vulnerability_count"]:
            write_row([report["status"], t("csv_query_status"), package["key"], "", "", "", "", d(package["query_error"] or package["query_status"])])
    for item in report["unresolved"]:
        write_row([report["status"], t("csv_unresolved"), location_text(item["location"], report["manifest_format"], lang), "", "", "", "", d(item["reason"])])
    return buffer.getvalue().encode("utf-8-sig")
