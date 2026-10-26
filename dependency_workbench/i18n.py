"""Explicit local translations for application text, never for source evidence.

Unknown locale codes fall back to Chinese. Unknown diagnostic details pass through
unchanged (for example operating-system errors and third-party parser messages).
The stored JSON protocol is independent of the display language.
"""

import re

_PAIRS = {
    "brand": ("依赖证据台", "Dependency Desk"),
    "page_title": ("依赖证据台 · Dependency Desk", "Dependency Desk · Evidence Workbench"),
    "language": ("界面语言", "Language"),
    "source": ("01　导入清单", "01  Import inventory"),
    "python_example": ("Python 示例", "Python example"),
    "npm_example": ("npm 示例", "npm example"),
    "upload": ("上传清单", "Upload inventory"),
    "paste": ("粘贴清单", "Paste inventory"),
    "upload_label": ("requirements.txt / pip list JSON / package-lock.json", "requirements.txt / pip list JSON / package-lock.json"),
    "content": ("清单内容", "Inventory content"),
    "input_limit": ("不安装或执行依赖。最多 5 MB、2,000 个唯一依赖版本。", "Dependencies are never installed or executed. Limit: 5 MB and 2,000 unique dependency versions."),
    "scope_heading": ("02　检查范围", "02  Check scope"),
    "production": ("排除 npm 开发依赖", "Exclude npm development dependencies"),
    "exclude": ("排除包名（逗号分隔）", "Exclude package names (comma separated)"),
    "exclude_placeholder": ("例如 internal-library", "e.g. internal-library"),
    "scope_hint": ("可先排除内部包；Python 文本清单不包含 dev 标签。", "Exclude internal packages before checking. Python text inventories have no dev flag."),
    "mode_heading": ("03　检查方式", "03  Check mode"),
    "data_source": ("数据来源", "Data source"),
    "live": ("联网检查", "Live OSV check"),
    "snapshot": ("离线演示快照", "Offline demo snapshot"),
    "refresh": ("重新获取公告，不用缓存", "Fetch advisories again, ignoring cache"),
    "live_hint": ("点击后仅向 api.osv.dev 发送所选包名、生态和版本，不上传清单原文。", "After you click, only selected package names, ecosystems and versions are sent to api.osv.dev. The inventory file is not uploaded."),
    "snapshot_hint": ("快照来自真实 OSV 公告，仅覆盖内置示例版本，不代表当前实时结果。", "The snapshot contains real OSV advisories for built-in example versions only. It is not a current live result."),
    "run_live": ("开始联网检查", "Start live check"),
    "run_snapshot": ("运行离线演示", "Run offline demo"),
    "sidebar_note": ("公开资料 · 不需要 API 密钥\n\n已知漏洞匹配 ≠ 已验证可利用", "Public data · No API key needed\n\nKnown vulnerability match ≠ verified exploitability"),
    "hero_title": ("每一项依赖，都有据可查。", "Evidence for every dependency."),
    "hero_body": ("从清单核对已知漏洞，保留版本、公告与修复参考。把未检查的部分，也放进报告。", "Check inventories against known vulnerabilities. Keep versions, advisories and fix references, and record gaps in the report."),
    "empty_input": ("上传或粘贴依赖清单。准备体验时，可先使用左侧的 Python / npm 示例。", "Upload or paste an inventory, or start with a Python / npm example in the sidebar."),
    "parse_error": ("清单读取失败：{error}", "Could not read inventory: {error}"),
    "inventory_caption": ("当前文件：{filename}　·　格式：{format}　·　唯一依赖版本 {total} 个，选中 {selected} 个", "File: {filename} · Format: {format} · {total} unique dependency versions, {selected} selected"),
    "scope_expander": ("检查范围与未解析项", "Check scope and unresolved entries"),
    "ecosystem": ("生态", "Ecosystem"),
    "package": ("包名", "Package"),
    "version": ("版本", "Version"),
    "dev": ("开发依赖", "Development dependency"),
    "locations": ("出现位置", "Locations"),
    "location": ("位置", "Location"),
    "reason": ("原因", "Reason"),
    "unresolved_warning": ("有 {count} 条声明无法确定精确版本，本次不会检查这些声明。", "An exact version could not be determined for {count} entries; they will not be checked."),
    "excluded_caption": ("本次排除：", "Excluded: "),
    "no_packages": ("当前没有可检查的精确依赖版本，请先调整清单或排除规则。", "No exact dependency versions are available to check. Adjust the inventory or exclusion rules."),
    "spinner": ("正在核验依赖版本并读取公告证据……", "Checking dependency versions and reading advisory evidence…"),
    "before_scan": ("确认范围后点击左侧检查按钮。不会解析的条目会单独列出；不会自行读取嵌套文件。", "Confirm the scope, then click the check button. Unresolved entries are listed separately; nested files are not read automatically."),
    "snapshot_at": ("离线真实公告快照 · 获取于 {time}（北京时间）。检查你的项目时请切换联网模式。", "Offline snapshot of real advisories · Captured {time} (UTC+08:00). Use live mode to check your project."),
    "live_at": ("OSV 实时版本匹配 · {time}（北京时间） · 复用公告缓存 {count} 条", "Live OSV version matching · {time} (UTC+08:00) · {count} cached advisories reused"),
    "partial": ("结果不完整：未解析 {unresolved} 项、查询失败 {queries} 项、详情未齐 {details} 项。具体原因已写入 JSON / Markdown / CSV。", "Incomplete result: {unresolved} unresolved entries, {queries} failed queries and {details} missing advisory details. Reasons are included in JSON / Markdown / CSV."),
    "queried_metric": ("检查依赖版本", "Versions checked"),
    "affected_metric": ("受影响依赖版本", "Affected versions"),
    "vulnerabilities_metric": ("去重漏洞", "Unique vulnerabilities"),
    "unresolved_metric": ("未解析声明", "Unresolved entries"),
    "findings_heading": ("漏洞与修复参考", "Vulnerabilities and fix references"),
    "search": ("按 CVE、包名或关键词过滤", "Filter by CVE, package name or keyword"),
    "search_placeholder": ("例如 CVE-2021、minimist、redirect", "e.g. CVE-2021, minimist, redirect"),
    "severity_filter": ("公告风险级别", "Advisory severity"),
    "severity": ("级别", "Severity"),
    "dependency": ("依赖版本", "Dependency version"),
    "vulnerability": ("漏洞", "Vulnerability"),
    "fixed": ("公告修复边界", "Advisory fixed versions"),
    "not_listed": ("未列出", "Not listed"),
    "summary": ("摘要", "Summary"),
    "open_evidence": ("打开一条证据", "Open an evidence record"),
    "excerpt_heading": ("公告原文摘录", "Original advisory excerpt"),
    "evidence_content": ("证据内容", "Evidence content"),
    "fix_heading": ("修复参考与来源", "Fix references and sources"),
    "no_fix": ("公告未列出修复边界", "No fixed versions listed in the advisory"),
    "fix_hint": ("可能包含多个维护分支，请结合当前分支与兼容性选择；不会自动改写依赖。", "Several maintenance branches may be listed. Check your branch and compatibility before upgrading; dependencies are never rewritten automatically."),
    "original_link": ("查看 OSV 原始公告 {index}", "View original OSV advisory {index}"),
    "modified": ("公告更新时间：", "Advisory modified: "),
    "missing_details": ("命中已保留，但部分详情未取得。", "The match is retained, but some advisory details could not be retrieved."),
    "no_filter_results": ("当前筛选没有匹配的漏洞条目，可清空关键词或调整级别。", "No findings match the current filters. Clear the keyword or adjust the severity filter."),
    "no_findings": ("本次未返回有效漏洞匹配；请同时查看范围、查询状态和未解析项。未命中不等于无漏洞。", "No active vulnerability matches were returned. Review scope, query status and unresolved entries too. No match does not establish that a package is vulnerability-free."),
    "status_expander": ("逐包查询状态 / 未完成详情 / 已撤回公告", "Per-package query status / missing details / withdrawn advisories"),
    "package_dependency": ("依赖", "Dependency"),
    "status": ("状态", "Status"),
    "match_count": ("去重命中", "Unique matches"),
    "error": ("错误", "Error"),
    "advisory": ("公告", "Advisory"),
    "withdrawn": ("已撤回：", "Withdrawn: "),
    "download_heading": ("带走这份证据", "Export this evidence"),
    "download_md": ("↓ Markdown 报告", "↓ Markdown report"),
    "download_json": ("↓ JSON 完整记录", "↓ Full JSON record"),
    "download_csv": ("↓ CSV 结果清单", "↓ CSV results"),
    "download_hint": ("报告保留未解析、排除范围与查询异常。缓存只保存公开公告，不保存上传清单。", "Reports retain unresolved entries, exclusions and query errors. Only public advisories are cached; uploaded inventories are not cached."),
    "footer": ("公开漏洞记录核验，不验证利用条件或升级兼容性。代码 Apache-2.0；示例公告数据保留来源与 CC BY 4.0 署名。", "Checks public vulnerability records; does not verify exploitability or upgrade compatibility. Code: Apache-2.0. Sample advisory data retains source attribution under CC BY 4.0."),
    "report_title": ("依赖漏洞核验报告", "Dependency vulnerability evidence report"),
    "report_metadata": ("检查时间：{time}。模式：{mode}。完整性：{status}。", "Checked: {time}. Mode: {mode}. Completeness: {status}."),
    "report_summary": ("检查 {queried} 个依赖版本；命中 {affected} 个依赖版本、{vulnerabilities} 组去重漏洞。", "Checked {queried} dependency versions; {affected} affected dependency versions and {vulnerabilities} unique vulnerabilities."),
    "report_gaps": ("未解析 {unresolved} 项；排除 {excluded} 项；查询失败 {queries} 项；详情失败 {details} 项。", "Unresolved: {unresolved}; excluded: {excluded}; query failures: {queries}; detail failures: {details}."),
    "report_table": ("| 依赖 | 级别 | 漏洞 | 公告修复边界 |", "| Dependency | Severity | Vulnerability | Advisory fixed versions |"),
    "evidence": ("证据：", "Evidence: "),
    "unresolved_heading": ("未解析项", "Unresolved entries"),
    "errors_heading": ("查询与详情异常", "Query and advisory-detail errors"),
    "excluded_heading": ("用户排除范围", "User exclusions"),
    "csv_completeness": ("报告完整性", "Report completeness"),
    "csv_type": ("记录类型", "Record type"),
    "csv_url": ("证据URL", "Evidence URL"),
    "csv_note": ("说明", "Note"),
    "csv_match": ("命中", "Match"),
    "csv_details_complete": ("详情完整", "Details complete"),
    "csv_details_missing": ("详情缺失，请复核", "Details missing; review required"),
    "csv_query_status": ("查询状态", "Query status"),
    "csv_unresolved": ("未解析", "Unresolved"),
    "cli_description": ("检查 requirements 精确版本、pip list JSON 或 npm lock v2/v3；不安装依赖。", "Check pinned requirements, pip list JSON or npm lock v2/v3; dependencies are never installed."),
    "cli_manifest": ("依赖清单路径", "Path to a dependency inventory"),
    "cli_demo": ("仅使用内置真实公告快照，不联网", "Use the built-in snapshot of real advisories without network access"),
    "cli_format": ("报告格式；JSON 字段与值不随语言切换", "Report format; JSON fields and values do not change with language"),
    "cli_output": ("写入新文件；默认输出到终端", "Write a new file; default: standard output"),
    "cli_production": ("排除 npm 标记 dev 的依赖；Python 清单无此标签", "Exclude npm dependencies marked dev; Python inventories have no such flag"),
    "cli_exclude": ("排除包名，可重复", "Exclude a package name; may be repeated"),
    "cli_refresh": ("忽略公告缓存，重新获取", "Ignore the advisory cache and fetch again"),
    "cli_lang": ("帮助、错误和可读报告语言（默认：zh）", "Language for help, errors and readable reports (default: zh)"),
    "cli_help": ("显示帮助信息并退出", "Show this help message and exit"),
    "cli_missing": ("请给出依赖清单路径，或使用 --demo", "Provide a manifest path, or use --demo"),
    "cli_exists": ("输出文件已存在，请换一个文件名以保留已有报告。", "Output file already exists. Choose another filename to preserve the existing report."),
    "cli_written": ("报告已写入：{path}", "Report written: {path}"),
    "cli_failed": ("检查未完成：{error}", "Check incomplete: {error}"),
    "cli_parser_error": ("错误：{message}", "error: {message}"),
}

MESSAGES = {locale: {key: pair[index] for key, pair in _PAIRS.items()} for index, locale in enumerate(("zh", "en"))}


def text(key, lang="zh", **values):
    """Render an owned message; unsupported locales deterministically use zh."""
    return MESSAGES.get(lang, MESSAGES["zh"])[key].format(**values)


# Exact application diagnostics. Do not translate arbitrary advisory/source text.
_DIAGNOSTICS = {
    "清单为空或超过 5 MB。": "The inventory is empty or exceeds 5 MB.",
    "请将清单保存为 UTF-8 编码。": "Save the inventory using UTF-8 encoding.",
    "包名格式无法识别": "Unrecognized package name format",
    "需要公开发行的精确版本，不支持通配或本地构建版本": "An exact public release version is required; wildcards and local builds are unsupported",
    "JSON 清单无法读取，请检查格式。": "Cannot read the JSON inventory; check its format.",
    "清单条目超过 50,000 项，请拆分。": "The inventory exceeds 50,000 entries; split it into smaller files.",
    "需要 name 与 version 字段": "The name and version fields are required",
    "锁文件条目超过 50,000 项，请拆分。": "The lock file exceeds 50,000 entries; split it into smaller files.",
    "本地链接或非标准条目，不查询远程地址": "Local link or nonstandard entry; remote addresses are not queried",
    "无法确定 npm 包名与精确发行版本": "Cannot determine the npm package name and exact release version",
    "JSON 需为 pip list 数组或 package-lock v2/v3；不支持 package.json、lock v1 或任意 JSON。": "JSON must be a pip list array or package-lock v2/v3; package.json, lock v1 and arbitrary JSON are unsupported.",
    "清单超过 50,000 行，请拆分。": "The inventory exceeds 50,000 lines; split it into smaller files.",
    "行长度超限": "Line length exceeds the limit",
    "不读取嵌套清单、编辑安装、索引选项或远程文件": "Nested inventories, editable installs, index options and remote files are not read",
    "无法解析依赖声明": "Cannot parse the dependency declaration",
    "未精确锁定版本或属于 URL 依赖；请导入锁文件 / pip list JSON": "Version is not exactly pinned or this is a URL dependency; import a lock file / pip list JSON",
    "文件末尾": "End of file",
    "未闭合的续行": "Unterminated line continuation",
    "唯一依赖版本超过 2,000 个，请拆分清单。": "The inventory exceeds 2,000 unique dependency versions; split it into smaller files.",
    "清单中没有可识别的依赖。": "No recognizable dependencies were found in the inventory.",
    "达到本次查询时间预算": "The time budget for this check has been reached",
    "OSV 响应超过大小上限": "The OSV response exceeds the size limit",
    "OSV 请求未完成": "The OSV request did not complete",
    "OSV 批量响应数量与请求不一致": "The OSV batch response count does not match the request count",
    "查询失败": "Query failed",
    "OSV 单项查询失败": "An individual OSV query failed",
    "OSV 漏洞条目格式错误": "Invalid OSV vulnerability entry format",
    "OSV 分页令牌重复或无效": "Repeated or invalid OSV pagination token",
    "超过分页上限，已保留当前命中，但结果不完整": "Pagination limit reached; existing matches are retained, but the result is incomplete",
    "OSV 公告编号格式无效": "Invalid OSV advisory identifier format",
    "公告响应编号与请求不一致": "The advisory response identifier does not match the request",
    "演示快照未覆盖该依赖；请切换联网检查": "The demo snapshot does not cover this dependency; switch to a live check",
    "公告响应结构错误": "Invalid advisory response structure",
    "详情获取失败": "Could not retrieve advisory details",
    "超过每次 200 个公告详情上限": "The limit of 200 advisory details per check was reached",
    "命中公告，详情未取得": "Advisory matched; details unavailable",
    "命中公告": "Advisory matched",
    "仅命中已撤回公告": "Only withdrawn advisories matched",
    "未命中": "No match",
    "按 OSV 对精确依赖版本的公开记录匹配；未验证安装状态、可达性、利用条件或升级兼容性。未命中不等于无漏洞。": "Matches exact dependency versions against public OSV records; installation state, reachability, exploitability and upgrade compatibility are not verified. No match does not establish that a package is vulnerability-free.",
    "修复参考是匹配包公告中列出的边界，可能包含多个分支；不是保证兼容的升级建议。": "Fix references are boundaries listed in advisories for the matched package and may cover several branches; they are not guaranteed-compatible upgrade recommendations.",
}


def diagnostic(value, lang="zh"):
    """Translate only recognized owned diagnostics; retain external technical details."""
    value = str(value)
    if lang != "en":
        return value
    if value in _DIAGNOSTICS:
        return _DIAGNOSTICS[value]
    value = re.sub(r"^第 (\d+) 行", r"Line \1", value)
    value = re.sub(r"^条目 (\d+)", r"Entry \1", value)
    value = value.replace("（含条件标记，未核实目标环境是否启用）", " (conditional marker; activation in the target environment is unverified)")
    value = re.sub(r"^OSV 返回 HTTP (\d+)$", r"OSV returned HTTP \1", value)
    return re.sub(r"^OSV 请求失败（([^）]+)）$", r"OSV request failed (\1)", value)


def location_text(value, manifest_format, lang="zh"):
    """Only Python line/entry labels are generated text; npm locations are paths."""
    return diagnostic(value, lang) if manifest_format in {"requirements", "pip-list-json"} else str(value)
