# Changelog

## 0.2.0 — 2026-10-26

- Add a Chinese / English UI selector with local translations for controls, statuses, diagnostics and readable exports.
- Preserve selected examples, pasted input, scope, filters, evidence and scan results across language changes; reruns do not trigger network requests.
- Add CLI `--lang en|zh` for localized help, errors, Markdown and CSV. Preserve default Chinese behavior, JSON fields and values, and exit codes `0/1/2`.
- Publish complete English and Chinese READMEs with reciprocal links; retain all original third-party advisory data and licensing.
- Preserve original npm workspace paths in every language, and use locale-specific source/mode widget IDs with independent canonical state to refresh frontend labels without losing selections.
- Add eleven language regressions to the existing unittest suite, including an English offline workflow, advisory-text/path retention, frontend widget IDs/options and explicit live-query state checks.

## 0.1.0 — 2026-10-26

- Python 精确 requirements、pip list JSON、npm lock v2/v3 解析。
- 显式未解析项、按唯一依赖版本去重、npm 生产范围与包名排除。
- OSV 实时查询、逐项分页、有限重试、公告缓存与不完整状态。
- 公告别名合并、包级修复参考、撤回记录分离与原文来源。
- Streamlit 界面、CLI、JSON / Markdown / CSV 导出与真实快照演示。
- 实际环境检查记录、自动化测试和双系统 CI。
