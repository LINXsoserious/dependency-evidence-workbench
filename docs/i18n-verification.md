# v0.2 bilingual verification

Date: 2026-10-26. Windows / Python 3.12.3, Streamlit 1.66.1. These are assistant-run development checks.

`python -m unittest discover -s tests -q` passed **41 tests**, including the original 30 and 11 localization regressions. CI discovers the same unittest classes. Existing third-party snapshots and licensing remain unchanged.

Coverage includes explicit English/Chinese catalogs, complete English offline checks, unchanged machine JSON, CLI help/errors and exit codes, localized Markdown/CSV, retained scope/filter/evidence/results without repeated queries, and frontend widget identity and selected-label refresh.

Original npm paths are preserved in UI, Markdown, CSV and JSON. A regression uses paths containing Chinese strings that resemble generated line-number and end-of-file diagnostics. Only generated requirements/pip-list locations are localized.

Actual browser review confirmed English source/mode options and checked indicators, then executed the offline Python example. It displayed 2 checked versions, 2 affected versions, 6 unique vulnerability groups and 0 unresolved entries. No new live OSV request was made for this review. See [the English screenshot](screenshot-en.jpg).

Original advisories, package identifiers, versions, source paths and report schemas are not translated. Historical network verification is retained separately in [verification.md](verification.md); current CI results must be checked for the exact published commit.
