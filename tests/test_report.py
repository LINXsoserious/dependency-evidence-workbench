import unittest

from dependency_workbench.models import Dependency, ParsedManifest, QueryResult
from dependency_workbench.report import csv_report, markdown_report, scan


PACKAGE = Dependency("npm", "minimist", "1.2.5")
RECORD = {"id": "GHSA-one", "aliases": ["CVE-2021-0001"], "summary": "Example issue", "details": "Evidence text.", "modified": "2026-01-01T00:00:00Z", "database_specific": {"severity": "HIGH"}, "affected": [{"package": {"name": "minimist", "ecosystem": "npm"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.6"}]}]}, {"package": {"name": "unrelated", "ecosystem": "npm"}, "ranges": [{"type": "SEMVER", "events": [{"fixed": "99.0.0"}]}]}]}


class FixtureClient:
    mode = "test"
    snapshot_at = ""

    def __init__(self, records=None, error=""):
        self.records = {"GHSA-one": RECORD} if records is None else records
        self.error = error

    def query(self, packages):
        return {p.key: QueryResult(list(self.records), self.error) for p in packages}

    def advisory(self, advisory_id):
        value = self.records[advisory_id]
        if value is None:
            raise OSError("details unavailable")
        return value


class ReportTests(unittest.TestCase):
    def test_fix_versions_belong_to_matching_package(self):
        report = scan(ParsedManifest([PACKAGE]), FixtureClient())
        self.assertEqual(report["findings"][0]["fixed_versions"], ["1.2.6"])
        self.assertNotIn("99.0.0", str(report["findings"]))

    def test_aliases_are_merged_without_losing_source_ids(self):
        second = {**RECORD, "id": "PYSEC-two"}
        report = scan(ParsedManifest([PACKAGE]), FixtureClient({"GHSA-one": RECORD, "PYSEC-two": second}))
        self.assertEqual(report["summary"]["unique_vulnerabilities"], 1)
        self.assertEqual(set(report["findings"][0]["source_ids"]), {"GHSA-one", "PYSEC-two"})

    def test_detail_failure_preserves_hit_and_marks_partial(self):
        report = scan(ParsedManifest([PACKAGE]), FixtureClient({"GHSA-missing": None}))
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["summary"]["affected_dependencies"], 1)

    def test_query_failure_and_unresolved_pins_do_not_produce_clean_verdict(self):
        report = scan(ParsedManifest([PACKAGE], [{"location": "line 2", "reason": "not pinned"}]), FixtureClient({}, "offline"))
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["summary"]["query_errors"], 1)

    def test_withdrawn_records_are_separate(self):
        withdrawn = {**RECORD, "withdrawn": "2026-02-01T00:00:00Z"}
        report = scan(ParsedManifest([PACKAGE]), FixtureClient({"GHSA-one": withdrawn}))
        self.assertEqual(report["summary"]["unique_vulnerabilities"], 0)
        self.assertEqual(report["summary"]["withdrawn_records"], 1)

    def test_absent_severity_is_unknown_instead_of_crashing(self):
        record = {**RECORD, "database_specific": None}
        report = scan(ParsedManifest([PACKAGE]), FixtureClient({"GHSA-one": record}))
        self.assertEqual(report["findings"][0]["severity"], "UNKNOWN")

    def test_exports_include_evidence_and_no_blanket_safe_claim(self):
        report = scan(ParsedManifest([PACKAGE]), FixtureClient())
        self.assertIn("https://osv.dev/vulnerability/GHSA-one", markdown_report(report))
        self.assertIn("1.2.6", csv_report(report).decode("utf-8-sig"))

    def test_exports_keep_query_errors_even_when_no_vulnerabilities_return(self):
        report = scan(ParsedManifest([PACKAGE]), FixtureClient({}, "offline"))
        self.assertIn("offline", markdown_report(report))
        self.assertIn("offline", csv_report(report).decode("utf-8-sig"))

    def test_empty_selected_scope_is_not_complete(self):
        self.assertEqual(scan(ParsedManifest(), FixtureClient({}), excluded=1)["status"], "partial")

    def test_csv_unresolved_fields_are_formula_safe(self):
        parsed = ParsedManifest([PACKAGE], [{"location": "=1+1", "reason": "@cmd"}])
        output = csv_report(scan(parsed, FixtureClient({}))).decode("utf-8-sig")
        self.assertIn("'=1+1", output)
        self.assertIn("'@cmd", output)


if __name__ == "__main__":
    unittest.main()
