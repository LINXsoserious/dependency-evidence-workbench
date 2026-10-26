import copy
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from streamlit.testing.v1 import AppTest

from dependency_workbench.manifests import parse_manifest
from dependency_workbench.models import QueryResult
from dependency_workbench.osv import SnapshotClient
from dependency_workbench.report import csv_report, markdown_report

ROOT = Path(__file__).resolve().parents[1]


class LanguageTests(unittest.TestCase):
    def test_dictionary_parity_and_explicit_fallback(self):
        self.assertIsNotNone(importlib.util.find_spec("dependency_workbench.i18n"))
        from dependency_workbench.i18n import MESSAGES, text
        self.assertEqual(set(MESSAGES["en"]), set(MESSAGES["zh"]))
        self.assertEqual(text("brand", "en"), "Dependency Desk")
        self.assertEqual(text("brand", "unsupported"), text("brand", "zh"))

    def test_english_offline_workflow_and_language_switch_preserve_results(self):
        app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=40).run()
        self.assertIn("ui_language", [widget.key for widget in app.selectbox])
        app.radio(key="source").set_value("npm 示例").run()
        with patch("urllib.request.urlopen", side_effect=AssertionError("network not allowed")) as network:
            app.selectbox(key="ui_language").set_value("English").run()
            app.button(key="scan").click().run()
            self.assertEqual(len(app.exception), 0)
            self.assertEqual({metric.label: metric.value for metric in app.metric}["Unique vulnerabilities"], "6")
            before = copy.deepcopy(app.session_state["report"])
            self.assertEqual(app.radio(key="source_en").value, "npm 示例")
            for kind in ("markdown", "caption", "info", "warning", "error", "subheader", "metric"):
                for element in app.get(kind):
                    value = getattr(element, "value", "")
                    self.assertIsNone(re.search(r"[\u4e00-\u9fff]", str(value)), (kind, value))
            for kind in ("radio", "checkbox", "text_input", "button", "expander", "download_button", "text_area"):
                for element in app.get(kind):
                    self.assertIsNone(re.search(r"[\u4e00-\u9fff]", element.label), (kind, element.label))
            for element in app.dataframe:
                self.assertIsNone(re.search(r"[\u4e00-\u9fff]", " ".join(map(str, element.value.columns))))
            with patch("dependency_workbench.osv.SnapshotClient.query", side_effect=AssertionError("must not rescan")):
                app.selectbox(key="ui_language").set_value("简体中文").run()
                self.assertEqual(app.session_state["report"], before)
                app.selectbox(key="ui_language").set_value("English").run()
                self.assertEqual(app.session_state["report"], before)
                self.assertEqual(app.radio(key="source_en").value, "npm 示例")
                self.assertEqual(len(app.exception), 0)
            self.assertFalse(network.called)

    def test_localized_exports_preserve_source_report_and_raw_advisory(self):
        from dependency_workbench.report import scan
        report = scan(parse_manifest((ROOT / "samples/requirements-mixed.txt").read_bytes(), "requirements.txt"), SnapshotClient(ROOT / "samples/osv-snapshot.json"))
        before = copy.deepcopy(report)
        english = markdown_report(report, lang="en")
        self.assertIn("# Dependency vulnerability evidence report", english)
        self.assertIn("## Unresolved entries", english)
        self.assertNotRegex(english, r"[\u4e00-\u9fff]")
        self.assertIn(report["findings"][0]["summary"], english)
        self.assertIn("Report completeness,Record type", csv_report(report, lang="en").decode("utf-8-sig"))
        self.assertIn("依赖漏洞核验报告", markdown_report(report, lang="zh"))
        self.assertEqual(report, before)

    def test_advisory_text_is_not_translated_when_it_resembles_a_diagnostic(self):
        from dependency_workbench.report import scan
        report = scan(parse_manifest((ROOT / "samples/requirements-demo.txt").read_bytes(), "requirements.txt"), SnapshotClient(ROOT / "samples/osv-snapshot.json"))
        finding = report["findings"][0]
        finding["summary"] = "清单为空或超过 5 MB。"
        finding["details_complete"] = False
        self.assertIn(finding["summary"], markdown_report(report, lang="en"))
        finding["summary"] = "命中公告，详情未取得"
        finding["details_excerpt"] = ""
        finding["details_complete"] = True
        self.assertIn("Advisory matched; details unavailable", markdown_report(report, lang="en"))

    def test_pasted_input_scope_filters_and_selected_evidence_survive_switch(self):
        app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=40).run()
        app.radio(key="source").set_value("粘贴清单").run()
        pasted = "requests==2.19.1\nidna==3.7\nflask>=3\n"
        app.text_area(key="paste").set_value(pasted).run()
        app.text_input(key="exclude").set_value("idna").run()
        app.radio(key="mode_粘贴清单").set_value("离线演示快照").run()
        app.button(key="scan").click().run()
        app.text_input(key="search").set_value("requests").run()
        app.selectbox(key="evidence").set_value(1).run()
        before = copy.deepcopy(app.session_state["report"])
        app.selectbox(key="ui_language").set_value("English").run()
        self.assertEqual(len(app.exception), 0)
        self.assertEqual(app.text_area(key="paste").value, pasted)
        self.assertEqual(app.text_input(key="exclude").value, "idna")
        self.assertEqual(app.text_input(key="search").value, "requests")
        self.assertEqual(app.selectbox(key="evidence").value, 1)
        self.assertEqual(app.session_state["report"], before)
        self.assertEqual(before["status"], "partial")
        for frame in app.dataframe:
            self.assertNotRegex(frame.value.to_string(index=False), r"[\u4e00-\u9fff]")

    def test_live_check_requires_click_and_language_reruns_do_not_query_again(self):
        app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=40).run()
        with patch("dependency_workbench.osv.OSVClient.query", side_effect=lambda packages: {p.key: QueryResult() for p in packages}) as query:
            app.radio(key="mode_Python 示例").set_value("联网检查").run()
            self.assertFalse(query.called)
            app.selectbox(key="ui_language").set_value("English").run()
            self.assertFalse(query.called)
            app.button(key="scan").click().run()
            self.assertEqual(query.call_count, 1)
            app.selectbox(key="ui_language").set_value("简体中文").run()
            self.assertEqual(query.call_count, 1)
            self.assertEqual(len(app.exception), 0)
            self.assertEqual(app.session_state["report"]["mode"], "live")

    def test_npm_paths_that_resemble_generated_locations_are_preserved_in_exports(self):
        from dependency_workbench.report import scan
        inventory = {"lockfileVersion": 3, "packages": {"第 2 行/node_modules/minimist": {"version": "1.2.8"}, "文件末尾": {"link": True}}}
        report = scan(parse_manifest(json.dumps(inventory).encode(), "package-lock.json"), SnapshotClient(ROOT / "samples/osv-snapshot.json"))
        self.assertEqual(tuple(report["packages"][0]["locations"]), ("第 2 行/node_modules/minimist",))
        for render in (markdown_report(report, lang="en"), csv_report(report, lang="en").decode("utf-8-sig")):
            self.assertIn("文件末尾", render)
            self.assertNotIn("End of file", render)

    def test_npm_original_paths_are_preserved_in_english_inventory_tables(self):
        app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=40).run()
        app.radio(key="source").set_value("粘贴清单").run()
        inventory = {"lockfileVersion": 3, "packages": {"第 2 行/node_modules/minimist": {"version": "1.2.8"}, "文件末尾": {"link": True}}}
        app.text_area(key="paste").set_value(json.dumps(inventory)).run()
        app.radio(key="mode_粘贴清单").set_value("离线演示快照").run()
        app.selectbox(key="ui_language").set_value("English").run()
        app.button(key="scan").click().run()
        self.assertEqual(len(app.exception), 0)
        values = "\n".join(frame.value.to_string(index=False) for frame in app.dataframe)
        self.assertIn("第 2 行/node_modules/minimist", values)
        self.assertIn("文件末尾", values)
        self.assertNotIn("Line 2/node_modules/minimist", values)
        self.assertNotIn("End of file", values)

    def test_localized_radio_labels_use_new_frontend_ids_with_canonical_state(self):
        app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=40).run()
        app.radio(key="source").set_value("npm 示例").run()
        source_id = app.radio(key="source").proto.id
        mode_id = app.radio(key="mode_npm 示例").proto.id
        app.selectbox(key="ui_language").set_value("English").run()
        source = next(widget for widget in app.radio if widget.label == "01  Import inventory")
        mode = next(widget for widget in app.radio if widget.label == "Data source")
        self.assertNotEqual(source.proto.id, source_id)
        self.assertNotEqual(mode.proto.id, mode_id)
        self.assertEqual(list(source.proto.options), ["Python example", "npm example", "Upload inventory", "Paste inventory"])
        self.assertEqual(list(mode.proto.options), ["Live OSV check", "Offline demo snapshot"])
        self.assertEqual(source.value, "npm 示例")
        self.assertEqual(mode.value, "离线演示快照")
        app.selectbox(key="ui_language").set_value("简体中文").run()
        self.assertEqual(app.radio(key="source").value, "npm 示例")


class CLILanguageTests(unittest.TestCase):
    def run_cli(self, *arguments):
        return subprocess.run([sys.executable, "-X", "utf8", "-m", "dependency_workbench.cli", *map(str, arguments)], cwd=ROOT, capture_output=True, timeout=25)

    def test_help_errors_and_reports_follow_selected_language(self):
        english_help = self.run_cli("--lang", "en", "--help")
        self.assertEqual(english_help.returncode, 0)
        self.assertIn(b"Check pinned requirements", english_help.stdout)
        self.assertNotRegex(english_help.stdout.decode(), r"[\u4e00-\u9fff]")
        zh_help = self.run_cli("--lang", "zh", "--help")
        self.assertIn("不安装依赖", zh_help.stdout.decode())
        self.assertEqual(self.run_cli("--help", "--lang=en").stdout, english_help.stdout)
        missing = self.run_cli("--lang", "en")
        self.assertEqual(missing.returncode, 2)
        self.assertIn(b"Provide a manifest path", missing.stderr)
        bad_argument = self.run_cli("--lang", "en", "--format", "invalid")
        self.assertEqual(bad_argument.returncode, 2)
        self.assertNotRegex(bad_argument.stderr.decode(), r"[\u4e00-\u9fff]")
        english = self.run_cli("--demo", "--lang", "en", "--format", "markdown")
        self.assertEqual(english.returncode, 1)
        self.assertIn(b"# Dependency vulnerability evidence report", english.stdout)
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "existing.json"
            target.write_text("keep", encoding="utf-8")
            error = self.run_cli("--demo", "--lang", "en", "--output", target)
            self.assertIn(b"Output file already exists", error.stderr)
            self.assertNotRegex(error.stderr.decode(), r"[\u4e00-\u9fff]")
            inventory = Path(directory) / "requirements.txt"
            inventory.write_bytes(b"\xff")
            invalid = self.run_cli(inventory, "--demo", "--lang", "en")
            self.assertEqual(invalid.returncode, 2)
            self.assertIn(b"UTF-8 encoding", invalid.stderr)
            clean_inventory = Path(directory) / "package-lock.json"
            clean_inventory.write_text(json.dumps({"lockfileVersion": 3, "packages": {"node_modules/minimist": {"version": "1.2.8"}}}), encoding="utf-8")
            clean = self.run_cli(clean_inventory, "--demo", "--lang", "en")
            self.assertEqual(clean.returncode, 0)
            self.assertEqual(json.loads(clean.stdout)["summary"]["unique_vulnerabilities"], 0)

    def test_json_schema_values_and_exit_codes_do_not_change_with_language(self):
        for name, expected in (("requirements-demo.txt", 1), ("requirements-mixed.txt", 2)):
            values = []
            for language in ("zh", "en"):
                result = self.run_cli(ROOT / "samples" / name, "--demo", "--lang", language)
                self.assertEqual(result.returncode, expected)
                report = json.loads(result.stdout)
                report.pop("checked_at")
                values.append(report)
            self.assertEqual(*values)


if __name__ == "__main__":
    unittest.main()
