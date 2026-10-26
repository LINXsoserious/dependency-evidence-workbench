import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from streamlit.testing.v1 import AppTest

ROOT = Path(__file__).resolve().parents[1]


class AppTests(unittest.TestCase):
    def test_offline_demo_never_calls_network_and_exports_three_formats(self):
        app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=40).run()
        with patch("urllib.request.urlopen", side_effect=AssertionError("network not allowed")) as network:
            app.button(key="scan").click().run()
        self.assertEqual(len(app.exception), 0)
        self.assertFalse(network.called)
        self.assertEqual({metric.label: metric.value for metric in app.metric}["去重漏洞"], "6")
        self.assertEqual(app.session_state["report"]["status"], "complete")
        self.assertEqual(len(app.get("download_button")), 3)

    def test_source_change_resets_old_results(self):
        app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=40).run()
        app.button(key="scan").click().run()
        app.radio(key="source").set_value("npm 示例").run()
        self.assertEqual(len(app.metric), 0)
        app.button(key="scan").click().run()
        self.assertEqual(len(app.exception), 0)
        self.assertEqual({metric.label: metric.value for metric in app.metric}["检查依赖版本"], "3")

    def test_unpinned_pasted_input_does_not_become_a_clean_report(self):
        app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=40).run()
        app.radio(key="source").set_value("粘贴清单").run()
        app.text_area(key="paste").set_value("requests>=2.0").run()
        app.button(key="scan").click().run()
        self.assertEqual(len(app.exception), 0)
        self.assertGreater(len(app.error), 0)
        self.assertEqual(len(app.metric), 0)


class CLITests(unittest.TestCase):
    def run_cli(self, *arguments):
        return subprocess.run([sys.executable, "-X", "utf8", "-m", "dependency_workbench.cli", *map(str, arguments)], cwd=ROOT, capture_output=True, timeout=25)

    def test_vulnerable_demo_returns_one_with_machine_readable_json(self):
        result = self.run_cli("--demo")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)["summary"]["unique_vulnerabilities"], 6)

    def test_unresolved_or_uncovered_snapshot_returns_two(self):
        mixed = self.run_cli(ROOT / "samples/requirements-mixed.txt", "--demo")
        self.assertEqual(mixed.returncode, 2)
        self.assertEqual(json.loads(mixed.stdout)["summary"]["unresolved_entries"], 2)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "requirements.txt"
            path.write_text("requests==100.0.0\n", encoding="utf-8")
            uncovered = self.run_cli(path, "--demo")
            self.assertEqual(uncovered.returncode, 2)
            self.assertEqual(json.loads(uncovered.stdout)["summary"]["query_errors"], 1)

    def test_existing_report_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "keep.json"
            target.write_text("keep", encoding="utf-8")
            result = self.run_cli("--demo", "--output", target)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(target.read_text(encoding="utf-8"), "keep")

    def test_production_filter_is_explicit_and_still_checks_selected_scope(self):
        result = self.run_cli(ROOT / "samples/package-lock.json", "--demo", "--production")
        self.assertEqual(result.returncode, 1)
        report = json.loads(result.stdout)
        self.assertEqual(report["summary"]["queried_dependencies"], 2)
        self.assertEqual(report["summary"]["excluded_dependencies"], 1)
        self.assertTrue(report["excluded_packages"])


if __name__ == "__main__":
    unittest.main()
