import json
from pathlib import Path
import tempfile
import unittest

from dependency_workbench.models import Dependency
from dependency_workbench.osv import OSVClient


A = Dependency("PyPI", "requests", "2.19.1")
B = Dependency("npm", "minimist", "1.2.5")


class OSVTests(unittest.TestCase):
    def test_per_query_pagination_preserves_package_mapping(self):
        calls = []

        def transport(method, path, payload):
            calls.append(payload)
            if len(calls) == 1:
                return {"results": [{"vulns": [{"id": "A"}], "next_page_token": "next"}, {"vulns": [{"id": "B"}]}]}
            self.assertEqual(payload["queries"][0]["package"]["name"], "requests")
            self.assertEqual(payload["queries"][0]["page_token"], "next")
            return {"results": [{"vulns": [{"id": "A2"}]}]}

        results = OSVClient(transport=transport).query([A, B])
        self.assertEqual(results[A.key].ids, ["A", "A2"])
        self.assertEqual(results[B.key].ids, ["B"])

    def test_network_failure_is_error_not_empty_success(self):
        def broken(*args):
            raise OSError("offline")

        result = OSVClient(transport=broken).query([A])[A.key]
        self.assertTrue(result.error)

    def test_mismatched_result_length_is_error(self):
        results = OSVClient(transport=lambda *args: {"results": [{}]}).query([A, B])
        self.assertTrue(all(result.error for result in results.values()))

    def test_pagination_limit_keeps_ids_and_marks_incomplete(self):
        client = OSVClient(transport=lambda *args: {"results": [{"vulns": [{"id": "A"}], "next_page_token": "again"}]}, max_pages=1)
        result = client.query([A])[A.key]
        self.assertEqual(result.ids, ["A"])
        self.assertTrue(result.error)

    def test_cache_id_mismatch_or_bad_json_is_not_trusted(self):
        with tempfile.TemporaryDirectory() as directory:
            client = OSVClient(transport=lambda *args: {"id": "OTHER"}, cache_dir=Path(directory))
            with self.assertRaises(ValueError):
                client.advisory("GHSA-example")

    def test_empty_vulns_is_legitimate_no_match(self):
        result = OSVClient(transport=lambda *args: {"results": [{}]}).query([A])[A.key]
        self.assertFalse(result.error)
        self.assertEqual(result.ids, [])


if __name__ == "__main__":
    unittest.main()
