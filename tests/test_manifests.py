import json
import unittest

from dependency_workbench.manifests import parse_manifest


class ManifestTests(unittest.TestCase):
    def test_python_exact_pin_normalization_and_duplicate_locations(self):
        parsed = parse_manifest(b"Requests==2.19.1\nrequests==2.19.1\nmy_pkg==1.0\n", "requirements.txt")
        self.assertEqual([(p.name, p.version) for p in parsed.packages], [("requests", "2.19.1"), ("my-pkg", "1.0")])
        self.assertEqual(len(parsed.packages[0].locations), 2)

    def test_unpinned_urls_includes_hashes_and_markers_are_not_executed(self):
        text = "requests>=2\n-r private.txt\npkg @ https://example.invalid/file.whl\nfoo==1.*\nbar==1.0 --hash=sha256:abcd\nidna==3.7 ; python_version >= '3.10'\n"
        parsed = parse_manifest(text.encode(), "requirements.txt")
        self.assertEqual([p.name for p in parsed.packages], ["bar", "idna"])
        self.assertEqual(len(parsed.skipped), 4)
        self.assertIn("条件", parsed.packages[-1].locations[0])

    def test_pip_list_json_and_invalid_versions(self):
        parsed = parse_manifest(json.dumps([{"name": "idna", "version": "3.7"}]).encode(), "installed.json")
        self.assertEqual(parsed.packages[0].key, "PyPI:idna@3.7")
        self.assertTrue(parse_manifest(b"idna==3.7+local\n", "requirements.txt").skipped)

    def test_npm_nested_scopes_dedup_and_dev_classification(self):
        payload = {"lockfileVersion": 3, "packages": {
            "": {"name": "project", "version": "1.0.0"},
            "node_modules/@scope/pkg": {"version": "1.2.0", "dev": True},
            "node_modules/other/node_modules/@scope/pkg": {"version": "1.2.0"},
            "node_modules/local": {"link": True},
        }}
        parsed = parse_manifest(json.dumps(payload).encode(), "package-lock.json")
        self.assertEqual(len(parsed.packages), 1)
        self.assertEqual(parsed.packages[0].name, "@scope/pkg")
        self.assertFalse(parsed.packages[0].dev)
        self.assertEqual(len(parsed.skipped), 1)

    def test_root_project_is_not_queried_and_v1_is_rejected(self):
        with self.assertRaises(ValueError):
            parse_manifest(b'{"lockfileVersion":1,"dependencies":{}}', "package-lock.json")

    def test_npm_non_exact_semver_is_unresolved(self):
        payload = {"lockfileVersion": 3, "packages": {"node_modules/pkg": {"version": "1banana"}}}
        parsed = parse_manifest(json.dumps(payload).encode(), "package-lock.json")
        self.assertFalse(parsed.packages)
        self.assertEqual(len(parsed.skipped), 1)

    def test_bad_json_empty_oversized_and_unsafe_package_are_rejected(self):
        for data, filename in [(b"", "a.txt"), (b"{bad", "a.json"), (b'{"lockfileVersion":[],"packages":{}}', "bad-lock.json"), (b"x" * (5 * 1024 * 1024 + 1), "a.txt")]:
            with self.subTest(filename=filename), self.assertRaises(ValueError):
                parse_manifest(data, filename)
        parsed = parse_manifest(b"x\ny @ git+https://example.invalid/repo\n", "requirements.txt")
        self.assertFalse(parsed.packages)
        self.assertEqual(len(parsed.skipped), 2)


if __name__ == "__main__":
    unittest.main()
