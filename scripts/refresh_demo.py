"""Explicitly refresh public sample records; not run by tests or app startup."""

from dataclasses import asdict
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dependency_workbench.manifests import parse_manifest
from dependency_workbench.osv import OSVClient
from dependency_workbench.report import scan
from dependency_workbench.models import ParsedManifest


def main():
    packages = []
    for path in [ROOT / "samples" / "requirements-demo.txt", ROOT / "samples" / "package-lock.json"]:
        packages.extend(parse_manifest(path.read_bytes(), path.name).packages)
    client = OSVClient()
    queries = client.query(packages)
    errors = {key: result.error for key, result in queries.items() if result.error}
    if errors:
        raise RuntimeError(f"Query failed: {errors}")
    ids = sorted({identifier for result in queries.values() for identifier in result.ids})
    records = {}
    for identifier in ids:
        records[identifier] = client.advisory(identifier)
    data = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "source": "https://api.osv.dev",
        "licenses": {
            "GHSA": "https://github.com/github/advisory-database/blob/main/LICENSE.md",
            "PYSEC": "https://github.com/pypa/advisory-database/blob/main/LICENSE",
        },
        "queries": {key: asdict(result) for key, result in queries.items()},
        "records": records,
    }
    (ROOT / "samples" / "osv-snapshot.json").write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"packages": len(packages), "records": len(records), "captured_at": data["captured_at"]}, indent=2))


if __name__ == "__main__":
    main()
