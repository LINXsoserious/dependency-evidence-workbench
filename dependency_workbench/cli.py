"""Command line checks suitable for daily use and CI. No dependency execution."""

import argparse
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys

from .manifests import parse_manifest
from .osv import OSVClient, SnapshotClient
from .report import csv_report, markdown_report, scan

ROOT = Path(__file__).resolve().parents[1]


def main(argv=None):
    parser = argparse.ArgumentParser(description="检查 requirements 精确版本、pip list JSON 或 npm lock v2/v3；不安装依赖。")
    parser.add_argument("manifest", nargs="?", type=Path)
    parser.add_argument("--demo", action="store_true", help="仅使用内置真实公告快照，不联网")
    parser.add_argument("--format", choices=["json", "markdown", "csv"], default="json")
    parser.add_argument("--output", type=Path, help="写入新文件；默认输出到终端")
    parser.add_argument("--production", action="store_true", help="排除 npm 标记 dev 的依赖；Python 清单无此标签")
    parser.add_argument("--exclude", action="append", default=[], help="排除包名，可重复")
    parser.add_argument("--refresh", action="store_true", help="忽略公告缓存，重新获取")
    args = parser.parse_args(argv)
    if not args.manifest and not args.demo:
        parser.error("请给出依赖清单路径，或使用 --demo")
    try:
        if args.output and args.output.exists():
            raise ValueError("输出文件已存在，请换一个文件名以保留已有报告。")
        path = args.manifest or ROOT / "samples" / "requirements-demo.txt"
        data = path.read_bytes()
        parsed = parse_manifest(data, path.name)
        names = {name.casefold() for name in args.exclude}
        excluded = [p.key for p in parsed.packages if p.name.casefold() in names or (args.production and p.dev)]
        parsed = replace(parsed, packages=[p for p in parsed.packages if p.key not in excluded])
        client = SnapshotClient(ROOT / "samples" / "osv-snapshot.json") if args.demo else OSVClient(cache_dir=ROOT / ".cache" / "osv", cache_ttl=0 if args.refresh else 86400)
        report = scan(parsed, client, excluded)
        report["manifest_sha256"] = hashlib.sha256(data).hexdigest()
        if args.format == "json":
            output = (json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        elif args.format == "markdown":
            output = markdown_report(report).encode("utf-8")
        else:
            output = csv_report(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_bytes(output)
            print(f"报告已写入：{args.output}", file=sys.stderr)
        else:
            sys.stdout.buffer.write(output)
        return 2 if report["status"] == "partial" else (1 if report["summary"]["unique_vulnerabilities"] else 0)
    except (OSError, ValueError) as error:
        print(f"检查未完成：{error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
