"""Command line checks suitable for daily use and CI. No dependency execution."""

import argparse
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys

from .manifests import parse_manifest
from .i18n import diagnostic, text
from .osv import OSVClient, SnapshotClient
from .report import csv_report, markdown_report, scan

ROOT = Path(__file__).resolve().parents[1]


class LanguageArgumentParser(argparse.ArgumentParser):
    def __init__(self, *args, lang="zh", **kwargs):
        self.lang = lang
        super().__init__(*args, **kwargs)
        if lang == "zh":
            self._positionals.title = "位置参数"
            self._optionals.title = "选项"

    def error(self, message):
        if self.lang == "zh":
            # argparse owns these standard diagnostics; technical values stay intact.
            for source, target in (("unrecognized arguments:", "无法识别的参数："), ("argument ", "参数 "), ("invalid choice:", "无效选项："), ("choose from", "可选值"), ("expected one argument", "需要一个参数值")):
                message = message.replace(source, target)
        self.print_usage(sys.stderr)
        self.exit(2, text("cli_parser_error", self.lang, message=message) + "\n")


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    # Inspect the locale before argparse processes --help, regardless of argument order.
    lang = "zh"
    for index, value in enumerate(argv):
        if value == "--lang" and index + 1 < len(argv):
            lang = argv[index + 1]
        elif value.startswith("--lang="):
            lang = value.partition("=")[2]
    lang = lang if lang in {"en", "zh"} else "zh"
    t = lambda key, **values: text(key, lang, **values)
    parser = LanguageArgumentParser(description=t("cli_description"), add_help=False, lang=lang)
    parser.add_argument("-h", "--help", action="help", help=t("cli_help"))
    parser.add_argument("manifest", nargs="?", type=Path, help=t("cli_manifest"))
    parser.add_argument("--lang", choices=["en", "zh"], default="zh", help=t("cli_lang"))
    parser.add_argument("--demo", action="store_true", help=t("cli_demo"))
    parser.add_argument("--format", choices=["json", "markdown", "csv"], default="json", help=t("cli_format"))
    parser.add_argument("--output", type=Path, help=t("cli_output"))
    parser.add_argument("--production", action="store_true", help=t("cli_production"))
    parser.add_argument("--exclude", action="append", default=[], help=t("cli_exclude"))
    parser.add_argument("--refresh", action="store_true", help=t("cli_refresh"))
    args = parser.parse_args(argv)
    if not args.manifest and not args.demo:
        parser.error(t("cli_missing"))
    try:
        if args.output and args.output.exists():
            raise ValueError(t("cli_exists"))
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
            output = markdown_report(report, lang=lang).encode("utf-8")
        else:
            output = csv_report(report, lang=lang)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_bytes(output)
            print(t("cli_written", path=args.output), file=sys.stderr)
        else:
            sys.stdout.buffer.write(output)
        return 2 if report["status"] == "partial" else (1 if report["summary"]["unique_vulnerabilities"] else 0)
    except (OSError, ValueError) as error:
        print(t("cli_failed", error=diagnostic(error, lang)), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
