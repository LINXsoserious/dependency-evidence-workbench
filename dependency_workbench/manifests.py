"""Parse pinned inventories without installing, resolving, or executing anything."""

from dataclasses import replace
import json
import re

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from .models import Dependency, ParsedManifest

MAX_BYTES = 5 * 1024 * 1024
MAX_PACKAGES = 2000
MAX_LINES = 50000
NPM_VERSION = r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"


def _npm_name(name):
    return isinstance(name, str) and len(name) <= 214 and re.fullmatch(r"(?:@[a-z0-9._-]+/)?[a-z0-9._-]+", name)


def parse_manifest(data: bytes, filename: str) -> ParsedManifest:
    if not data or len(data) > MAX_BYTES:
        raise ValueError("清单为空或超过 5 MB。")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise ValueError("请将清单保存为 UTF-8 编码。") from error
    result = ParsedManifest()
    dependencies = []

    def skip(location, reason):
        result.skipped.append({"location": location, "reason": reason})

    def python_pin(name, version, location):
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?", name):
            skip(location, "包名格式无法识别")
            return
        try:
            parsed_version = Version(version)
            if parsed_version.local or "*" in version:
                raise InvalidVersion(version)
        except (InvalidVersion, TypeError):
            skip(location, "需要公开发行的精确版本，不支持通配或本地构建版本")
            return
        dependencies.append(Dependency("PyPI", str(canonicalize_name(name)), version, (location,)))

    if filename.lower().endswith(".json"):
        try:
            value = json.loads(text)
        except (ValueError, RecursionError) as error:
            raise ValueError("JSON 清单无法读取，请检查格式。") from error
        if isinstance(value, list):
            if len(value) > MAX_LINES:
                raise ValueError("清单条目超过 50,000 项，请拆分。")
            result.format = "pip-list-json"
            for index, item in enumerate(value):
                if isinstance(item, dict):
                    python_pin(item.get("name"), item.get("version"), f"条目 {index + 1}")
                else:
                    skip(f"条目 {index + 1}", "需要 name 与 version 字段")
        elif isinstance(value, dict) and value.get("lockfileVersion") in (2, 3) and isinstance(value.get("packages"), dict):
            if len(value["packages"]) > MAX_LINES:
                raise ValueError("锁文件条目超过 50,000 项，请拆分。")
            result.format = f"npm-lock-v{value['lockfileVersion']}"
            for path, item in value["packages"].items():
                if path == "":
                    continue
                location = str(path)[:500]
                if not isinstance(item, dict) or item.get("link"):
                    skip(location, "本地链接或非标准条目，不查询远程地址")
                    continue
                name = item.get("name") or path.rsplit("node_modules/", 1)[-1]
                version = item.get("version")
                if "node_modules/" not in path or not _npm_name(name) or not isinstance(version, str) or len(version) > 100 or not re.fullmatch(NPM_VERSION, version):
                    skip(location, "无法确定 npm 包名与精确发行版本")
                    continue
                dependencies.append(Dependency("npm", name, version, (location,), bool(item.get("dev", False))))
        else:
            raise ValueError("JSON 需为 pip list 数组或 package-lock v2/v3；不支持 package.json、lock v1 或任意 JSON。")
    else:
        result.format = "requirements"
        lines = text.splitlines()
        if len(lines) > MAX_LINES:
            raise ValueError("清单超过 50,000 行，请拆分。")
        pending = ""
        for number, raw in enumerate(lines, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if len(line) > 10000:
                skip(f"第 {number} 行", "行长度超限")
                continue
            if line.endswith("\\"):
                pending += line[:-1].strip() + " "
                continue
            line, pending = pending + line, ""
            location = f"第 {number} 行"
            if line.startswith("-"):
                skip(location, "不读取嵌套清单、编辑安装、索引选项或远程文件")
                continue
            line = re.sub(r"\s+--hash=\S+", "", line)
            line = re.split(r"\s+#", line, maxsplit=1)[0]
            try:
                requirement = Requirement(line)
            except InvalidRequirement:
                skip(location, "无法解析依赖声明")
                continue
            specs = list(requirement.specifier)
            if requirement.url or len(specs) != 1 or specs[0].operator != "==" or "*" in specs[0].version:
                skip(location, "未精确锁定版本或属于 URL 依赖；请导入锁文件 / pip list JSON")
                continue
            if requirement.marker:
                location += "（含条件标记，未核实目标环境是否启用）"
            python_pin(requirement.name, specs[0].version, location)
        if pending:
            skip("文件末尾", "未闭合的续行")
    combined = {}
    for dependency in dependencies:
        previous = combined.get(dependency.key)
        if previous:
            previous["locations"].extend(dependency.locations)
            previous["dev"] = previous["dev"] and dependency.dev
        else:
            combined[dependency.key] = {"dependency": dependency, "locations": list(dependency.locations), "dev": dependency.dev}
    result.packages = [replace(item["dependency"], locations=tuple(item["locations"]), dev=item["dev"]) for item in combined.values()]
    if len(result.packages) > MAX_PACKAGES:
        raise ValueError("唯一依赖版本超过 2,000 个，请拆分清单。")
    if not result.packages and not result.skipped:
        raise ValueError("清单中没有可识别的依赖。")
    return result
