"""OSV client: positional batch mapping, bounded pagination, explicit errors."""

import hashlib
import json
from pathlib import Path
import re
import time
import urllib.error
import urllib.parse
import urllib.request

from .models import QueryResult

BASE_URL = "https://api.osv.dev"


class ServiceError(RuntimeError):
    pass


class OSVClient:
    mode = "live"
    snapshot_at = ""

    def __init__(self, transport=None, cache_dir=None, max_pages=10, timeout=12, cache_ttl=86400):
        self.transport = transport
        self.cache_dir = Path(cache_dir) if cache_dir else None
        self.max_pages = max_pages
        self.timeout = timeout
        self.cache_ttl = cache_ttl
        self.deadline = time.monotonic() + 90
        self.requests = 0
        self.cache_hits = 0
        self.records = {}

    def _request(self, method, path, payload=None):
        if time.monotonic() >= self.deadline:
            raise ServiceError("达到本次查询时间预算")
        if self.transport:
            return self.transport(method, path, payload)
        for attempt in range(2):
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise ServiceError("达到本次查询时间预算")
            request = urllib.request.Request(
                BASE_URL + path, data=json.dumps(payload).encode() if payload is not None else None,
                headers={"Content-Type": "application/json", "User-Agent": "DependencyEvidenceWorkbench/0.1"}, method=method,
            )
            self.requests += 1
            try:
                with urllib.request.urlopen(request, timeout=min(self.timeout, remaining)) as response:
                    raw = response.read(2 * 1024 * 1024 + 1)
                if len(raw) > 2 * 1024 * 1024:
                    raise ServiceError("OSV 响应超过大小上限")
                return json.loads(raw)
            except urllib.error.HTTPError as error:
                if error.code not in {429, 500, 502, 503, 504} or attempt:
                    raise ServiceError(f"OSV 返回 HTTP {error.code}") from error
            except (OSError, ValueError) as error:
                if attempt:
                    raise ServiceError(f"OSV 请求失败（{type(error).__name__}）") from error
            time.sleep(0.3)
        raise ServiceError("OSV 请求未完成")

    def query(self, packages):
        self.deadline = time.monotonic() + 90
        output = {package.key: QueryResult() for package in packages}
        for start in range(0, len(packages), 100):
            active = [(package, "") for package in packages[start:start + 100]]
            seen = {package.key: set() for package, _ in active}
            for _ in range(self.max_pages):
                if not active:
                    break
                queries = [{"package": {"ecosystem": p.ecosystem, "name": p.name}, "version": p.version, **({"page_token": token} if token else {})} for p, token in active]
                try:
                    response = self._request("POST", "/v1/querybatch", {"queries": queries})
                    results = response.get("results")
                    if not isinstance(results, list) or len(results) != len(active):
                        raise ServiceError("OSV 批量响应数量与请求不一致")
                except Exception as error:
                    for package, _ in active:
                        output[package.key].error = str(error)[:180] or "查询失败"
                    active = []
                    break
                next_active = []
                for (package, _), result in zip(active, results):
                    try:
                        if not isinstance(result, dict) or result.get("error"):
                            raise ServiceError("OSV 单项查询失败")
                        vulns = result.get("vulns", [])
                        if not isinstance(vulns, list) or any(not isinstance(v, dict) or not isinstance(v.get("id"), str) or not v["id"] for v in vulns):
                            raise ServiceError("OSV 漏洞条目格式错误")
                        output[package.key].ids = list(dict.fromkeys(output[package.key].ids + [v["id"] for v in vulns]))
                        token = result.get("next_page_token", "")
                        if token:
                            if not isinstance(token, str) or token in seen[package.key]:
                                raise ServiceError("OSV 分页令牌重复或无效")
                            seen[package.key].add(token)
                            next_active.append((package, token))
                    except Exception as error:
                        output[package.key].error = str(error)[:180]
                active = next_active
            for package, _ in active:
                output[package.key].error = "超过分页上限，已保留当前命中，但结果不完整"
        return output

    def advisory(self, advisory_id):
        if not isinstance(advisory_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", advisory_id):
            raise ValueError("OSV 公告编号格式无效")
        target = self.cache_dir / (hashlib.sha256(advisory_id.encode()).hexdigest() + ".json") if self.cache_dir else None
        if target and target.exists():
            try:
                cached = json.loads(target.read_text(encoding="utf-8"))
                if 0 <= time.time() - cached["fetched_at"] < self.cache_ttl and cached["record"].get("id") == advisory_id:
                    self.cache_hits += 1
                    self.records[advisory_id] = cached["record"]
                    return cached["record"]
            except (OSError, ValueError, KeyError, TypeError):
                pass
        record = self._request("GET", "/v1/vulns/" + urllib.parse.quote(advisory_id, safe=""))
        if not isinstance(record, dict) or record.get("id") != advisory_id:
            raise ValueError("公告响应编号与请求不一致")
        self.records[advisory_id] = record
        if target:
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(json.dumps({"fetched_at": time.time(), "record": record}), encoding="utf-8")
            except OSError:
                pass
        return record


class SnapshotClient:
    mode = "snapshot"

    def __init__(self, path):
        self.data = json.loads(Path(path).read_text(encoding="utf-8"))
        self.snapshot_at = self.data["captured_at"]
        self.requests = 0
        self.cache_hits = 0

    def query(self, packages):
        return {p.key: QueryResult(**self.data["queries"][p.key]) if p.key in self.data["queries"] else QueryResult(error="演示快照未覆盖该依赖；请切换联网检查") for p in packages}

    def advisory(self, advisory_id):
        return self.data["records"][advisory_id]
