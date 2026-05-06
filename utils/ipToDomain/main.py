#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sqlite3
import socket
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# ---- domain normalization / validation ----

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)

def _looks_like_domain(s: str) -> bool:
    s = s.strip()
    if not s or len(s) > 253:
        return False
    if "." not in s:
        return False
    if s.lower() in ("localhost",):
        return False
    return bool(DOMAIN_RE.match(s))

def _norm_domain(s: str) -> str:
    return s.strip().rstrip(".").lower()


# ---- HTTP session with retries ----

def build_session() -> requests.Session:
    sess = requests.Session()
    retry = Retry(
        total=2,
        connect=2,
        read=2,
        backoff_factor=0.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("GET",),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=10)
    sess.mount("https://", adapter)
    sess.mount("http://", adapter)
    sess.headers.update({"User-Agent": "reverse-ip-domains-no-keys/2.0"})
    return sess


# ---- SQLite cache ----

class Cache:
    def __init__(self, path: str) -> None:
        self.path = os.path.expanduser(path)
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        self.db = sqlite3.connect(self.path)
        self.db.execute(
            """
            CREATE TABLE IF NOT EXISTS cache (
              provider TEXT NOT NULL,
              key TEXT NOT NULL,
              ts INTEGER NOT NULL,
              status INTEGER NOT NULL,
              body BLOB,
              PRIMARY KEY(provider, key)
            )
            """
        )
        self.db.commit()

    def get(self, provider: str, key: str) -> Optional[Tuple[int, int, Optional[bytes]]]:
        row = self.db.execute(
            "SELECT ts, status, body FROM cache WHERE provider=? AND key=?",
            (provider, key),
        ).fetchone()
        if not row:
            return None
        return int(row[0]), int(row[1]), row[2]

    def put(self, provider: str, key: str, ts: int, status: int, body: Optional[bytes]) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO cache(provider,key,ts,status,body) VALUES (?,?,?,?,?)",
            (provider, key, ts, status, body),
        )
        self.db.commit()


# ---- generic JSON walker to extract domains ----

def extract_domains_from_json(obj: Any) -> Set[str]:
    out: Set[str] = set()

    def walk(x: Any) -> None:
        if x is None:
            return
        if isinstance(x, str):
            if _looks_like_domain(x):
                out.add(_norm_domain(x))
            return
        if isinstance(x, dict):
            for v in x.values():
                walk(v)
            return
        if isinstance(x, list):
            for v in x:
                walk(v)
            return

    walk(obj)
    return out


# ---- provider framework ----

@dataclass
class ProviderResult:
    provider: str
    domains: Set[str]
    note: Optional[str] = None
    used_cache: bool = False
    cache_stale: bool = False


class Provider:
    name: str
    ttl_s: int = 24 * 3600
    min_interval_s: float = 0.0  # polite throttling

    def fetch(self, ip: str, sess: requests.Session, cache: Cache, timeout_s: float) -> ProviderResult:
        raise NotImplementedError


_last_call_ts: Dict[str, float] = {}

def _throttle(provider_name: str, min_interval_s: float) -> None:
    if min_interval_s <= 0:
        return
    now = time.time()
    last = _last_call_ts.get(provider_name, 0.0)
    sleep_for = (last + min_interval_s) - now
    if sleep_for > 0:
        time.sleep(sleep_for)
    _last_call_ts[provider_name] = time.time()


class PTRProvider(Provider):
    name = "ptr"
    ttl_s = 6 * 3600

    def fetch(self, ip: str, sess: requests.Session, cache: Cache, timeout_s: float) -> ProviderResult:
        # PTR is local, but caching still reduces repeated resolver hits in loops.
        ck = ip
        now = int(time.time())
        cached = cache.get(self.name, ck)
        if cached and (now - cached[0]) < self.ttl_s and cached[2]:
            try:
                payload = json.loads(cached[2].decode("utf-8"))
                return ProviderResult(self.name, set(payload.get("domains", [])), used_cache=True)
            except Exception:
                pass

        old = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout_s)
        domains: Set[str] = set()
        try:
            host, aliases, _ = socket.gethostbyaddr(ip)
            for h in [host, *aliases]:
                if isinstance(h, str) and _looks_like_domain(h):
                    domains.add(_norm_domain(h))
        except Exception:
            pass
        finally:
            socket.setdefaulttimeout(old)

        cache.put(self.name, ck, now, 200, json.dumps({"domains": sorted(domains)}).encode("utf-8"))
        return ProviderResult(self.name, domains)


class HackerTargetProvider(Provider):
    name = "hackertarget"
    ttl_s = 24 * 3600
    min_interval_s = 1.0  # gentle; free tier is limited anyway

    def fetch(self, ip: str, sess: requests.Session, cache: Cache, timeout_s: float) -> ProviderResult:
        ck = ip
        now = int(time.time())
        cached = cache.get(self.name, ck)
        if cached and (now - cached[0]) < self.ttl_s and cached[2]:
            return ProviderResult(self.name, set(cached[2].decode("utf-8").splitlines()), used_cache=True)

        _throttle(self.name, self.min_interval_s)

        url = "https://api.hackertarget.com/reverseiplookup/"
        try:
            r = sess.get(url, params={"q": ip}, timeout=timeout_s)
            text = (r.text or "").strip()

            # Errors are plain-text; keep note but fall back to cache if present.
            if r.status_code != 200 or text.lower().startswith("error") or "quota" in text.lower():
                note = text[:200] if text else f"HTTP {r.status_code}"
                if cached and cached[2]:
                    return ProviderResult(
                        self.name,
                        set(cached[2].decode("utf-8").splitlines()),
                        note=note,
                        used_cache=True,
                        cache_stale=True,
                    )
                return ProviderResult(self.name, set(), note=note)

            domains: Set[str] = set()
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                d = line.split(",", 1)[0].strip()
                if _looks_like_domain(d):
                    domains.add(_norm_domain(d))

            cache.put(self.name, ck, now, r.status_code, ("\n".join(sorted(domains))).encode("utf-8"))
            return ProviderResult(self.name, domains)

        except Exception as e:
            if cached and cached[2]:
                return ProviderResult(
                    self.name,
                    set(cached[2].decode("utf-8").splitlines()),
                    note=f"request failed: {e}",
                    used_cache=True,
                    cache_stale=True,
                )
            return ProviderResult(self.name, set(), note=f"request failed: {e}")

# ---- DNS-over-HTTPS verification (Cloudflare dns-json) ----

def doh_lookup_cloudflare(name: str, rtype: str, sess: requests.Session, timeout_s: float) -> Set[str]:
    """
    Cloudflare DoH JSON endpoint:
      GET https://cloudflare-dns.com/dns-query?name=...&type=A
      Header: Accept: application/dns-json
    """
    url = "https://cloudflare-dns.com/dns-query"
    headers = {"Accept": "application/dns-json"}
    r = sess.get(url, params={"name": name, "type": rtype}, headers=headers, timeout=timeout_s)
    if r.status_code != 200:
        return set()
    j = r.json()
    out: Set[str] = set()
    for ans in (j.get("Answer") or []):
        data = ans.get("data")
        if isinstance(data, str):
            out.add(data.strip())
    return out


def verify_domains(domains: Iterable[str], target_ip: str, sess: requests.Session, timeout_s: float, workers: int = 32) -> Set[str]:
    from concurrent.futures import ThreadPoolExecutor, as_completed

    target = ipaddress.ip_address(target_ip)

    def check(d: str) -> Tuple[str, bool]:
        addrs = set()
        addrs |= doh_lookup_cloudflare(d, "A", sess, timeout_s)
        addrs |= doh_lookup_cloudflare(d, "AAAA", sess, timeout_s)
        ok = any(ipaddress.ip_address(a) == target for a in addrs if _is_ip(a))
        return d, ok

    def _is_ip(s: str) -> bool:
        try:
            ipaddress.ip_address(s)
            return True
        except ValueError:
            return False

    doms = list(domains)
    keep: Set[str] = set()
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(check, d) for d in doms]
        for fut in as_completed(futs):
            d, ok = fut.result()
            if ok:
                keep.add(d)
    return keep


# ---- main ----

PROVIDERS: Dict[str, Provider] = {
    "ptr": PTRProvider(),
    "hackertarget": HackerTargetProvider(),
}

def validate_ip(value: str) -> str:
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e)) from e

def main(argv: Sequence[str]) -> int:
    ap = argparse.ArgumentParser(description="Reverse IP -> domain list (no keys), with cache + optional verification.")
    ap.add_argument("ip", type=validate_ip)
    ap.add_argument("--sources", default="ptr,hackertarget",
                    help="Comma-separated: " + ",".join(PROVIDERS.keys()))
    ap.add_argument("--verify", action="store_true", help="Only keep domains that currently resolve to the IP (DoH).")
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--cache", default="~/.cache/reverse_ip_domains/cache.sqlite3")
    ap.add_argument("--format", choices=("text", "json", "tsv"), default="text")
    args = ap.parse_args(argv)

    ip = args.ip
    sources = [s.strip().lower() for s in args.sources.split(",") if s.strip()]
    for s in sources:
        if s not in PROVIDERS:
            raise SystemExit(f"Unknown source '{s}'. Valid: {', '.join(PROVIDERS.keys())}")

    sess = build_session()
    cache = Cache(args.cache)

    all_domains: Set[str] = set()
    dom_sources: Dict[str, Set[str]] = {}
    notes: List[str] = []

    for s in sources:
        res = PROVIDERS[s].fetch(ip, sess, cache, args.timeout)
        if res.note:
            extra = " (stale cache)" if res.cache_stale else ""
            notes.append(f"{res.provider}: {res.note}{extra}")
        for d in res.domains:
            all_domains.add(d)
            dom_sources.setdefault(d, set()).add(res.provider)

    verified_domains: Optional[Set[str]] = None
    if args.verify and all_domains:
        verified_domains = verify_domains(all_domains, ip, sess, args.timeout)
        dom_sources = {d: dom_sources[d] for d in verified_domains}

    final = sorted(verified_domains if verified_domains is not None else all_domains)

    if args.format == "text":
        for d in final:
            print(d)
        if notes:
            print("\n# notes", file=sys.stderr)
            for n in notes:
                print(f"# {n}", file=sys.stderr)

    elif args.format == "tsv":
        print("domain\tsources\tverified")
        vflag = "1" if verified_domains is not None else ""
        for d in final:
            print(f"{d}\t{','.join(sorted(dom_sources.get(d, set())))}\t{vflag}")
        if notes:
            print("\n# notes", file=sys.stderr)
            for n in notes:
                print(f"# {n}", file=sys.stderr)

    else:  # json
        payload = {
            "ip": ip,
            "sources": sources,
            "verified": bool(args.verify),
            "count": len(final),
            "domains": [{"domain": d, "sources": sorted(dom_sources.get(d, set()))} for d in final],
            "notes": notes,
        }
        print(json.dumps(payload, indent=2))

    return 0

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
