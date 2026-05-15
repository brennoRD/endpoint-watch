#!/usr/bin/env python3
"""
endpoint-watch — watch a target's JS assets for new endpoints and secrets.

Workflow per run:
  1. Fetch the target page
  2. Extract every <script src=…> URL
  3. Download each JS, hash it, compare with the last stored hash
  4. For JS files that changed, diff old vs new content and extract:
       - new endpoint-like strings (paths, full URLs)
       - new secret-like strings (API keys, tokens — best-effort)
  5. Print a report; optionally POST it to a webhook
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sqlite3
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Iterable

import requests

DB_PATH = Path.home() / ".endpoint-watch" / "snapshots.db"
DEFAULT_TIMEOUT = 15
DEFAULT_UA = "endpoint-watch/0.1 (+https://github.com/brennoRD/endpoint-watch)"

SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)

ENDPOINT_RES = [
    re.compile(r'["\'](/[A-Za-z0-9_\-./]{2,}\??[A-Za-z0-9_\-./=&]*)["\']'),
    re.compile(r'["\'](https?://[A-Za-z0-9_\-./:?=&%]+)["\']'),
]

SECRET_RES = [
    (re.compile(r'AKIA[0-9A-Z]{16}'),                "AWS Access Key"),
    (re.compile(r'AIza[0-9A-Za-z_\-]{35}'),          "Google API Key"),
    (re.compile(r'ghp_[A-Za-z0-9]{36}'),             "GitHub Token"),
    (re.compile(r'sk-[A-Za-z0-9]{20,}'),             "OpenAI-style Key"),
    (re.compile(r'xox[baprs]-[A-Za-z0-9-]{10,}'),    "Slack Token"),
    (re.compile(r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}'), "JWT"),
]


def db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS snapshots (
            target TEXT NOT NULL,
            js_url TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            content TEXT NOT NULL,
            ts INTEGER NOT NULL,
            PRIMARY KEY (target, js_url)
        )
    """)
    return conn


def fetch(url: str, timeout: int = DEFAULT_TIMEOUT) -> tuple[int, str]:
    r = requests.get(url, timeout=timeout, headers={"User-Agent": DEFAULT_UA})
    return r.status_code, r.text


def extract_script_srcs(html: str, base_url: str) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for match in SCRIPT_SRC_RE.findall(html):
        full = urllib.parse.urljoin(base_url, match)
        if full.startswith(("http://", "https://")) and full not in seen:
            seen.add(full)
            out.append(full)
    return out


def hash_text(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8", errors="ignore")).hexdigest()


def find_endpoints(content: str) -> set[str]:
    found: set[str] = set()
    for rx in ENDPOINT_RES:
        for m in rx.findall(content):
            if 3 <= len(m) <= 200:
                found.add(m)
    return found


def find_secrets(content: str) -> list[tuple[str, str]]:
    hits: list[tuple[str, str]] = []
    for rx, label in SECRET_RES:
        for m in set(rx.findall(content)):
            hits.append((label, m))
    return hits


def diff_sets(old: set[str], new: set[str]) -> set[str]:
    return new - old


def load_previous(conn, target: str, js_url: str) -> tuple[str, str] | None:
    row = conn.execute(
        "SELECT sha256, content FROM snapshots WHERE target=? AND js_url=?",
        (target, js_url),
    ).fetchone()
    return row if row else None


def save_snapshot(conn, target: str, js_url: str, sha: str, content: str) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO snapshots (target, js_url, sha256, content, ts) "
        "VALUES (?, ?, ?, ?, ?)",
        (target, js_url, sha, content, int(time.time())),
    )
    conn.commit()


def scan(target: str, webhook: str | None = None, quiet: bool = False) -> dict:
    report: dict = {"target": target, "changes": [], "errors": []}

    try:
        status, html = fetch(target)
    except Exception as e:
        report["errors"].append(f"fetch target: {e}")
        return report

    if status >= 400:
        report["errors"].append(f"target returned HTTP {status}")
        return report

    js_urls = extract_script_srcs(html, target)
    if not quiet:
        print(f"[+] {target}: found {len(js_urls)} JS file(s)")

    conn = db()
    for js_url in js_urls:
        try:
            _, content = fetch(js_url)
        except Exception as e:
            report["errors"].append(f"fetch {js_url}: {e}")
            continue

        sha = hash_text(content)
        previous = load_previous(conn, target, js_url)

        if previous is None:
            save_snapshot(conn, target, js_url, sha, content)
            if not quiet:
                print(f"    [first seen] {js_url}")
            continue

        old_sha, old_content = previous
        if old_sha == sha:
            continue

        new_endpoints = sorted(diff_sets(find_endpoints(old_content), find_endpoints(content)))
        new_secrets = find_secrets(content)
        old_secrets = set(find_secrets(old_content))
        new_secrets = [s for s in new_secrets if s not in old_secrets]

        change = {
            "js_url": js_url,
            "old_sha": old_sha,
            "new_sha": sha,
            "new_endpoints": new_endpoints[:50],
            "new_secrets": new_secrets,
        }
        report["changes"].append(change)
        save_snapshot(conn, target, js_url, sha, content)

        if not quiet:
            print(f"    [changed] {js_url}")
            for ep in new_endpoints[:10]:
                print(f"        + endpoint: {ep}")
            for label, s in new_secrets:
                preview = s[:8] + "…"
                print(f"        ! secret ({label}): {preview}")

    if webhook and report["changes"]:
        try:
            requests.post(webhook, json=report, timeout=10)
        except Exception as e:
            report["errors"].append(f"webhook: {e}")

    return report


def main(argv: Iterable[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="endpoint-watch",
        description="Watch a target's JS for new endpoints and secrets",
    )
    p.add_argument("target", help="Target URL (e.g. https://example.com)")
    p.add_argument("--webhook", help="POST JSON report to this URL on change")
    p.add_argument("--json", action="store_true", help="Print JSON report instead of text")
    p.add_argument("--quiet", action="store_true", help="No text output (useful with --json)")
    args = p.parse_args(argv)

    report = scan(args.target, webhook=args.webhook, quiet=args.quiet or args.json)
    if args.json:
        print(json.dumps(report, indent=2))
    return 0 if not report["errors"] else 1


if __name__ == "__main__":
    sys.exit(main())
