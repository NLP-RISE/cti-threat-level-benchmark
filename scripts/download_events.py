#!/usr/bin/env python3
from __future__ import annotations

import argparse
import concurrent.futures as fut
import datetime as dt
import json
import os
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from common import ensure_dir, sha256_bytes, parse_event_minimal

INDEX_URL_CIRCL = "https://www.circl.lu/doc/misp/feed-osint/"
INDEX_URL_BOTVRIJ = "https://www.botvrij.eu/data/feed-osint/"

def today_stamp() -> str:
    return dt.date.today().isoformat()

def list_json_urls(target_urls) -> List[str]:
    """Fetch the index page and return a list of absolute URLs to .json files."""
    urls: List[str] = []
    for index_url in target_urls:
        r = requests.get(index_url, timeout=60)
        r.raise_for_status()
        soup = BeautifulSoup(r.text, "html.parser")
        for a in soup.find_all("a"):
            href = a.get("href") or ""
            if href.lower().endswith(".json"):
                urls.append(urljoin(index_url, href))
    return sorted(set(urls))

def download_one(url: str, outdir_raw: str, timeout: int = 120, retries: int = 3) -> Dict[str, Any]:
    """Download a single JSON and write to disk (into outdir_raw). Returns manifest row."""
    name = os.path.basename(urlparse(url).path)
    dest = os.path.join(outdir_raw, name)
    last_exc: Optional[Exception] = None
    for attempt in range(1, retries + 1):
        try:
            r = requests.get(url, timeout=timeout)
            r.raise_for_status()
            b = r.content
            with open(dest, "wb") as f:
                f.write(b)
            meta: Dict[str, Any] = {}
            try:
                raw = json.loads(b.decode("utf-8", errors="replace"))
                meta = parse_event_minimal(raw)  # NOTE: respects 'publish_timestamp' (no published_timestamp)
            except Exception:
                pass
            return {
                "url": url,
                "filename": name,
                "size": len(b),
                "sha256": sha256_bytes(b),
                **meta,
            }
        except Exception as e:
            last_exc = e
            if attempt < retries:
                time.sleep(1.5 * attempt)
            else:
                return {
                    "url": url,
                    "filename": name,
                    "error": str(last_exc),
                }
    # should not reach
    return {"url": url, "filename": name, "error": "unknown"}

def main():
    ap = argparse.ArgumentParser(description="Download CIRCL MISP OSINT feed snapshot.")
    ap.add_argument("--out", default=f"snapshots_both/{today_stamp()}", help="Output snapshot directory (will create <out>/raw)")
    ap.add_argument("--max-workers", type=int, default=16, help="Parallel download workers")
    args = ap.parse_args()

    # Create snapshot layout: <out>/raw
    out_raw = os.path.join(args.out, "raw")
    ensure_dir(out_raw)

    target_urls = [INDEX_URL_CIRCL, INDEX_URL_BOTVRIJ]

    print(f"[INFO] Listing JSONs...")
    urls = list_json_urls(target_urls)
    print(f"[INFO] Found {len(urls)} files. Downloading to {out_raw} ...")

    rows: List[Dict[str, Any]] = []
    with fut.ThreadPoolExecutor(max_workers=args.max_workers) as ex:
        for res in ex.map(lambda u: download_one(u, out_raw), urls):
            rows.append(res)
            if "error" in res:
                print(f"[ERR] {res['filename']}: {res['error']}")
            else:
                print(f"[OK]  {res['filename']} ({res.get('size','?')} bytes)")

    mani_path = os.path.join(out_raw, "manifest.jsonl")
    with open(mani_path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"[DONE] Wrote manifest: {mani_path}")

if __name__ == "__main__":
    main()
