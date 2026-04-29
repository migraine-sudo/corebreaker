#!/usr/bin/env python3
"""Batch fetch merged security-fix CLs from Chromium Gerrit.

Uses the Gerrit REST API via HTTP proxy (127.0.0.1:7890).
Output: one file per CL in diffs/, containing commit message + patch.
"""

import json
import base64
import sys
import os
import time
import urllib.request
import urllib.error

GERRIT = "https://chromium-review.googlesource.com"
PROXY = "http://127.0.0.1:7890"
DIFFS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "diffs")

QUERIES = [
    "status:merged+message:policy+message:bypass",
    "status:merged+message:DCHECK+message:fix+message:security",
    "status:merged+message:CSP+message:bypass",
    "status:merged+message:permission+message:check+message:security",
    "status:merged+message:download+message:bypass",
    "status:merged+message:incognito+message:bypass",
    "status:merged+message:security+message:insufficient",
    "status:merged+message:sandbox+message:bypass",
]

MAX_PER_QUERY = 25


def gerrit_get(path: str) -> str:
    url = f"{GERRIT}{path}"
    proxy_handler = urllib.request.ProxyHandler({"https": PROXY, "http": PROXY})
    opener = urllib.request.build_opener(proxy_handler)
    req = urllib.request.Request(url)
    try:
        resp = opener.open(req, timeout=30)
        raw = resp.read().decode("utf-8")
        # Strip Gerrit XSSI prefix
        if raw.startswith(")]}'"):
            raw = raw[4:].lstrip("\n")
        return raw
    except urllib.error.HTTPError as e:
        print(f"  HTTP {e.code} for {url}", file=sys.stderr)
        return ""
    except Exception as e:
        print(f"  Error fetching {url}: {e}", file=sys.stderr)
        return ""


def fetch_changes(query: str, n: int = MAX_PER_QUERY) -> list:
    path = f"/changes/?q={query}&n={n}&o=CURRENT_REVISION"
    raw = gerrit_get(path)
    if not raw:
        return []
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        print(f"  JSON decode error for query: {query}", file=sys.stderr)
        return []


def fetch_patch(change_number: int, revision_id: str) -> str:
    path = f"/changes/{change_number}/revisions/{revision_id}/patch"
    raw = gerrit_get(path)
    if not raw:
        return ""
    try:
        return base64.b64decode(raw).decode("utf-8", errors="replace")
    except Exception:
        return ""


def fetch_files(change_number: int, revision_id: str) -> dict:
    path = f"/changes/{change_number}/revisions/{revision_id}/files/"
    raw = gerrit_get(path)
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {}


def main():
    os.makedirs(DIFFS_DIR, exist_ok=True)

    seen_cls = set()
    total_fetched = 0

    for query in QUERIES:
        print(f"\n--- Query: {query}")
        changes = fetch_changes(query)
        print(f"  Found {len(changes)} CLs")

        for cl in changes:
            cl_num = cl.get("_number")
            if not cl_num or cl_num in seen_cls:
                continue
            seen_cls.add(cl_num)

            subject = cl.get("subject", "")
            project = cl.get("project", "")
            revisions = cl.get("revisions", {})

            if not revisions:
                continue

            rev_id = list(revisions.keys())[0]
            print(f"  CL {cl_num}: {subject[:80]}")

            patch = fetch_patch(cl_num, rev_id)
            if not patch:
                print(f"    (no patch)")
                continue

            files = fetch_files(cl_num, rev_id)
            file_list = [f for f in files.keys() if f != "/COMMIT_MSG"]

            # Classify by component
            component = "other"
            for f in file_list:
                if "content/browser/" in f:
                    component = "content_browser"
                    break
                elif "chrome/browser/" in f:
                    component = "chrome_browser"
                    break
                elif "components/" in f:
                    component = "components"
                    break
                elif "front_end/" in f or "devtools" in f.lower():
                    component = "devtools"
                    break
                elif "third_party/blink/" in f:
                    component = "blink"
                    break
                elif "extensions/" in f:
                    component = "extensions"
                    break

            outpath = os.path.join(DIFFS_DIR, f"CL_{cl_num}_{component}.patch")
            with open(outpath, "w") as f:
                f.write(f"# CL: {cl_num}\n")
                f.write(f"# Subject: {subject}\n")
                f.write(f"# Project: {project}\n")
                f.write(f"# Component: {component}\n")
                f.write(f"# Files: {', '.join(file_list[:10])}\n")
                f.write(f"# Query: {query}\n")
                f.write("#" + "=" * 79 + "\n\n")
                f.write(patch)

            total_fetched += 1
            time.sleep(0.5)

    print(f"\n=== Done: {total_fetched} unique CLs fetched to {DIFFS_DIR}")

    # Summary
    summary_path = os.path.join(DIFFS_DIR, "_summary.md")
    with open(summary_path, "w") as f:
        f.write("# Fetched Security Fix CLs\n\n")
        f.write(f"Total: {total_fetched} unique CLs\n\n")
        f.write("| CL | Component | Subject |\n")
        f.write("|----|-----------|---------|\n")
        for fname in sorted(os.listdir(DIFFS_DIR)):
            if not fname.endswith(".patch"):
                continue
            fpath = os.path.join(DIFFS_DIR, fname)
            with open(fpath) as pf:
                lines = pf.readlines()[:5]
            cl_num = ""
            subject = ""
            comp = ""
            for line in lines:
                if line.startswith("# CL:"):
                    cl_num = line.split(":", 1)[1].strip()
                elif line.startswith("# Subject:"):
                    subject = line.split(":", 1)[1].strip()[:80]
                elif line.startswith("# Component:"):
                    comp = line.split(":", 1)[1].strip()
            f.write(f"| {cl_num} | {comp} | {subject} |\n")

    print(f"Summary written to {summary_path}")


if __name__ == "__main__":
    main()
