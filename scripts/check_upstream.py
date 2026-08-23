#!/usr/bin/env python3
"""Check upstream releases for every tool in tools.yaml.

Usage: yq -o=json '.tools' tools.yaml | ./scripts/check_upstream.py [--out outdated.json] [--all]

Reads the tool list as JSON on stdin (rendered from tools.yaml with mikefarah/yq),
queries each upstream for its newest version and prints a report. Writes the
outdated set as JSON to --out (or stdout with --json) for downstream automation.

GitHub API calls use GITHUB_TOKEN when set to avoid rate limits.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

GH_API = "https://api.github.com"
UA = "binary-tools-upstream-checker/1.0"


def gh_get(path):
    req = urllib.request.Request(GH_API + path, headers={
        "User-Agent": UA,
        "Accept": "application/vnd.github+json",
    })
    tok = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if tok:
        req.add_header("Authorization", f"Bearer {tok}")
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def http_get(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode("utf-8", "replace")


def version_key(v):
    """Sort key tolerant of mixed versions: 1.7 < 1.10, 4.5.0, 20240606."""
    parts = re.split(r"[._\-+~]", v.lstrip("v"))
    key = []
    for p in parts:
        if p.isdigit():
            key.append((0, int(p)))
        elif p == "":
            continue
        else:
            m = re.match(r"(\d+)(.*)", p)
            if m:
                key.append((0, int(m.group(1))))
                key.append((1, m.group(2)))
            else:
                key.append((1, p))
    return key


def pick_max(candidates):
    if not candidates:
        return None
    return sorted(candidates, key=lambda c: (version_key(c), c))[-1]


def strip_prefix(tag, prefix=None):
    if prefix:
        return tag[len(prefix):] if tag.startswith(prefix) else tag
    return re.sub(r"^v", "", tag)


def extract_version(tag, t):
    """Apply optional regex filter and prefix stripping to a raw tag name."""
    pat = t.get("pattern")
    if pat:
        m = re.match(pat, tag)
        if not m:
            return None
        if len(m.groups()) == 1:
            return m.group(1)
        ver = re.sub(r"^v", "", m.group(0))
        pref = t.get("prefix")
        if pref and ver.startswith(pref):
            ver = ver[len(pref):]
        return ver
    return strip_prefix(tag, t.get("prefix"))


def is_stable(v):
    return "-" not in v


def check_github_release(t):
    d = gh_get(f"/repos/{t['slug']}/releases/latest")
    return strip_prefix(d["tag_name"], t.get("prefix"))


def check_github_tag(t):
    names, page = [], 1
    while page <= 3:
        tags = gh_get(f"/repos/{t['slug']}/tags?per_page=100&page={page}")
        if not tags:
            break
        names += [x["name"] for x in tags]
        if len(tags) < 100:
            break
        page += 1
    vers = [extract_version(n, t) for n in names]
    vers = [v for v in vers if v]
    if t.get("transform") == "underscore_to_dot":
        vers = [v.replace("_", ".") for v in vers]
    if t.get("stable_only", True):
        vers = [v for v in vers if is_stable(v)]
    return pick_max(vers)


def check_git_remote(t):
    out = subprocess.run(
        ["git", "ls-remote", "--tags", t["remote"]],
        capture_output=True, text=True, timeout=180,
    )
    if out.returncode != 0:
        raise RuntimeError(out.stderr.strip()[:200])
    names = []
    for line in out.stdout.splitlines():
        ref = line.split("\t", 1)[-1]
        ref = re.sub(r"\^\{\}$", "", ref)
        m = re.match(r"refs/tags/(.+)$", ref)
        if not m:
            continue
        names.append(m.group(1))
    vers = [extract_version(n, t) for n in names]
    vers = [v for v in vers if v]
    if t.get("stable_only", True):
        vers = [v for v in vers if is_stable(v)]
    return pick_max(vers)


def check_url(t):
    body = http_get(t["url"])
    found = [m.group(1) for m in re.finditer(t["pattern"], body)]
    ver = pick_max(found)
    if ver is None:
        raise RuntimeError(f"no match for {t['pattern']}")
    if t.get("follow"):
        url2 = t["follow"].replace("{v0}", ver)
        body2 = http_get(url2)
        found2 = [m.group(1) for m in re.finditer(t["pattern2"], body2)]
        ver2 = pick_max(found2)
        if ver2:
            ver = ver2
    if t.get("transform") == "underscore_to_dot":
        ver = ver.replace("_", ".")
    return ver


def check_sourceforge(t):
    d = json.loads(http_get(
        f"https://sourceforge.net/projects/{t['project']}/best_release.json"))
    rel = d.get("release") or d.get("best_release", {}).get("release") or {}
    if rel.get("version"):
        return rel["version"]
    fn = rel.get("filename", "")
    m = re.search(r"/v?(\d[\d.]*)/", fn)
    return m.group(1) if m else None


CHECKERS = {
    "github-release": check_github_release,
    "github-tag": check_github_tag,
    "git-remote": check_git_remote,
    "url": check_url,
    "sourceforge": check_sourceforge,
}


def check_one(t):
    name = t["name"]
    ctype = t["check"]["type"]
    if ctype == "pinned":
        return name, None, "pinned"
    if not t.get("enabled", True):
        return name, None, "disabled"
    fn = CHECKERS.get(ctype)
    if fn is None:
        return name, None, f"unknown check type {ctype}"
    try:
        latest = fn(t["check"])
    except Exception as e:  # noqa: BLE001 - report everything, fail soft
        return name, None, f"error: {e}"
    if not latest:
        return name, t.get("version"), "error: no version found upstream"
    cur = t.get("version", "")
    status = "outdated" if version_key(latest) != version_key(cur) else "ok"
    return name, latest, status


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", help="write outdated JSON here")
    ap.add_argument("--json", action="store_true", help="print full JSON report")
    ap.add_argument("--all", action="store_true", help="also list up-to-date tools")
    args = ap.parse_args()

    tools = json.load(sys.stdin)
    results = {}
    with ThreadPoolExecutor(max_workers=12) as ex:
        futs = {ex.submit(check_one, t): t for t in tools}
        for fut in as_completed(futs):
            name, latest, status = fut.result()
            results[name] = {"latest": latest, "status": status}
            mark = {"outdated": "!!", "ok": "  ", "pinned": "--",
                    "disabled": "--"}.get(status.split(":")[0], "??")
            line = f"{mark} {name:<22} shipped={str(tools_next(name, tools)):<14}"
            if latest:
                line += f"latest={latest}"
            if args.all or status.startswith(("outdated", "error")):
                print(line + ("" if status == "outdated" else f"   [{status}]"),
                      file=sys.stderr)

    outdated = [
        {"name": n, "current": next(t["version"] for t in tools if t["name"] == n),
         "latest": r["latest"]}
        for n, r in sorted(results.items()) if r["status"].startswith("outdated")
    ]
    errors = [{"name": n, "error": r["status"]} for n, r in sorted(results.items())
              if r["status"].startswith("error")]
    report = {"outdated": outdated, "errors": errors,
              "checked": sum(1 for r in results.values()
                             if not r["status"].startswith(("pinned", "disabled")))}

    payload = json.dumps(report, indent=2)
    if args.out:
        with open(args.out, "w") as f:
            f.write(payload)
    if args.json or not args.out:
        print(payload)


def tools_next(name, tools):
    return next(t["version"] for t in tools if t["name"] == name)


if __name__ == "__main__":
    main()
