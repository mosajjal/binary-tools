#!/usr/bin/env python3
"""Update README.md version/SHA256 columns for bumped tools.

usage: update_readme.py <dist-root> NAME=NEWVER [NAME=NEWVER ...]

Reads artifact hashes from <dist-root>/bt-<name>/x64/<first-output> and rewrites
the matching table row(s). Version column is padded to its original width so
the tables stay aligned.
"""
import hashlib
import os
import re
import sys

sys.path.insert(0, os.path.dirname(__file__))
from manifest import load_tools, first_bin  # noqa: E402

ROW = re.compile(
    r"^(?P<pre>\|\s*\[[^\]]+\]\([^)]*\)\s*\|)\s*(?P<ver>[^|]+?)\s*\|"
    r"\s*(?P<fn>`[^`]+`)\s*\|\s*(?P<cat>[^|]+)\|\s*`(?P<sha>[0-9a-f]{64})`\s*\|\s*$")

# tool id -> text expected inside the README `filename` cell
FILENAME_CELL = {
    "dh": "dh", "hx": "hx", "frp": "frpc/frps", "pueue": "pueue(d)",
    "iodine": "iodine(d)", "nmap": "nmap, nping", "tor": "tor/*",
    "dropbear": "dropbear/*", "netsniff": "netsniff/*", "wireshark": "wireshark/*",
    "zmap": "zmap/*", "dnspot": "dnspot/*", "sshx": "sshx", "httptunnel_client":
    "httptunnel-*", "jj": "jj", "q": "`q`", "nc": "nc",
}


def cell_for(name):
    return FILENAME_CELL.get(name, name)


def sha_of(dist_root, name):
    d = os.path.join(dist_root, f"bt-{name}", "x64")
    binname = None
    for t in load_tools():
        if t["name"] == name:
            outs = t.get("outputs") or []
            bins = [(o["bin"] if isinstance(o, dict) else o) for o in outs]
            binname = first_bin(t)
            break
    if not binname:
        return None
    p = os.path.join(d, binname)
    if not os.path.exists(p):
        return None
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    dist_root = sys.argv[1]
    bumps = {}
    for arg in sys.argv[2:]:
        name, _, ver = arg.partition("=")
        bumps[name] = ver

    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "README.md")
    lines = open(path).read().split("\n")

    # which table section each line belongs to
    section = None
    changed = []
    for i, line in enumerate(lines):
        if line.startswith("# Filename map (x64)"):
            section = "x64"
        elif line.startswith("# Filename map (ARM5)"):
            section = "arm"
        m = ROW.match(line)
        if not m or section is None:
            continue
        fn = m.group("fn")
        for name, ver in bumps.items():
            if f"`{cell_for(name)}`" != fn and cell_for(name) not in fn.strip("`"):
                continue
            sha = sha_of(dist_root, name)
            new_ver = f" {ver} "
            old = m.group("ver")
            pad = len(old) - len(new_ver)
            if pad > 0:
                new_ver = f" {ver} ".ljust(len(old))
            elif pad < 0:
                pass  # let the row grow; markdown tolerates it
            nl = (f"{m.group('pre')}{new_ver}|"
                  f"{line.split('|')[3].join(['|',''])}"  # placeholder, rebuilt below
                  )
            # rebuild row explicitly to avoid column juggling bugs
            parts = line.split("|")
            # parts: '', sw, ver, fn, cat, sha, ''
            parts[2] = new_ver.rstrip() if False else f" {new_ver.strip()} "
            if sha:
                parts[5] = f" `{sha}` "
            lines[i] = "|".join(parts)
            changed.append((section, name, ver, bool(sha)))
            break

    open(path, "w").write("\n".join(lines))
    for sec, name, ver, hashed in changed:
        print(f"{sec}: {name} -> {ver} sha={'updated' if hashed else 'KEPT (artifact missing)'}")


if __name__ == "__main__":
    main()
