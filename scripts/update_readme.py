#!/usr/bin/env python3
"""Update README.md version/SHA256 columns for bumped tools.

usage: update_readme.py NAME=NEWVER [NAME=NEWVER ...]

Hashes the binary as it landed in the repo (outputs[0].dst) and rewrites the
matching table row(s), so the published SHA256 always describes the file a user
downloads. Version column is padded to its original width so tables stay aligned.
"""
import hashlib
import os
import re
import sys

sys.path.insert(0, os.path.dirname(__file__))
from manifest import load_tools, outputs  # noqa: E402

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


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def cell_for(name):
    return FILENAME_CELL.get(name, name)


def sha_of(root, name):
    """SHA256 of the shipped binary, read from the repo rather than from dist/."""
    outs = next((outputs(t) for t in load_tools() if t["name"] == name), [])
    if not outs:
        return None
    p = os.path.join(root, outs[0][1])
    if not os.path.exists(p):
        return None
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    bumps = {}
    for arg in sys.argv[1:]:
        name, _, ver = arg.partition("=")
        bumps[name] = ver

    path = os.path.join(ROOT, "README.md")
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
            sha = sha_of(ROOT, name)
            parts = line.split("|")
            # parts: '', sw, ver, fn, cat, sha, ''
            # keep the original cell width when the new version fits; a longer
            # one just grows the row (markdown tolerates ragged tables)
            parts[2] = f" {ver} ".ljust(len(parts[2]))
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
