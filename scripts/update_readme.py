#!/usr/bin/env python3
"""Update README.md version/SHA256 columns for bumped tools.

usage: update_readme.py NAME=NEWVER [NAME=NEWVER ...]
       update_readme.py --sync            (re-derive every row from the repo)

A tool that starts shipping an ARM binary gets a row created for it in the ARM
table, copied from its x64 row and inserted alphabetically. Without that a new
`arm_outputs` ships a binary no table ever mentions.

Rewrites a tool's version and SHA256 cells from tools.yaml and the binary as it
landed in the repo, per section: the x64 table gets the x64 hash, the ARM table
the ARM one. Version column keeps its original width so tables stay aligned.

Rows are matched on the exact filename cell. Substring matching used to be
enough until it wasn't: "strace" is inside "dnstrace", "tiny" inside
"tinyproxy", "vi" inside "vim", "wg" inside "wg-go", "rg" inside "rargs" -- each
of those wrote one tool's version and hash into another tool's row.
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
    "zmap": "zmap/*", "dnspot": "dnspot/*", "sshx": "sshx/server",
    "httptunnel_client": "httptunnel-*", "jj": "jj", "q": "q", "nc": "nc",
    "dnstt_client": "dnstt_*",
}


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def cell_for(name):
    return FILENAME_CELL.get(name, name)


def cell_owners(tools=None):
    """filename cell -> tool name. One tool per cell, checked by test_layout."""
    return {cell_for(t["name"]): t["name"] for t in (tools or load_tools())}


def sha_of(root, name, arch):
    """SHA256 of the shipped binary for one arch, read from the repo.

    The ARM table used to be filled with x64 hashes: every row was hashed from
    outputs[0] regardless of which section it sat in.
    """
    outs = next((outputs(t, arch) for t in load_tools() if t["name"] == name), [])
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


def _cells(line):
    """The five raw cells of a table row, padding included."""
    return line.split("|")[1:6]


def _fit(text, width):
    return f" {text} ".ljust(width)[:max(width, len(text) + 2)]


def arm_row(x64_line, arm_lines, ver, sha):
    """An ARM row for a tool that has only an x64 one, in the ARM table's shape."""
    src = _cells(x64_line)
    widths = [len(c) for c in _cells(arm_lines[0])]
    cells = [src[0], f" {ver} ", src[2], src[3], f" `{sha}` "]
    return "|" + "|".join(_fit(c.strip(), w) for c, w in zip(cells, widths)) + "|"


def insert_arm_rows(lines, additions):
    """Insert new ARM rows alphabetically by software label."""
    arm_idx = [i for i, l in enumerate(lines) if ROW.match(l)
               and i > next(j for j, x in enumerate(lines)
                            if x.startswith("# Filename map (ARM5)"))]
    for line in additions:
        label = re.match(r"^\|\s*\[([^\]]+)\]", line).group(1).lower()
        at = arm_idx[-1] + 1
        for i in arm_idx:
            other = re.match(r"^\|\s*\[([^\]]+)\]", lines[i]).group(1).lower()
            if other > label:
                at = i
                break
        lines.insert(at, line)
        arm_idx = [i if i < at else i + 1 for i in arm_idx] + [at]
        arm_idx.sort()
    return lines


def main():
    tools = load_tools()
    if sys.argv[1:2] == ["--sync"]:
        bumps = {t["name"]: t["version"] for t in tools}
    else:
        bumps = {}
        for arg in sys.argv[1:]:
            name, _, ver = arg.partition("=")
            bumps[name] = ver
    owners = cell_owners(tools)

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
        name = owners.get(m.group("fn").strip("`"))
        if name is None or name not in bumps:
            continue
        ver = bumps[name]
        sha = sha_of(ROOT, name, section)
        parts = line.split("|")
        # parts: '', sw, ver, fn, cat, sha, ''
        # keep the original cell width when the new version fits; a longer
        # one just grows the row (markdown tolerates ragged tables)
        parts[2] = f" {ver} ".ljust(len(parts[2]))
        if sha:
            parts[5] = f" `{sha}` "
        lines[i] = "|".join(parts)
        changed.append((section, name, ver, bool(sha)))

    # a tool that just started shipping ARM has no row to update yet
    have_arm = {name for sec, name, _, _ in changed if sec == "arm"}
    x64_line = {}
    for line in lines:                       # x64 table comes first, so its row wins
        m = ROW.match(line)
        name = owners.get(m.group("fn").strip("`")) if m else None
        if name:
            x64_line.setdefault(name, line)
    arm_lines = [l for l in lines[next(i for i, x in enumerate(lines)
                 if x.startswith("# Filename map (ARM5)")):] if ROW.match(l)]
    additions = []
    for name, ver in bumps.items():
        if name in have_arm or name not in x64_line:
            continue
        sha = sha_of(ROOT, name, "arm")
        if not sha:
            continue
        additions.append(arm_row(x64_line[name], arm_lines, ver, sha))
        changed.append(("arm", name, ver, True))
    if additions:
        lines = insert_arm_rows(lines, additions)

    open(path, "w").write("\n".join(lines))
    for sec, name, ver, hashed in changed:
        print(f"{sec}: {name} -> {ver} sha={'updated' if hashed else 'KEPT (binary missing)'}")

    # a bump that matched no row is a silent no-op otherwise
    for name in bumps:
        if not any(c[1] == name for c in changed):
            print(f"WARNING: {name} matched no README row (cell "
                  f"'{cell_for(name)}')", file=sys.stderr)


if __name__ == "__main__":
    main()
