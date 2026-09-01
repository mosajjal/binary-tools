"""Tiny helper to read tools.yaml without a YAML dependency.

Uses mikefarah/yq (present on dev machines and installed in CI) to convert the
manifest to JSON, then loads it.
"""
import json
import os
import subprocess
import shutil
import sys


def _yq():
    yq = shutil.which("yq") or "/opt/toolbelt/yq"
    if not os.path.exists(yq):
        raise SystemExit("mikefarah/yq v4 is required (binary named 'yq')")
    return yq


def load_tools(root=None):
    root = root or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    manifest = os.path.join(root, "tools.yaml")
    out = subprocess.run(
        [_yq(), "-o=json", ".tools", manifest],
        capture_output=True, text=True, check=True)
    return json.loads(out.stdout)


def tool_by_name(name, tools=None):
    for t in tools or load_tools():
        if t["name"] == name:
            return t
    raise KeyError(name)


ARCHES = ("x64", "arm")


def _entries(t, arch):
    """Raw `outputs` / `arm_outputs` list. `same` mirrors the x64 outputs."""
    outs = t.get("arm_outputs") if arch == "arm" else t.get("outputs")
    if outs in ("same", ["same"]):
        outs = t.get("outputs")
    return outs or []


def outputs(t, arch="x64"):
    """[(bin, dest)] for one arch, dest relative to the repo root.

    The destination is read from the manifest and never searched for in the
    tree: `git ls-files "x64/tor"` matches every file under x64/tor/, README
    included, which is how a tor binary once landed on top of its own docs.
    """
    entries = _entries(t, arch)
    bins = [(e["bin"] if isinstance(e, dict) else e) for e in entries]
    flat = len(bins) == 1 and bins[0] == t["name"]

    resolved = []
    for entry, b in zip(entries, bins):
        dst = entry.get("dst") if isinstance(entry, dict) else None
        resolved.append((b, f"{arch}/{dst or (b if flat else t['name'] + '/' + b)}"))
    return resolved


def output_bins(t):
    return [b for b, _ in outputs(t, "x64")]


def arm_bins(t):
    return [b for b, _ in outputs(t, "arm")]


def _cli():
    """`manifest.py dests <tool> <arch>` -> one "<bin> <path>" line per output."""
    if len(sys.argv) != 4 or sys.argv[1] != "dests":
        raise SystemExit("usage: manifest.py dests <tool> <arch>")
    for b, dest in outputs(tool_by_name(sys.argv[2]), sys.argv[3]):
        print(f"{b} {dest}")


if __name__ == "__main__":
    _cli()
