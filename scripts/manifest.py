"""Tiny helper to read tools.yaml without a YAML dependency.

Uses mikefarah/yq (present on dev machines and installed in CI) to convert the
manifest to JSON, then loads it.
"""
import json
import os
import subprocess
import shutil


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


def output_bins(t):
    outs = t.get("outputs") or []
    return [(o["bin"] if isinstance(o, dict) else o) for o in outs]


def arm_bins(t):
    outs = t.get("arm_outputs") or []
    if outs == ["same"]:
        return output_bins(t)
    return [(o["bin"] if isinstance(o, dict) else o) for o in outs]


def first_bin(t):
    bins = output_bins(t)
    return bins[0] if bins else None
