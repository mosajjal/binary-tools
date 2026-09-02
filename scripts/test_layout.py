#!/usr/bin/env python3
"""Regression tests for manifest path resolution and version ordering.

usage: python3 scripts/test_layout.py    (also a lint-buildfiles CI step)

Guards the two defects that shipped in the 2026-08-31 bump PR:
  1. apply_bump.sh guessed a binary's destination with
     `git ls-files "x64/**/$BIN" "x64/$BIN"`. The second pathspec matches a
     whole directory, so for BIN=tor git returned x64/tor/README.md first and
     the tor binary was written over the docs. Destinations now come from
     tools.yaml only.
  2. check_upstream treated any version difference as "outdated", so an
     upstream release older than the shipped one (dnstrace 1.4.3 -> 1.4.0)
     was published as a bump.
"""
import hashlib
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_upstream import is_newer, pick_max  # noqa: E402
from manifest import ARCHES, load_tools, outputs  # noqa: E402
from update_readme import ROW, cell_for, cell_owners  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOC_EXT = (".md", ".txt", ".conf", ".json", ".yaml", ".yml")

# tools with no row of their own: pt_bridges ships inside the tor/* row, tangd
# is ARM-only
NO_README_ROW = {"pt_bridges", "tangd"}

failures = []


def check(cond, msg):
    if not cond:
        failures.append(msg)


def tracked():
    out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True,
                         text=True, check=True).stdout.split()
    files = set(out)
    dirs = {d for f in files for d in _parents(f)}
    return files, dirs


def _parents(path):
    parts = path.split("/")[:-1]
    return ["/".join(parts[:i + 1]) for i in range(len(parts))]


def test_destinations(files, dirs):
    """Every declared output maps to a binary path, never a doc or a directory."""
    for t in load_tools():
        for arch in ARCHES:
            for binname, dest in outputs(t, arch):
                where = f"{t['name']}/{arch}/{binname}"
                check(not dest.endswith(DOC_EXT),
                      f"{where}: destination {dest} is a doc file")
                check(dest not in dirs,
                      f"{where}: destination {dest} is a directory; set an "
                      f"explicit dst in tools.yaml")
                if dest in files:
                    check(_is_elf(dest), f"{where}: {dest} is tracked but not ELF")


def test_no_relocation(files):
    """A bump must overwrite the shipped binary, not create a second copy."""
    for t in load_tools():
        for arch in ARCHES:
            declared = {d for _, d in outputs(t, arch)}
            for binname, dest in outputs(t, arch):
                shipped = [f for f in files
                           if f.startswith(f"{arch}/") and os.path.basename(f) == binname]
                if not shipped or dest in files:
                    continue
                check(set(shipped) & declared,
                      f"{t['name']}/{arch}/{binname}: manifest says {dest} but "
                      f"the repo ships {shipped}")


def test_clobbered_docs(files):
    """The exact files the bad PR overwrote."""
    for doc in ("x64/tor/README.md", "x64/zmap/README.md"):
        check(doc in files, f"{doc} missing from the repo")
        check(not _is_elf(doc), f"{doc} is a binary, not documentation")


def test_smoke_cmd_targets_own_binary():
    """A test_cmd must exercise the tool it belongs to.

    superfile carried a copy of suricata's command. Nothing failed: the shell's
    own "/out/x64/suricata: not found" went through `2>&1` into
    `grep -qiE "Suricata|build-info"`, which matched the path in that very
    message -- so the tool shipped for months with no smoke test at all.
    """
    for t in load_tools():
        cmd = t.get("test_cmd")
        if not cmd:
            continue
        mine = {b for b, _ in outputs(t, "x64")} | {b for b, _ in outputs(t, "arm")}
        for ref in re.findall(r"/out/x64/([\w.-]+)", cmd):
            check(ref in mine,
                  f"{t['name']}: test_cmd runs /out/x64/{ref}, not one of {sorted(mine)}")


def test_readme_rows_resolve():
    """Each tool owns one README row per section, matched on the exact cell.

    Substring matching put strace's version in dnstrace's row, tiny's in
    tinyproxy's, vi's in vim's, wg's in wg-go's and rg's in rargs'.
    """
    owners = cell_owners()
    names = [t["name"] for t in load_tools()]
    check(len(owners) == len(names),
          f"two tools share a README cell: "
          f"{sorted(set(names) - set(owners.values()))}")

    seen = {}
    section = None
    for line in open(os.path.join(ROOT, "README.md")):
        if line.startswith("# Filename map (x64)"):
            section = "x64"
        elif line.startswith("# Filename map (ARM5)"):
            section = "arm"
        m = ROW.match(line.rstrip("\n"))
        if not m or section is None:
            continue
        name = owners.get(m.group("fn").strip("`"))
        if name is None:
            continue
        key = (section, name)
        check(key not in seen, f"{name}: two {section} rows in README.md")
        seen[key] = True

    for name in names:
        if name in NO_README_ROW:
            continue
        check(("x64", name) in seen,
              f"{name}: cell '{cell_for(name)}' resolves to no x64 row, so a "
              f"bump would silently leave its version and hash stale")


def test_readme_matches_binaries():
    """Both tables must describe the binaries actually in the repo.

    The published SHA256 is the only thing a user can check a download
    against, and the x64 table drifted 39 hashes out of date before anyone
    noticed.
    """
    owners = cell_owners()
    tools = {t["name"]: t for t in load_tools()}
    section = None
    for line in open(os.path.join(ROOT, "README.md")):
        if line.startswith("# Filename map (x64)"):
            section = "x64"
        elif line.startswith("# Filename map (ARM5)"):
            section = "arm"
        m = ROW.match(line.rstrip("\n"))
        if not m or section is None:
            continue
        name = owners.get(m.group("fn").strip("`"))
        if name is None:
            continue
        outs = outputs(tools[name], section)
        if not outs:
            continue
        path = os.path.join(ROOT, outs[0][1])
        if not os.path.exists(path):
            check(False, f"{section} {name}: README row but no {outs[0][1]}")
            continue
        with open(path, "rb") as f:
            sha = hashlib.sha256(f.read()).hexdigest()
        check(m.group("sha") == sha,
              f"{section} {name}: README sha does not match {outs[0][1]}")
        check(m.group("ver").strip() == tools[name]["version"],
              f"{section} {name}: README says {m.group('ver').strip()}, "
              f"tools.yaml says {tools[name]['version']}")


def test_arm_same_expands():
    """`arm_outputs: same` is a scalar in tools.yaml; splitting it yields s,a,m,e."""
    for t in load_tools():
        if t.get("arm_outputs") != "same":
            continue
        arm = [b for b, _ in outputs(t, "arm")]
        check(arm == [b for b, _ in outputs(t, "x64")],
              f"{t['name']}: arm_outputs 'same' expanded to {arm}")
        return
    check(False, "no tool uses `arm_outputs: same`; test is stale")


def test_version_ordering():
    check(is_newer("1.4.3", "1.4.0"), "1.4.3 should be newer than 1.4.0")
    check(not is_newer("1.4.0", "1.4.3"), "dnstrace downgrade 1.4.3 -> 1.4.0")
    check(not is_newer("1.8.2", "1.8.2"), "equal versions are not newer")
    check(is_newer("1.10", "1.7"), "1.10 should be newer than 1.7")
    check(is_newer("v2.13.0", "2.8.1"), "leading v must not break ordering")
    check(not is_newer("0.4.10", "e5b49ef"),
          "a tagged release is not comparable to a shipped commit sha")
    # a delimited suffix is a prerelease (older); one glued to a digit is a
    # patch letter (newer): 1.0.0 > 1.0.0-alpha, but tmux 3.7c > 3.7
    check(is_newer("1.0.0", "1.0.0-alpha"), "1.0.0 is newer than 1.0.0-alpha")
    check(not is_newer("1.0.0-alpha", "1.0.0"), "1.0.0-alpha is not a bump")
    check(is_newer("3.7c", "3.7"), "3.7c is newer than 3.7")
    check(is_newer("1.8.2", "1.8.2-rc1"), "release beats its own rc")
    check(pick_max(["1.0.0", "1.0.0-rc1", "0.9.9"]) == "1.0.0",
          "pick_max must not choose a prerelease over its release")


def _is_elf(path):
    with open(os.path.join(ROOT, path), "rb") as f:
        return f.read(4) == b"\x7fELF"


def main():
    files, dirs = tracked()
    test_destinations(files, dirs)
    test_no_relocation(files)
    test_clobbered_docs(files)
    test_smoke_cmd_targets_own_binary()
    test_readme_rows_resolve()
    test_readme_matches_binaries()
    test_arm_same_expands()
    test_version_ordering()

    for f in failures:
        print(f"FAIL {f}", file=sys.stderr)
    print(f"{'FAILED' if failures else 'OK'}: {len(failures)} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
