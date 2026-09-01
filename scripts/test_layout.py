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
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_upstream import is_newer, pick_max  # noqa: E402
from manifest import ARCHES, load_tools, outputs  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOC_EXT = (".md", ".txt", ".conf", ".json", ".yaml", ".yml")

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
    test_arm_same_expands()
    test_version_ordering()

    for f in failures:
        print(f"FAIL {f}", file=sys.stderr)
    print(f"{'FAILED' if failures else 'OK'}: {len(failures)} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
