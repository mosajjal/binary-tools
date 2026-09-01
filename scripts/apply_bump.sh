#!/usr/bin/env bash
# Assemble an upstream-bump working tree from built artifacts.
#
# usage: scripts/apply_bump.sh <outdated.json> <dist-root> [bumped.json]
#
# For every outdated tool with artifacts under <dist-root>/bt-<tool>/:
#   - copies binaries to the paths tools.yaml declares (outputs[].dst)
#   - bumps `version` in tools.yaml
#   - records the bump in bumped.json (only tools that actually built+tested)
# Then regenerates README rows via scripts/update_readme.py.
set -euo pipefail

OUTDATED=${1:?usage: apply_bump.sh outdated.json dist-root [bumped.json]}
DIST=${2:?usage: apply_bump.sh outdated.json dist-root [bumped.json]}
BUMPED_OUT=${3:-bumped.json}
YQ=$(command -v yq || echo /opt/toolbelt/yq)
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

# Destinations come from tools.yaml alone. They used to be searched for with
# `git ls-files "x64/**/$BIN" "x64/$BIN"`, but the second pathspec matches a
# whole directory: for BIN=tor git listed x64/tor/README.md first and the tor
# binary was committed on top of its own documentation.
dests() {
    python3 "$ROOT/scripts/manifest.py" dests "$1" "$2"
}

is_elf() {
    [ "$(head -c 4 "$1" | od -An -tx1 | tr -d ' \n')" = "7f454c46" ]
}

# Copy one arch's built binaries into the repo, refusing to overwrite anything
# that is not already a binary.
install_arch() {
    local tool=$1 arch=$2 srcdir=$3 bin dest
    while read -r bin dest; do
        [ -n "$bin" ] || continue
        [ -f "$srcdir/$bin" ] || continue
        if [ -e "$dest" ] && ! is_elf "$dest"; then
            echo "  $tool: $dest is not a binary; refusing to overwrite"
            return 1
        fi
        mkdir -p "$(dirname "$dest")"
        cp "$srcdir/$bin" "$dest"
        chmod +x "$dest"
        cmp -s "$srcdir/$bin" "$dest" || { echo "  $tool: $dest did not land"; return 1; }
        echo "  $tool($arch): $bin -> $dest"
    done <<< "$(dests "$tool" "$arch")"
}

N=$($YQ -r '.outdated | length' "$OUTDATED")
echo "bumping $N tools"

BUMPED=""
BUMPED_JSON="[]"
i=0
while [ $i -lt $N ]; do
    TOOL=$($YQ -r ".outdated[$i].name" "$OUTDATED")
    LATEST=$($YQ -r ".outdated[$i].latest" "$OUTDATED")
    i=$((i+1))

    XDIR="$DIST/bt-$TOOL/x64"
    ADIR="$DIST/bt-$TOOL/arm"
    [ -d "$XDIR" ] || { echo "skip $TOOL (no artifacts)"; continue; }

    # verify every declared output actually built before touching the repo
    MISSING=0
    for BIN in $(dests "$TOOL" x64 | cut -d" " -f1); do
        [ -f "$XDIR/$BIN" ] || { echo "  $TOOL: missing output $BIN; skipping"; MISSING=1; }
    done
    [ $MISSING = 0 ] || continue

    install_arch "$TOOL" x64 "$XDIR" || continue
    if [ -d "$ADIR" ] && compgen -G "$ADIR/*" > /dev/null; then
        install_arch "$TOOL" arm "$ADIR" || continue
    fi

    CURRENT=$($YQ -r ".tools[] | select(.name == \"$TOOL\") | .version" tools.yaml)
    $YQ -i "(.tools[] | select(.name == \"$TOOL\") | .version) = \"$LATEST\"" tools.yaml
    BUMPED="$BUMPED $TOOL=$LATEST"
    BUMPED_JSON=$(jq --arg n "$TOOL" --arg c "$CURRENT" --arg l "$LATEST" \
        '. + [{name: $n, current: $c, latest: $l}]' <<<"$BUMPED_JSON")
done

if [ -n "$BUMPED" ]; then
    # BUMPED is a space-separated NAME=VER list; word splitting is intended
    # shellcheck disable=SC2086
    python3 scripts/update_readme.py $BUMPED
fi

echo "$BUMPED_JSON" > "$BUMPED_OUT"
echo "apply_bump done:$BUMPED"
