#!/usr/bin/env bash
# Assemble an upstream-bump working tree from built artifacts.
#
# usage: scripts/apply_bump.sh <outdated.json> <dist-root> [bumped.json]
#
# For every outdated tool with artifacts under <dist-root>/bt-<tool>/:
#   - copies binaries into their existing repo locations (found via git ls-files,
#     falling back to x64/<bin> / arm/<bin> for new files)
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
    for BIN in $($YQ -r ".tools[] | select(.name == \"$TOOL\") | .outputs | map(.bin // .) | join(\" \")" tools.yaml); do
        [ -f "$XDIR/$BIN" ] || { echo "  $TOOL: missing output $BIN; skipping"; MISSING=1; }
    done
    [ $MISSING = 0 ] || continue

    # x64 binaries
    for SRCBIN in "$XDIR"/*; do
        BIN=$(basename "$SRCBIN")
        DEST=$(git ls-files "x64/**/$BIN" "x64/$BIN" | head -1)
        DEST=${DEST:-"x64/$BIN"}
        mkdir -p "$(dirname "$DEST")"
        cp "$SRCBIN" "$DEST"
        chmod +x "$DEST"
        echo "  $TOOL: $SRCBIN -> $DEST"
    done
    # arm binaries (dir may be empty or absent)
    if [ -d "$ADIR" ] && compgen -G "$ADIR/*" > /dev/null; then
        for SRCBIN in "$ADIR"/*; do
            BIN=$(basename "$SRCBIN")
            DEST=$(git ls-files "arm/**/$BIN" "arm/$BIN" | head -1)
            DEST=${DEST:-"arm/$BIN"}
            mkdir -p "$(dirname "$DEST")"
            cp "$SRCBIN" "$DEST"
            chmod +x "$DEST"
            echo "  $TOOL(arm): $SRCBIN -> $DEST"
        done
    fi

    CURRENT=$($YQ -r ".tools[] | select(.name == \"$TOOL\") | .version" tools.yaml)
    $YQ -i "(.tools[] | select(.name == \"$TOOL\") | .version) = \"$LATEST\"" tools.yaml
    BUMPED="$BUMPED $TOOL=$LATEST"
    BUMPED_JSON=$(jq --arg n "$TOOL" --arg c "$CURRENT" --arg l "$LATEST" \
        '. + [{name: $n, current: $c, latest: $l}]' <<<"$BUMPED_JSON")
done

if [ -n "$BUMPED" ]; then
    python3 scripts/update_readme.py "$DIST" $BUMPED
fi

echo "$BUMPED_JSON" > "$BUMPED_OUT"
echo "apply_bump done:$BUMPED"
