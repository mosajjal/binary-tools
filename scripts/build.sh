#!/usr/bin/env bash
# Build and smoke-test one tool's Dockerfile; optionally extract binaries.
#
# usage: scripts/build.sh TOOL [VERSION] [--extract]
#   TOOL      tool id from tools.yaml (must have build/<tool>/Dockerfile)
#   VERSION   override; defaults to tools.yaml `version`
#   --extract copy /out from the image into dist/<tool>/
#
# Smoke tests run inside the container (x64 natively; arm via qemu-user when
# installed). Test commands come from tools.yaml (`test` args or `test_cmd`).
set -euo pipefail

TOOL=${1:?usage: scripts/build.sh TOOL [VERSION] [--extract]}
shift || true
EXTRACT=0
for a in "$@"; do [[ "$a" == "--extract" ]] && EXTRACT=1 || VERSION="$a"; done
VERSION=${VERSION:-}

YQ=yq
command -v $YQ >/dev/null || YQ=/opt/toolbelt/yq
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

sel=".tools[] | select(.name == \"$TOOL\")"
[[ -f "build/$TOOL/Dockerfile" ]] || { echo "no build/$TOOL/Dockerfile"; exit 1; }

VERSION=${VERSION:-$($YQ -r "$sel | .version" tools.yaml)}
IMAGE="bt/$TOOL:$VERSION"

echo "==> building $TOOL $VERSION"
docker build -q=false --build-arg VERSION="$VERSION" -t "$IMAGE" "build/$TOOL" >&2

echo "==> smoke test (x64)"
TEST_ARGS=$($YQ -r "$sel | .test // \"--version\"" tools.yaml)
TEST_CMD=$($YQ -r "$sel | .test_cmd // \"\"" tools.yaml)

run_x64() {
    docker run --rm --entrypoint /bin/sh "$IMAGE" -ec "$1"
}

if [[ -n "$TEST_CMD" && "$TEST_CMD" != "null" ]]; then
    run_x64 "$TEST_CMD"
else
    BINS=$($YQ -r "$sel | .outputs | map(.bin // .) | join(\" \")" tools.yaml)
    for b in $BINS; do
        echo "    /out/x64/$b $TEST_ARGS"
        docker run --rm --entrypoint /bin/sh "$IMAGE" -ec "/out/x64/$b $TEST_ARGS >/dev/null"
    done
fi

# ARM smoke test through qemu-user-static if the host provides it.
if docker run --rm --entrypoint /bin/sh "$IMAGE" -ec 'ls /out/arm/* >/dev/null 2>&1' 2>/dev/null; then
    QEMU=$(command -v qemu-arm-static || true)
    if [[ -z "$QEMU" && -x /usr/bin/qemu-arm-static ]]; then QEMU=/usr/bin/qemu-arm-static; fi
    if [[ -n "$QEMU" ]]; then
        echo "==> smoke test (arm via qemu)"
        ARMDIR=$(mktemp -d)
        CID=$(docker create "$IMAGE")
        docker cp -q "$CID":/out/arm/. "$ARMDIR" >/dev/null 2>&1 || docker cp "$CID":/out/arm/. "$ARMDIR"
        docker rm "$CID" >/dev/null
        for b in "$ARMDIR"/*; do
            echo "    arm $(basename "$b")"
            "$QEMU" "$b" $TEST_ARGS >/dev/null || {
                echo "    (arm smoke failed for $(basename "$b"); not blocking)"; }
        done
        rm -rf "$ARMDIR"
    else
        echo "==> arm binaries present (qemu unavailable locally; CI verifies)"
    fi
fi

if [[ $EXTRACT == 1 ]]; then
    echo "==> extracting to dist/$TOOL/"
    rm -rf "dist/$TOOL"; mkdir -p "dist/$TOOL"
    CID=$(docker create "$IMAGE")
    docker cp "$CID":/out/. "dist/$TOOL/"
    docker rm "$CID" >/dev/null
    ( cd "dist/$TOOL" && find . -type f -exec sha256sum {} \; )
fi

echo "==> OK $TOOL $VERSION"
