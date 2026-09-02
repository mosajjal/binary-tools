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
docker build --progress=plain --build-arg VERSION="$VERSION" -t "$IMAGE" "build/$TOOL" >&2

echo "==> smoke test (x64)"
TEST_ARGS=$($YQ -r "$sel | .test // \"--version\"" tools.yaml)
TEST_CMD=$($YQ -r "$sel | .test_cmd // \"\"" tools.yaml)

run_x64() {
    docker run --rm --entrypoint /bin/sh "$IMAGE" -ec "$1"
}

QEMU_IN=/qemu-arm  # where qemu-arm-static is mounted inside the image

# A daemon that ignores --version blocks forever: 3proxy burned a 2h job that
# way. Tools that need more than a flag carry a `test_cmd` with their own guard.
SMOKE_TIMEOUT="timeout 20"

run_arm() {
    docker run --rm -v "$QEMU":"$QEMU_IN":ro --entrypoint /bin/sh "$IMAGE" -ec "$1"
}

if [[ -n "$TEST_CMD" && "$TEST_CMD" != "null" ]]; then
    run_x64 "$TEST_CMD"
else
    BINS=$($YQ -r "$sel | .outputs | map(.bin // .) | join(\" \")" tools.yaml)
    for b in $BINS; do
        echo "    /out/x64/$b $TEST_ARGS"
        if run_x64 "$SMOKE_TIMEOUT /out/x64/$b $TEST_ARGS >/dev/null 2>&1"; then
            continue
        fi
        # not every tool supports the manifest's default flag; walk a ladder
        # of common version/help invocations before giving up
        OK=0
        for args in "--version" "-V" "-v" "version" "--help" "-h"; do
            if run_x64 "$SMOKE_TIMEOUT /out/x64/$b $args >/dev/null 2>&1"; then OK=1; break; fi
        done
        [ $OK = 1 ] || { echo "smoke test failed for /out/x64/$b"; exit 1; }
    done
fi

# ARM smoke test through qemu-user-static if the host provides it.
# ARM is only shipped when the tool declares arm outputs; if we ship it, it
# must pass the same checks as x64 -- a broken ARM binary never lands in a PR.
# qemu is static, so it is bind-mounted into the image and the ARM binaries run
# against the same filesystem the x64 run used: a `test_cmd` that prepares a
# helper first (termshark stubs tshark) still works, and nothing touches the
# host. test_cmd matters here: dsvpn and icmptunnel exit non-zero on every flag
# in the ladder below, so without it they can never pass ARM.
if docker run --rm --entrypoint /bin/sh "$IMAGE" -ec 'ls /out/arm/* >/dev/null 2>&1' 2>/dev/null; then
    ARM_SHIPPED=1
else
    ARM_SHIPPED=0
fi
if [[ $ARM_SHIPPED == 1 ]]; then
    QEMU=$(command -v qemu-arm-static || true)
    if [[ -z "$QEMU" && -x /usr/bin/qemu-arm-static ]]; then QEMU=/usr/bin/qemu-arm-static; fi
    if [[ -n "$QEMU" ]]; then
        echo "==> smoke test (arm via qemu)"
        if [[ -n "$TEST_CMD" && "$TEST_CMD" != "null" ]]; then
            run_arm "${TEST_CMD//\/out\/x64\//$QEMU_IN /out/arm/}"
        else
            for b in $(run_x64 'ls /out/arm'); do
                echo "    arm $b"
                run_arm "$SMOKE_TIMEOUT $QEMU_IN /out/arm/$b $TEST_ARGS >/dev/null 2>&1" && continue
                # same fallback ladder as x64; if none pass, the binary is broken
                OK=0
                for args in "--version" "-V" "-v" "version" "--help" "-h"; do
                    if run_arm "$SMOKE_TIMEOUT $QEMU_IN /out/arm/$b $args >/dev/null 2>&1"; then OK=1; break; fi
                done
                [ $OK = 1 ] || { echo "arm smoke test failed for /out/arm/$b"; exit 1; }
            done
        fi
    else
        echo "==> arm binaries present (qemu unavailable locally; CI installs it)"
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
