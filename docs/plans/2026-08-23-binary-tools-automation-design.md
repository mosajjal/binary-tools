# Design: binary-tools automation

Date: 2026-08-23
Status: implemented (initial coverage; experimental tier best-effort)

## Goal

Stop maintaining `binary-tools` by hand. When an upstream project publishes a
new release, CI should rebuild the static binary, test it, and hand the result
to the maintainer as a PR — assigned to the owner — containing the new binary,
updated README tables and updated manifest.

Decisions (user-confirmed): cover **everything** including tarball-only
upstreams, build for **x64 + ARMv7**, run the sweep **weekly**.

## Architecture

```
tools.yaml                 single source of truth: 113 entries
  per tool: version, check{type,...}, lang, outputs[], arm_outputs[], test
scripts/
  check_upstream.py        threaded upstream version discovery (stdlib only)
  gen_dockerfiles.py       renders build/<tool>/Dockerfile from recipes
  recipes_{go,rust,c,pt}.py  declarative build recipes (~104 tools)
  build.sh                 docker build + smoke test + artifact extraction
  apply_bump.sh            assembles a bump working tree from artifacts
  update_readme.py         rewrites README table rows (version + SHA256)
build/<tool>/Dockerfile    generated; builds at ARG VERSION -> /out/{x64,arm}
.github/workflows/
  upstream-bump.yml        weekly cron: check -> matrix build -> single PR
  build-tool.yml           workflow_dispatch/call: ad-hoc single-tool build
  lint-buildfiles.yml      hadolint/shellcheck/manifest checks on PRs
```

## Version checking

Five check types cover all upstreams:

| type | used for | notes |
|---|---|---|
| github-release | most tools | `/releases/latest` |
| github-tag | repos without releases (dropbear, iodine, vim, ...) | regex filter + prefix strip + prerelease skip |
| git-remote | non-GitHub hosts (dnstt@bamsoftware, tor@gitlab.tpo) | `git ls-remote --tags` |
| url | tarball indexes (busybox.net, nmap.org, dest-unreach, tcpdump.org...) | scrape + regex, optional two-stage (nano dist/vN/) |
| sourceforge | bbe, ngrep | best_release.json, version parsed from filename |

Version comparison is segment-aware (`1.7 < 1.10`, `20240606` style dates,
`3.7c` suffixes). Pinned entries (dead upstreams like inlets, nc) are skipped.

Validated live against all 113 upstreams on 2026-08-23: 88 outdated detected,
zero unexplained errors.

## Build templates

Three generators share one output contract (`/out/x64/*`, `/out/arm/*`,
strip + UPX):

- **Go** — `golang:1.25-alpine`, `CGO_ENABLED=0 GOTOOLCHAIN=auto`,
  `GOARCH=arm GOARM=7` cross is free. cgo exceptions (dnsmonster/mylg)
  pin `CGO_ENABLED=1` with alpine static libs.
- **Rust** — `rust:1-alpine` (host target is musl), ARM via musl.cc
  `arm-linux-musleabihf` linker + rustup target.
- **C/C++** — `alpine:3.20` + `build-base`; autotools builds use release
  tarballs when upstream only ships generated `configure` there
  (jq, strace); `test -x configure || autoreconf -fi` fallback elsewhere.
  Tarballs decode via extension pipes (busybox tar can't read xz natively).

ARM cross-builds are limited to tools that already ship ARM binaries today
(30 tools) plus trivially-portable ones; heavy-dependency cross builds
(htop/tmux/socat/openssl stacks) are x64-only until someone needs them.

## Testing

- Local: `scripts/build.sh <tool> <version>` builds and smoke-tests inside the
  image; ARM smoke runs through host qemu-user-static when present.
- 33 tools verified locally across every template family during development,
  including multi-binary (dropbear, jq+arm, tcpdump w/ bundled libpcap).
- CI: smoke tests are mandatory per tool; `experimental: true` failures don't
  block the weekly PR but are visible in job history.

## PR assembly

Matrix jobs upload artifacts `bt-<tool>/{x64,arm}/*`. The `pr` job downloads
all of them, runs `apply_bump.sh` (copies binaries to their existing repo
paths discovered via `git ls-files`, bumps `tools.yaml`), regenerates README
rows, then opens one PR assigned to the owner with a summary body.
