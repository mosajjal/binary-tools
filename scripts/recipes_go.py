"""Go build recipes -> consumed by gen_dockerfiles.py.

bins: [(output_filename, go_package_path)]
arm is free for pure-Go builds (GOARCH=arm GOARM=7).
"""

RECIPES = {
    "amass": dict(
        lang="go", slug="owasp-amass/amass", tag_prefix="v",
        bins=[("amass", "./cmd/amass")],
    ),
    "amicontained": dict(
        lang="go", slug="genuinetools/amicontained",
        bins=[("amicontained", ".")],
    ),
    "bed": dict(
        lang="go", slug="itchyny/bed", tag_prefix="v",
        bins=[("bed", "./cmd/bed")],
    ),
    "bit": dict(
        lang="go", slug="chriswalz/bit", tag_prefix="v",
        bins=[("bit", ".")],
    ),
    "brook": dict(
        lang="go", slug="txthinking/brook", tag_prefix="v",
        bins=[("brook", "./cli/brook")],
    ),
    "dnsmonster": dict(
        lang="go", slug="FenkoHQ/dnsmonster", tag_prefix="v",
        bins=[("dnsmonster", "./cmd/dnsmonster")],
        env={"CGO_ENABLED": "1"}, pkgs=["build-base", "libpcap-dev"],
        ldflags='-extldflags "-static"', arm=False,
    ),
    "dnspot": dict(
        lang="go", slug="mosajjal/dnspot",
        bins=[("dnspot-agent", "./cmd/agent"), ("dnspot-server", "./cmd/server")],
    ),
    "dnstrace": dict(
        lang="go", slug="rs/dnstrace", tag_prefix="v",
        bins=[("dnstrace", ".")],
        # repo predates go modules
        pre=["go mod init dnstrace && go mod tidy"],
    ),
    "dnstt_client": dict(
        lang="go", clone_url="https://www.bamsoftware.com/git/dnstt.git",
        tag_prefix="v", example_version="1.20241021",
        bins=[("dnstt_client", "./dnstt-client"), ("dnstt_server", "./dnstt-server")],
    ),
    "doggo": dict(
        lang="go", slug="mr-karan/doggo", tag_prefix="v",
        bins=[("doggo", "./cmd/doggo")],
    ),
    "es-dump": dict(
        lang="go", slug="mosajjal/x", branch=True,
        # the subpackage carries its own go.mod; build from inside it
        bins=[("es-dump", ".")], arm=False,
        build=[
            "(cd elasticdump && CGO_ENABLED=0 go build -trimpath -ldflags=\"-s -w\" -o /tmp/x64_es-dump .)",
            "(cd elasticdump && CGO_ENABLED=0 GOARCH=arm GOARM=7 go build -trimpath -ldflags=\"-s -w\" -o /tmp/arm_es-dump .)",
        ],
    ),
    "fq": dict(
        lang="go", slug="wader/fq", tag_prefix="v",
        bins=[("fq", ".")],
    ),
    "frp": dict(
        lang="go", slug="fatedier/frp", tag_prefix="v",
        bins=[("frpc", "./cmd/frpc"), ("frps", "./cmd/frps")],
        # cmd packages go:embed web/*/dist -- build the SPA first
        pkgs=["nodejs", "npm"],
        pre=["cd web/frpc && npm install --no-audit --no-fund >/dev/null && npm run build >/dev/null"],
    ),
    "fzf": dict(
        lang="go", slug="junegunn/fzf", tag_prefix="v",
        bins=[("fzf", ".")],
    ),
    "ghfs": dict(
        lang="go", slug="mjpclab/go-http-file-server", tag_prefix="v",
        bins=[("ghfs", ".")],
    ),
    "gobuster": dict(
        lang="go", slug="OJ/gobuster", tag_prefix="v",
        bins=[("gobuster", ".")],
    ),
    "gojq": dict(
        lang="go", slug="itchyny/gojq", tag_prefix="v",
        bins=[("gojq", "./cmd/gojq")],
    ),
    "gotop": dict(
        lang="go", slug="xxxserxxx/gotop", tag_prefix="v",
        bins=[("gotop", "./cmd/gotop")],
    ),
    "goss": dict(
        lang="go", slug="goss-org/goss", tag_prefix="v",
        bins=[("goss", "./cmd/goss")],
    ),
    "gron": dict(
        lang="go", slug="tomnomnom/gron", tag_prefix="v",
        bins=[("gron", ".")],
    ),
    "gum": dict(
        lang="go", slug="charmbracelet/gum", tag_prefix="v",
        bins=[("gum", ".")],
    ),
    "httpdump": dict(
        lang="go", slug="hsiafan/httpdump", branch=True,
        bins=[("httpdump", ".")],
    ),
    "httpx": dict(
        lang="go", slug="projectdiscovery/httpx", tag_prefix="v",
        bins=[("httpx", "./cmd/httpx")],
    ),
    "jj": dict(
        lang="go", slug="tidwall/jj", tag_prefix="v",
        bins=[("jj", "./cmd/jj")],
    ),
    "lazygit": dict(
        lang="go", slug="jesseduffield/lazygit", tag_prefix="v",
        bins=[("lazygit", ".")],
    ),
    "massren": dict(
        # depends on mattn/go-sqlite3 (cgo-only); without cgo the driver is a
        # no-op stub and massren panics at runtime ("unknown driver sqlite3").
        lang="go", slug="laurent22/massren", tag_prefix="v", cgo=True,
        bins=[("massren", ".")],
    ),
    "memcd-util": dict(
        lang="go", slug="me-io/memcached-util", tag_prefix="v",
        bins=[("memcd-util", "./cmd/util")], experimental=True,
    ),
    "micro": dict(
        lang="go", slug="micro-editor/micro", tag_prefix="v",
        bins=[("micro", "./cmd/micro")],
    ),
    "mylg": dict(
        lang="go", slug="mehrdadrad/mylg", branch=True,
        bins=[("mylg", ".")],
        env={"CGO_ENABLED": "1"}, pkgs=["libpcap-dev"],
        ldflags='-extldflags "-static"',
    ),
    "onionpipe": dict(
        lang="go", slug="cmars/onionpipe", tag_prefix="v",
        bins=[("onionpipe", ".")],
    ),
    "pline-go": dict(
        lang="go", slug="justjanne/powerline-go", tag_prefix="v",
        bins=[("pline-go", ".")],
    ),
    "q": dict(
        lang="go", slug="natesales/q", tag_prefix="v",
        bins=[("q", ".")],
    ),
    "singbox": dict(
        lang="go", slug="SagerNet/sing-box", tag_prefix="v",
        bins=[("singbox", "./cmd/sing-box")],
    ),
    "sniproxy": dict(
        lang="go", slug="mosajjal/sniproxy", tag_prefix="v",
        bins=[("sniproxy", "./cmd/sniproxy")],
    ),
    "spp": dict(
        lang="go", slug="esrrhs/spp",
        bins=[("spp", ".")],
    ),
    "termshark": dict(
        lang="go", slug="gcla/termshark", tag_prefix="v",
        bins=[("termshark", "./cmd/termshark")],
    ),
    "termsvg": dict(
        lang="go", slug="MrMarble/termsvg", tag_prefix="v",
        bins=[("termsvg", "./cmd/termsvg")],
    ),
    "wg-go": dict(
        lang="go", slug="WireGuard/wireguard-go",
        bins=[("wg-go", ".")],
    ),
    "inlets": dict(
        lang="go", slug="the-cc-dev/inlets", branch=True,
        bins=[("inlets", ".")],
    ),
    "yq": dict(
        lang="go", slug="mikefarah/yq", tag_prefix="v",
        bins=[("yq", ".")],
    ),
}

RECIPES["ffuf"] = dict(
    lang="go", slug="ffuf/ffuf", tag_prefix="v",
    bins=[("ffuf", ".")],
)
RECIPES["superfile"] = dict(
    lang="go", slug="yorukot/superfile", tag_prefix="v",
    bins=[("superfile", ".")],
)
