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
        bins=[("es-dump", "./elasticdump")],
        # multi-tool repo without go.mod in the subpackage
        pre=["cd elasticdump && go mod init elasticdump && go mod tidy"],
    ),
    "fq": dict(
        lang="go", slug="wader/fq", tag_prefix="v",
        bins=[("fq", ".")],
    ),
    "frp": dict(
        lang="go", slug="fatedier/frp", tag_prefix="v",
        bins=[("frpc", "./cmd/frpc"), ("frps", "./cmd/frps")],
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
        lang="go", slug="laurent22/massren", tag_prefix="v",
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
