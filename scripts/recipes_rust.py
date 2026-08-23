"""Rust build recipes -> consumed by gen_dockerfiles.py.

bins: [(output_filename, path_under_target/release)]
features/cargo_args are appended to `cargo build --release`.
"""

RECIPES = {
    "avml": dict(
        lang="rust", slug="microsoft/avml", tag_prefix="v",
        rust_image="rust:1.72-alpine",
        bins=[("avml", "avml")],
    ),
    "bandwhich": dict(
        lang="rust", slug="imsnif/bandwhich", tag_prefix="v",
        bins=[("bandwhich", "bandwhich")],
    ),
    "boringtun": dict(
        lang="rust", slug="cloudflare/boringtun", tag_prefix="boringtun-",
        bins=[("boringtun", "boringtun-cli"), ("wg-user", "boringtun-cli")],
    ),
    "evtx": dict(
        lang="rust", slug="omerbenamram/evtx", tag_prefix="v",
        bins=[("evtx", "evtx_dump")], cargo_args="--features evtx_dump", arm=False,
    ),
    "fd": dict(
        lang="rust", slug="sharkdp/fd", tag_prefix="v",
        bins=[("fd", "fd")],
    ),
    "grex": dict(
        lang="rust", slug="pemistahl/grex", tag_prefix="v",
        bins=[("grex", "grex")],
    ),
    "hex": dict(
        lang="rust", slug="sitkevij/hex", tag_prefix="v",
        bins=[("hex", "hex")],
    ),
    "hx": dict(
        lang="rust", slug="helix-editor/helix",
        # skip tree-sitter grammar fetch/build (network+cc heavy); core editor works
        env={"HELIX_DISABLE_AUTO_GRAMMAR_BUILD": "1"},
        bins=[("hx", "hx")], arm=False,
    ),
    "jaq": dict(
        lang="rust", slug="01mf02/jaq", tag_prefix="v",
        bins=[("jaq", "jaq")], arm=False,
    ),
    "kibi": dict(
        lang="rust", slug="ilai-deutel/kibi", tag_prefix="v",
        bins=[("kibi", "kibi")],
    ),
    "kmon": dict(
        lang="rust", slug="orhun/kmon", tag_prefix="v",
        bins=[("kmon", "kmon")],
    ),
    "merino": dict(
        lang="rust", slug="ajmwagar/merino", branch=True,
        bins=[("merino", "merino")], experimental=True,
    ),
    "miniserve": dict(
        lang="rust", slug="svenstaro/miniserve", tag_prefix="v",
        bins=[("miniserve", "miniserve")], pkgs=["openssl-libs-static"],
        features=["tls"], env={"OPENSSL_STATIC": "1"},
    ),
    "nomino": dict(
        lang="rust", slug="yaa110/nomino",
        bins=[("nomino", "nomino")],
    ),
    "pueue": dict(
        lang="rust", slug="Nukesor/pueue", tag_prefix="v",
        bins=[("pueue", "pueue"), ("pueued", "pueued")], arm=False,
    ),
    "rargs": dict(
        lang="rust", slug="lotabout/rargs", tag_prefix="v",
        bins=[("rargs", "rargs")],
    ),
    "sd": dict(
        lang="rust", slug="chmln/sd", tag_prefix="v",
        bins=[("sd", "sd")],
    ),
    "sshx": dict(
        lang="rust", slug="ekzhang/sshx", branch=True,
        bins=[("sshx", "sshx"), ("sshx-server", "sshx-server")], arm=False,
    ),
    "tiny": dict(
        lang="rust", slug="osa1/tiny", tag_prefix="v",
        bins=[("tiny", "tiny")], experimental=True,
        env={"OPENSSL_STATIC": "1", "OPENSSL_DIR": "/usr"},
        pkgs=["openssl-libs-static", "openssl-dev"],
    ),
    "xsv": dict(
        lang="rust", slug="BurntSushi/xsv", tag_prefix="",
        bins=[("xsv", "xsv")], experimental=True, arm=False,
    ),
    "zenith": dict(
        lang="rust", slug="bvaisvil/zenith",
        bins=[("zenith", "zenith")],
    ),
    "zellij": dict(
        lang="rust", slug="zellij-org/zellij", tag_prefix="v",
        bins=[("zellij", "zellij")], arm=False,
    ),
}
