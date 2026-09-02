"""C / C++ build recipes -> consumed by gen_dockerfiles.py.

Contract: `build` shell lines must leave final x64 binaries at
/tmp/out/<bin>; `arm_build` lines (when present) must leave ARMv7 binaries
at /tmp/out-arm/<bin>. bins: [(output_filename, ignored)].

Common helpers as shell snippets:
  AUTOGEN  = regenerate configure when the repo only ships autogen.sh
  STATIC   = LDFLAGS value for fully-static musl linking
"""

AUTOGEN = 'test -x configure || autoreconf -fi'
STATIC = '-static'

RECIPES = {
    # ------------------------------------------------------------- simple --
    "dh": dict(
        lang="c", slug="ryanmjacobs/darkhttpd", branch=True,
        bins=[("dh", "")],
        build=["cc -O2 -static -o /tmp/out/dh darkhttpd.c"],
        arm_build=["arm-linux-musleabihf-gcc -O2 -static -o /tmp/out-arm/dh darkhttpd.c"],
    ),
    "dsvpn": dict(
        lang="c", slug="jedisct1/dsvpn", tag_prefix="",
        bins=[("dsvpn", "")],
        build=["make CC=gcc CFLAGS='-O2 -static' LDFLAGS=-static -j$(nproc)",
               "cp dsvpn /tmp/out/"],
        arm_build=["make clean || true",
                   "sed -i '/^\\tstrip /d' Makefile",
                   # the Makefile links with CFLAGS, so -static must be there too
                   "make CC=arm-linux-musleabihf-gcc CFLAGS='-O2 -static' LDFLAGS=-static -j$(nproc)",
                   "cp dsvpn /tmp/out-arm/"],
    ),
    "corkscrew": dict(
        lang="c", slug="bryanpkc/corkscrew", tag_prefix="v",
        bins=[("corkscrew", "")],
        pkgs=["autoconf", "automake"],
        build=[AUTOGEN, "./configure --host=$(gcc -dumpmachine) LDFLAGS=-static",
               "make -j$(nproc)", "cp corkscrew /tmp/out/"],
        arm_build=["make distclean || true",
                   "./configure --host=arm-linux-musleabihf LDFLAGS=-static",
                   "make -j$(nproc)", "cp corkscrew /tmp/out-arm/"],
    ),
    "redir": dict(
        lang="c", slug="troglobit/redir", tag_prefix="v",
        bins=[("redir", "")],
        pkgs=["autoconf", "automake"],
        build=[AUTOGEN, "./configure LDFLAGS=-static", "make -j$(nproc)",
               "cp redir /tmp/out/"],
    ),
    "ioping": dict(
        lang="c", slug="koct9i/ioping", tag_prefix="v",
        bins=[("ioping", "")],
        build=["make -j$(nproc) LDFLAGS=-static", "cp ioping /tmp/out/"],
        arm_build=["make clean || true",
                   "make -j$(nproc) CC=arm-linux-musleabihf-gcc LDFLAGS=-static",
                   "cp ioping /tmp/out-arm/"],
    ),
    "icmptunnel": dict(
        lang="c", slug="DhavalKapil/icmptunnel", tag_prefix="v",
        bins=[("icmptunnel", "")],
        build=["make -j$(nproc) CFLAGS='-O2 -static' LDFLAGS=-static",
               "cp icmptunnel /tmp/out/"],
        arm_build=["make clean || true",
                   # LDFLAGS alone leaves a musl-dynamic binary: link via CFLAGS too
                   "make -j$(nproc) CC=arm-linux-musleabihf-gcc CFLAGS='-O2 -static' LDFLAGS=-static",
                   "cp icmptunnel /tmp/out-arm/"],
    ),
    "wg": dict(
        lang="c", clone_url="https://git.zx2c4.com/wireguard-tools",
        tag_prefix="v", example_version="1.0.20210914",
        bins=[("wg", "")],
        build=["make -C src -j$(nproc) PLATFORM=linux LDFLAGS=-static wg",
               "cp src/wg /tmp/out/"],
    ),
    "xxd": dict(
        lang="c", slug="vim/vim", branch=True,
        bins=[("xxd", "")],
        build=["cc -O2 -static -o /tmp/out/xxd src/xxd/xxd.c"],
        arm_build=["arm-linux-musleabihf-gcc -O2 -static -o /tmp/out-arm/xxd src/xxd/xxd.c"],
    ),
    "logtop": dict(
        lang="c", slug="JulienPalard/logtop", tag_prefix="logtop-",
        bins=[("logtop", "")],
        # uthash header fetched at build time; plain Makefile, no autotools
        pkgs=["ncurses-dev", "ncurses-static"],
        pre=["mkdir -p src && curl -fsSLo src/uthash.h https://raw.githubusercontent.com/troydhanson/uthash/master/src/uthash.h && cp src/uthash.h ."],
        build=["make -j$(nproc) LDFLAGS=-static", "cp logtop /tmp/out/"],
        experimental=True,
    ),

    # ---------------------------------------------------- autotools static --
    "htop": dict(
        lang="c", slug="htop-dev/htop",
        bins=[("htop", "")],
        pkgs=["autoconf", "automake", "ncurses-dev", "ncurses-static"],
        build=[AUTOGEN, "./configure LDFLAGS=-static LIBS=-lncursesw",
               "make -j$(nproc)", "cp htop /tmp/out/"],
    ),
    "tmux": dict(
        lang="c", slug="tmux/tmux",
        bins=[("tmux", "")],
        pkgs=["autoconf", "automake", "pkgconf", "libevent-dev", "libevent-static",
              "ncurses-dev", "ncurses-static", "byacc"],
        build=[AUTOGEN, "./configure --with-libevent=/usr LDFLAGS=-static",
               "make -j$(nproc) ACLOCAL=: AUTOCONF=: AUTOHEADER=: AUTOMAKE=:",
               "cp tmux /tmp/out/"],
    ),
    "strace": dict(
        lang="c", slug="strace/strace", tag_prefix="v",
        release_tarball="strace-{v}.tar.xz",
        bins=[("strace", "")],
        build=["./configure LDFLAGS=-static --enable-mpers=no",
               "make -j$(nproc)", "cp src/strace /tmp/out/"],
        arm_build=["make distclean || true",
                   "./configure --host=arm-linux-musleabihf LDFLAGS=-static --enable-mpers=no",
                   "make -j$(nproc)", "cp src/strace /tmp/out-arm/"],
    ),
    # NOTE: strace arm_build reuses same unpacked tree
    "dropbear": dict(
        lang="c", slug="mkj/dropbear", tag_prefix="DROPBEAR_",
        bins=[("dropbear", ""), ("dbclient", ""), ("dropbearconvert", ""),
              ("dropbearkey", ""), ("scp", "")],
        pkgs=["autoconf", "automake", "zlib-static", "zlib-dev"],
        build=["./configure LDFLAGS=-static --disable-zlib",
               "make -j$(nproc) PROGRAMS='dropbear dbclient dropbearconvert dropbearkey scp'",
               "cp dropbear dbclient dropbearconvert dropbearkey scp /tmp/out/"],
        arm_build=["make clean || true",
                   # configure links through CFLAGS here, so LDFLAGS alone left a
                   # binary needing /usr/lib/ld.so.1 -- unrunnable on a real target
                   # dropbear's hardening adds -Wl,-pie, which beats -static and left
                   # a dynamic PIE needing /usr/lib/ld.so.1 -- unrunnable on a target
                   "./configure --host=arm-linux-musleabihf CFLAGS='-O2 -static' "
                   "LDFLAGS=-static --disable-zlib --disable-harden",
                   "make -j$(nproc) PROGRAMS='dropbear dbclient dropbearconvert dropbearkey scp'",
                   "mkdir -p /tmp/out-arm && cp dropbear dbclient dropbearconvert dropbearkey scp /tmp/out-arm/"],
    ),
    "tinyproxy": dict(
        lang="c", slug="tinyproxy/tinyproxy",
        bins=[("tinyproxy", "")],
        pkgs=["autoconf", "automake"],
        build=[AUTOGEN, "./configure LDFLAGS=-static", "make -j$(nproc)",
               "cp src/tinyproxy /tmp/out/"],
    ),
    "nano": dict(
        lang="c",
        tarball="https://www.nano-editor.org/dist/v{vmajor}/nano-{v}.tar.xz",
        bins=[("nano", "")],
        pkgs=["ncurses-static", "ncurses-dev", "file-dev"],
        build=["./configure LDFLAGS=-static", "make -j$(nproc)", "cp src/nano /tmp/out/"],
    ),
    "jq": dict(
        lang="c", slug="jqlang/jq", tag_prefix="jq-",
        release_tarball="jq-{v}.tar.gz", example_version="1.7.1",
        bins=[("jq", "")],
        # jq links its executable via libtool. Plain `-static` in LDFLAGS only
        # tells libtool to prefer static libtool libs -- musl stays dynamic.
        # `-all-static` forces a fully static link, but it is a libtool-only
        # flag: passing it to ./configure breaks configure's raw-gcc link
        # tests (exit 77). So pass it only to the libtool link at make time.
        build=["./configure --without-oniguruma --disable-shared",
               "make -j$(nproc) LC_ALL=C LDFLAGS=-all-static", "cp jq /tmp/out/"],
        arm_build=['mkdir -p /src-arm && curl -fsSL "https://github.com/jqlang/jq/releases/download/jq-${VERSION}/jq-${VERSION}.tar.gz" | gunzip -c | tar x -C /src-arm --strip-components=1',
                   "cd /src-arm && ./configure --host=arm-linux-musleabihf --without-oniguruma --disable-shared",
                   "make -j$(nproc) LC_ALL=C LDFLAGS=-all-static", "cp jq /tmp/out-arm/"],
    ),
    "ncdu": dict(
        lang="c",
        tarball="https://dev.yorhel.nl/download/ncdu-{v}.tar.gz",
        bins=[("ncdu", "")],
        pkgs=["ncurses-static", "ncurses-dev"],
        build=["./configure LDFLAGS=-static", "make -j$(nproc)", "cp ncdu /tmp/out/"],
    ),
    "socat": dict(
        lang="c",
        tarball="http://www.dest-unreach.org/socat/download/socat-{v}.tar.gz",
        bins=[("socat", "")],
        pkgs=["openssl-dev", "openssl-libs-static", "readline-static", "readline-dev", "ncurses-static", "zlib-static"],
        build=["./configure LDFLAGS='-static -lssl -lcrypto'", "make -j$(nproc)",
               "cp socat /tmp/out/"],
    ),
    "ugrep": dict(
        lang="cxx", slug="Genivia/ugrep", tag_prefix="v",
        bins=[("ugrep", "")],
        pkgs=["autoconf", "automake", "libtool", "bash", "pkgconf"],
        build=["autoreconf -fi",
               "CONFIG_SHELL=/bin/bash bash ./configure --disable-shared LDFLAGS=-static",
               "make -j$(nproc) ACLOCAL=: AUTOCONF=: AUTOHEADER=: AUTOMAKE=:",
               "cp bin/ugrep /tmp/out/"],
    ),
    "curl": dict(
        lang="c",
        slug="curl/curl", tag_prefix="curl-", tag_transform="dots_to_underscores",
        release_tarball="curl-{v}.tar.gz", example_version="8.21.0",
        bins=[("curl", "")],
        pkgs=["autoconf", "automake", "libtool", "openssl-dev", "openssl-libs-static",
              "zlib-static", "zlib-dev", "pkgconf", "python3"],
        # plain HTTP/1.1+TLS: no nghttp2 (its .so wins over the .a at link time).
        # PKG_CONFIG --static pulls OpenSSL 3's private transitive deps; LDFLAGS at
        # configure time bakes -static into feature tests; curl_LDFLAGS=-all-static
        # is libtool's own fully-static toggle (plain LDFLAGS=-static is swallowed
        # by libtool and the exe links dynamically against libssl.so).
        build=["PKG_CONFIG='pkg-config --static' ./configure --disable-shared --enable-static "
               "--with-openssl --with-zlib --without-libpsl --without-nghttp2 "
               "--without-brotli --without-zstd --without-libidn2 --disable-ldap --disable-ldaps "
               "LDFLAGS=-static",
               "make -j$(nproc) curl_LDFLAGS=-all-static", "cp src/curl /tmp/out/"],
    ),
    "busybox": dict(
        lang="c",
        tarball="https://busybox.net/downloads/busybox-{v}.tar.bz2", tarflags="jx",
        bins=[("busybox", "")],
        build=["make defconfig",
               "sed -i 's/^# CONFIG_STATIC is not set/CONFIG_STATIC=y/' .config",
               "yes '' | make oldconfig >/dev/null",
               "make -j$(nproc)", "cp busybox /tmp/out/"],
        arm_build=["make clean || true", "make defconfig",
                   "sed -i 's/^# CONFIG_STATIC is not set/CONFIG_STATIC=y/' .config",
                   "yes '' | make CROSS_COMPILE=arm-linux-musleabihf- oldconfig >/dev/null",
                   "make -j$(nproc) CROSS_COMPILE=arm-linux-musleabihf-",
                   "cp busybox /tmp/out-arm/"],
    ),
    "pv": dict(
        lang="c",
        tarball="https://www.ivarch.com/programs/sources/pv-{v}.tar.gz",
        bins=[("pv", "")],
        pkgs=["gettext-tiny-dev", "ncurses-static", "ncurses-dev"],
        build=["./configure --disable-nls LDFLAGS=-static", "make -j$(nproc)",
               "cp pv /tmp/out/"],
        arm_build=["make distclean || true",
                   "./configure --host=arm-linux-musleabihf --disable-nls LDFLAGS=-static",
                   "make -j$(nproc)", "cp pv /tmp/out-arm/"],
    ),
    "iodine": dict(
        lang="c", slug="yarrick/iodine", tag_prefix="v",
        bins=[("iodine", ""), ("iodined", "")],
        pkgs=["zlib-static", "zlib-dev", "pkgconf"],
        # musl has daemon(3); neuter iodine's bundled fallback that clashes with it
        pre=["sed -i 's/^#if !defined(ANDROID)/#if 0/' src/common.c"],
        # command-line LDFLAGS replaces the makefile's += chain, so re-add
        # what osflags/zlib would have contributed
        build=['make -C src -j$(nproc) TARGETOS=Linux LDFLAGS="-static -lz $(sh osflags Linux link)"',
               "cp bin/iodine bin/iodined /tmp/out/"],
    ),
    "tcpdump": dict(
        lang="c",
        tarball="https://www.tcpdump.org/release/tcpdump-{v}.tar.gz",
        bins=[("tcpdump", "")],
        pkgs=["flex", "byacc"],
        pre=["mkdir -p /libpcap-src /opt/libpcap",
             "curl -fsSL https://www.tcpdump.org/release/libpcap-1.10.5.tar.gz | tar xz -C /libpcap-src --strip-components=1"],
        build=["cd /libpcap-src && ./configure --prefix=/opt/libpcap --enable-dbus=no --without-libnl && make -j$(nproc) && make install && cd /src",
               "PATH=/opt/libpcap/bin:$PATH ./configure CFLAGS='-I/opt/libpcap/include' LDFLAGS='-static -L/opt/libpcap/lib'",
               "make -j$(nproc)", "cp tcpdump /tmp/out/"],
    ),
    "httptunnel_client": dict(
        lang="c",
        tarball="https://ftp.gnu.org/gnu/httptunnel/httptunnel-{v}.tar.gz",
        bins=[("httptunnel-client", ""), ("httptunnel-server", "")],
        build=["./configure LDFLAGS=-static", "make -j$(nproc)",
               "cp hts /tmp/out/httptunnel-server && cp htc /tmp/out/httptunnel-client"],
    ),
    "bbe": dict(
        lang="c", tarball="https://downloads.sourceforge.net/project/bbe-/bbe/{v}/bbe-{v}.tar.gz",
        bins=[("bbe", "")],
        build=["./configure LDFLAGS=-static", "make -j$(nproc)", "cp bbe /tmp/out/"],
    ),
    "packetq": dict(
        lang="cxx", slug="DNS-OARC/PacketQ", tag_prefix="v",
        bins=[("packetq", "")],
        pkgs=["autoconf", "automake", "libtool", "pkgconf", "zlib-dev", "zlib-static"],
        build=[AUTOGEN, "./configure LDFLAGS=-static", "make -j$(nproc)",
               "cp src/packetq /tmp/out/"],
    ),

    # ------------------------------------------- experimental / heavy builds --
    "atop": dict(
        lang="c", slug="Atoptool/atop", tag_prefix="v",
        bins=[("atop", "")],
        pkgs=["ncurses-static", "ncurses-dev", "zlib-static", "glib-dev", "glib-static", "pkgconf"],
        build=["make -j$(nproc) LDFLAGS=-static", "cp atop /tmp/out/"],
        experimental=True,
    ),
    "nmap": dict(
        lang="c",
        tarball="https://nmap.org/dist/nmap-{v}.tar.bz2", tarflags="jx",
        bins=[("nmap", ""), ("nping", "")],
        pkgs=["openssl-dev", "openssl-libs-static", "pcre2-dev", "zlib-static", "zlib-dev"],
        build=["./configure --without-zenmap --without-ndiff --without-nmap-update "
               "--without-libssh2 --with-libpcap=included --with-libpcre=included "
               "--with-zlib=included --with-openssl=/usr LDFLAGS=-static",
               "make -j$(nproc)", "cp nmap /tmp/out/",
               "cp nping/nping /tmp/out/ 2>/dev/null || cp nping /tmp/out/ 2>/dev/null || true"],
        experimental=True,
    ),
    "lnav": dict(
        lang="cxx", slug="tstack/lnav", tag_prefix="v",
        bins=[("lnav", "")],
        pkgs=["cmake", "autoconf", "automake", "libtool", "ncurses-static",
              "sqlite-static", "sqlite-dev", "zlib-static", "curl-dev", "openssl-libs-static",
              # configure links its probes statically, so every curl
              # dependency needs its .a here too
              "libunistring-dev", "libunistring-static", "curl-static",
              "nghttp2-static", "brotli-static", "zstd-static",
              "libidn2-static", "c-ares-static", "libpsl-static", "pkgconf"],
        # alpine ships no static libpcre2 -- build one, same as suricata
        pre=["mkdir -p /pcre2-src /opt/pcre2",
             "curl -fsSL --retry 3 https://github.com/PCRE2Project/pcre2/releases/download/pcre2-10.45/pcre2-10.45.tar.gz | "
             "gunzip -c | tar x -C /pcre2-src --strip-components=1",
             "cd /pcre2-src && ./configure --prefix=/opt/pcre2 --disable-shared --enable-static "
             "&& make -j$(nproc) && make install && cd /src"],
        build=["./autogen.sh && PKG_CONFIG_PATH=/opt/pcre2/lib/pkgconfig PKG_CONFIG='pkg-config --static' ./configure "
               "LDFLAGS='-static -L/opt/pcre2/lib' CPPFLAGS=-I/opt/pcre2/include "
               "LIBS=\"$(pkg-config --static --libs libcurl)\"",
               "make -j$(nproc)", "cp src/lnav /tmp/out/"],
        experimental=True,
    ),
    "sslh": dict(
        lang="c", slug="yrutschle/sslh", tag_prefix="v",
        bins=[("sslh", "")],
        pkgs=["pcre2-dev", "libconfig-dev", "libconfig-static", "libev-dev", "openssl-libs-static"],
        # 2.x dropped autotools — plain Makefile. 1.x had ./configure; try both.
        build=["test -x configure && ./configure || echo 'no configure, using Makefile defaults'",
               "make -j$(nproc) sslh-select CC=gcc LDFLAGS='-static' USELIBCONFIG=1 2>/dev/null || make -j$(nproc) sslh-select CC=gcc LDFLAGS='-static'",
               "cp sslh-select /tmp/out/sslh 2>/dev/null || cp sslh /tmp/out/sslh"],
        experimental=True,
    ),
    "sslsplit": dict(
        lang="c", slug="droe/sslsplit",
        bins=[("sslsplit", "")],
        pkgs=["cmake", "libevent-static", "openssl-libs-static", "libpcap-dev"],
        build=["./configure LDFLAGS='-static' ", "make -j$(nproc)",
               "cp sslsplit /tmp/out/"],
        experimental=True,
    ),
    "openrsync": dict(
        lang="c",
        # Mirror Alpine's testing/openrsync recipe: pin a known-good commit
        # (master HEAD breaks periodically), apply their assert patch, build
        # with plain GNU make -- no bmake, no musl-fts needed.
        tarball="https://github.com/kristapsdz/openrsync/archive/{v}.tar.gz",
        example_version="48070e68d73f67d6922b2ffc8c2dee9754e659c6",
        bins=[("openrsync", "")],
        pkgs=["patch"],
        pre=["curl -fsSL --retry 3 https://raw.githubusercontent.com/alpinelinux/aports/master/testing/openrsync/10-assert.patch | patch -p1"],
        build=["./configure PREFIX=/usr LDFLAGS=-static",
               "make -j$(nproc)", "cp openrsync /tmp/out/"],
    ),
            # BLOCKED: alpine musl static link of ldns leaves EVP_sha256
        # unresolved in ldns's own tools; needs ldns built with openssl
        # embedded or passivedns patched for dynamic linking
"pdns": dict(
        lang="c", slug="gamelinux/passivedns",
        bins=[("pdns", "")],
        # static -lldns probe needs its own deps spelled out
        pkgs=["autoconf", "automake", "openssl-dev", "openssl-libs-static",
              "libpcap-dev", "zlib-static"],
        pre=["mkdir -p /ldns-src /opt/ldns",
             "curl -fsSL --retry 3 https://www.nlnetlabs.nl/downloads/ldns/ldns-1.8.3.tar.gz | "
             "gunzip -c | tar x -C /ldns-src --strip-components=1"],
        build=["cd /ldns-src && ./configure --prefix=/opt/ldns --disable-shared "
               "--with-ssl=/usr && make -j$(nproc) LIBS='-lcrypto' && make install && cd /src",
               "autoreconf -fi",
               "./configure LDFLAGS='-static -L/opt/ldns/lib' "
               "CPPFLAGS='-I/opt/ldns/include' LIBS='-lldns -lssl -lcrypto -lz'",
               "make -j$(nproc)", "cp src/passivedns /tmp/out/pdns"],
        experimental=True,
    ),
    "vi": dict(
        lang="c", slug="johnsonjh/OpenVi",
        bins=[("vi", "")],
        # BSD-style GNUmakefile build; produces the `ovi` binary
        pkgs=["ncurses-static", "ncurses-dev"],
        build=["make -j$(nproc) -f GNUmakefile LDFLAGS=-static || make -j$(nproc) -f GNUmakefile",
               "cp bin/vi /tmp/out/vi 2>/dev/null || cp ovi /tmp/out/vi 2>/dev/null || find . -maxdepth 2 -name vi -path '*bin*' -exec cp {} /tmp/out/vi \\;"],
        experimental=True,
    ),
    "vim": dict(
        lang="c", slug="vim/vim", tag_prefix="v",
        bins=[("vim", "")],
        pkgs=["ncurses-static", "ncurses-dev", "acl-dev", "autoconf"],
        build=["cd src && ./configure --with-features=huge --disable-gui --without-x "
               "--disable-nls --disable-canberra --enable-multibyte LDFLAGS=-static && "
               "make -j$(nproc) && cp vim /tmp/out/"],
        experimental=True,
    ),
    "fish": dict(
        lang="c", slug="fish-shell/fish-shell", base_image="rust:1-alpine",
        bins=[("fish", "")],
        pkgs=["cmake", "ninja", "pcre2-dev", "ncurses-dev"],
        build=["cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release "
               "-DCMAKE_EXE_LINKER_FLAGS=-static", "cmake --build build -j$(nproc)",
               "cp build/fish /tmp/out/"],
        experimental=True, arm=False,
    ),
    "netsniff": dict(
        lang="c", slug="netsniff-ng/netsniff-ng", tag_prefix="v",
        bins=[("netsniff-ng", ""), ("ifpps", "")],
        pkgs=["autoconf", "automake", "libtool", "libnl3", "libnl3-dev", "libnl3-static", "libpcap-dev",
              "ncurses-dev", "ncurses-static", "libnetfilter_queue-dev", "bash"],
        build=["chmod +x configure && ./configure",
               "make -j$(nproc) LDFLAGS=-static",
               "find . -maxdepth 2 -type f \\( -name netsniff-ng -o -name ifpps \\) "
               "-exec cp {} /tmp/out/ \\;"],
        experimental=True,
    ),
    "suricata": dict(
        lang="c",
        base_image="rust:1-alpine",
        tarball="https://www.openinfosecfoundation.org/download/suricata-{v}.tar.gz",
        bins=[("suricata", "")],
        pkgs=["autoconf", "automake", "libtool", "pkgconf", "pcre-dev", "pcre-static", "pcre2-dev", "yaml-dev",
              "yaml-static", "jansson-dev", "jansson-static", "libpcap-dev",
              "openssl-libs-static", "zlib-static"],
        # alpine ships no static libpcre2 (only .so) -- build it from source
        # so suricata's static link check (pcre2_compile_8 in -lpcre2-8) passes.
        pre=["mkdir -p /pcre2-src /opt/pcre2",
             "curl -fsSL --retry 3 https://github.com/PCRE2Project/pcre2/releases/download/pcre2-10.45/pcre2-10.45.tar.gz | "
             "gunzip -c | tar x -C /pcre2-src --strip-components=1",
             "cd /pcre2-src && ./configure --prefix=/opt/pcre2 --disable-shared --enable-static "
             "&& make -j$(nproc) && make install && cd /src",
             "(cd rust && cargo update -p lexical-core 2>/dev/null || cargo update 2>/dev/null || true)"],
        build=["PKG_CONFIG_PATH=/opt/pcre2/lib/pkgconfig PKG_CONFIG='pkg-config --static' "
               "./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var "
               # libtool drops a bare -static on the final link, so CFLAGS carries
               # it; -no-pie stops the default PIE link from winning over -static
               "LDFLAGS='-static -no-pie -L/opt/pcre2/lib' CFLAGS='-O2 -static -no-pie' "
               "CPPFLAGS='-I/opt/pcre2/include' "
               "--disable-python --disable-lua --disable-nfqueue "
               "--disable-nflog --disable-gccmarch-native",
               # libtool only honours -all-static, and only at link time
               "make -j$(nproc) LDFLAGS='-all-static -L/opt/pcre2/lib'",
               "cp src/suricata /tmp/out/"],
        experimental=True,
    ),
            # BLOCKED: cli-only build still links tshark against shared
        # libwsutil; ENABLE_STATIC=ON insufficient on musl. Next step:
        # -DBUILD_SHARED_LIBS='OFF' patch or ship dynamic w/ bundled libs
"wireshark": dict(
        lang="cxx",
        slug="wireshark/wireshark", tag_prefix="v",
        bins=[("tshark", ""), ("dumpcap", ""), ("editcap", ""), ("mergecap", ""),
              ("capinfos", ""), ("captype", ""), ("rawshark", ""), ("text2pcap", ""),
              ("randpkt", ""), ("reordercap", ""), ("sharkd", ""), ("dftest", ""),
              ("tfshark", "")],
        pkgs=["cmake", "ninja", "perl", "flex", "glib-dev", "glib-static", "libgcrypt-dev",
              "libgcrypt-static", "c-ares-dev", "libxml2-dev", "libssh-dev", "libpcap-dev",
              "pcre2-dev", "zlib-static", "speexdsp-dev"],
        # DISABLED in tools.yaml: static 4.x on musl is infeasible -- alpine
        # ships no static c-ares/gnutls/krb5, and even Alpine builds it dynamic.
        # The repo keeps its hand-built static 2.6.17 binaries.
        build=["cmake -B build -G Ninja -DBUILD_wireshark=OFF -DBUILD_qtapps=OFF "
               "-DENABLE_STATIC=ON -DENABLE_PCAP=OFF -DZLIB_INCLUDE_DIR=/usr/include "
               "-DZLIB_LIBRARY=/lib/libz.a -DCMAKE_BUILD_TYPE=Release "
               "-DCMAKE_EXE_LINKER_FLAGS=-static", "cmake --build build -j$(nproc)",
               "find build -maxdepth 4 -name tshark -type f -exec cp {} /tmp/out/ \\; 2>/dev/null || true",
               "for f in tshark dumpcap editcap mergecap capinfos captype rawshark "
               "text2pcap randpkt reordercap sharkd dftest tfshark; do "
               "find build -name $f -type f -exec cp {} /tmp/out/ \\; 2>/dev/null || echo missing-$f; done; "
               "ls /tmp/out/"],
        experimental=True, arm=False,
    ),
    "zmap": dict(
        lang="c", slug="zmap/zmap", tag_prefix="v",
        bins=[("zmap", ""), ("ztee", ""), ("zgrab2", "")],
        pkgs=["cmake", "gengetopt", "flex", "byacc", "json-c-dev", "libunistring-dev",
              "libunistring-static", "libpcap-dev", "judy-dev", "gmp-dev", "go", "pkgconf"],
        build=["cmake -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_EXE_LINKER_FLAGS=-static "
               "-DWITH_DEMOS=OFF -DWITH_WERROR=OFF", "cmake --build build -j$(nproc)",
               "cp build/src/zmap /tmp/out/", "cp build/src/ztee /tmp/out/",
               "CGO_ENABLED=0 GOBIN=/tmp/out GOTOOLCHAIN=auto "
               "go install github.com/zmap/zgrab2/cmd/zgrab2@latest"],
        experimental=True, arm=False,
    ),
}

# tor is special (C daemon + Go pluggable transports); see build/tor/Dockerfile.


RECIPES["3proxy"] = dict(
    lang="c", slug="3proxy/3proxy",
    bins=[("3proxy", "")],
    # hang-guard: their Makefile occasionally stalls on CI runners
    # Plugins are .so — disable for static build to avoid "attempted static
    # link of dynamic object" (ld.so plugin error). Plugin support is not
    # needed for the standalone proxy binary we ship.
    build=["timeout -k 30 600 make -f Makefile.Linux -j$(nproc) CC=gcc LDFLAGS='-static' WITH_PLUGINS=no",
           "cp bin/3proxy /tmp/out/"],
    arm_build=["make -f Makefile.Linux clean 2>/dev/null; rm -rf bin/*.o bin/3proxy",
               "timeout -k 30 600 make -f Makefile.Linux -j$(nproc) CC=arm-linux-musleabihf-gcc LDFLAGS='-static' WITH_PLUGINS=no",
               "cp bin/3proxy /tmp/out-arm/"],
    experimental=True,
)

RECIPES["ngrep"] = dict(
    lang="c", clone_url="https://github.com/jpr5/ngrep.git",
    tag_prefix="v", example_version="1.49.0",
    bins=[("ngrep", "")],
    pkgs=["libpcap-dev", "pcre2-dev", "pkgconf"],
    build=["test -x configure || autoreconf -fi",
           "./configure --enable-pcre2 LDFLAGS=-static",
           "make -j$(nproc)", "cp ngrep /tmp/out/"],
)

RECIPES["ptunnel-ng"] = dict(
    lang="c", slug="utoni/ptunnel-ng", tag_prefix="v",
    bins=[("ptunnel-ng", "")],
    # musl's netinet/in.h doesn't set _LINUX_IN6_H, so linux/in6.h redefines
    # the v6 structs; pre-defining the guard avoids the clash
    pkgs=["autoconf", "automake", "libtool"],
    build=[AUTOGEN, "./configure LDFLAGS=-static CFLAGS='-D_LINUX_IN6_H'",
           "make -j$(nproc)", "cp src/ptunnel-ng /tmp/out/"],
)

RECIPES["tor"] = dict(
    lang="c", clone_url="https://gitlab.torproject.org/tpo/core/tor.git",
    tag_prefix="tor-", example_version="0.4.9.11",
    bins=[("tor", "")],
    pkgs=["autoconf", "automake", "libtool", "pkgconf", "libevent-dev", "libevent-static",
          "openssl-dev", "openssl-libs-static", "zlib-static", "zlib-dev", "xz-dev",
          # static link pulls in the compression libs tor optionally uses
          "xz-static", "zstd-static", "zstd-dev"],
    # minimal relay-free static daemon; pluggable transports live in pt_bridges
    build=["./autogen.sh",
           "./configure --disable-systemd --disable-unittests --disable-libscrypt "
           "--disable-module-relay --disable-asciidoc --disable-manpage "
           # --enable-static-tor demands --with-*-dir for every dep; the static
           # libs are all in /usr here, so plain -static is enough
           "LDFLAGS=-static",
           "make -j$(nproc)", "cp src/app/tor /tmp/out/"],
    experimental=True, arm=False,
)

# OpenBSD netcat, via Debian's portable patchset (the same source alpine's
# netcat-openbsd package uses). The binary this replaced was glibc-linked with
# no recipe at all, the last dynamic binary in the repo.
_LIBBSD = "0.12.2"
_LIBMD = "1.1.0"
# upstream libbsd answers GitHub runners with HTTP 418; debian's pool serves the
# same tarballs, and this build already pulls netcat from there
_DEB_POOL = "http://deb.debian.org/debian/pool/main"
_NC_PRE = [
    # libbsd carries strtonum/arc4random for the OpenBSD source; alpine ships
    # it shared-only, so build a static one
    "mkdir -p /libbsd /opt/libbsd",
    f"curl -fsSL --retry 3 {_DEB_POOL}/libb/libbsd/libbsd_{_LIBBSD}.orig.tar.xz "
    "| unxz | tar x -C /libbsd --strip-components=1",
    "cd /libbsd && ./configure --prefix=/opt/libbsd --disable-shared --enable-static "
    "&& make -j$(nproc) && make install && cd /src",
    # debian keeps the linux port as a quilt series
    'while read -r p; do patch -Np1 < "debian/patches/$p"; done < debian/patches/series',
    # the port calls b64_ntop, which musl has no equivalent of. base64.c is
    # vendored in build/nc/: the runner could not reach the distro git host it
    # used to come from, and a build should not depend on one being up
    r"sed -i '/^int[[:space:]]*remote_connect(/i "
    r"int b64_ntop(const unsigned char *, size_t, char *, size_t);' socks.c",
    r"""sed -i '/SRCS=/s;\(.*\);& base64.c;' Makefile""",
]
# IPTOS_DSCP_VA is a linux/glibc define musl's netinet/ip.h lacks
_NC_CFLAGS = "-O2 -static -DIPTOS_DSCP_VA=0xb0"

RECIPES["nc"] = dict(
    lang="c",
    tarball="https://salsa.debian.org/debian/netcat-openbsd/-/archive/"
            "debian/{v}/netcat-openbsd-debian-{v}.tar.gz",
    bins=[("nc", "")],
    pkgs=["linux-headers", "libmd-dev", "patch"],
    files=["base64.c"],
    pre=_NC_PRE,
    build=["mkdir -p /tmp/out",
           f"make CFLAGS='{_NC_CFLAGS} -I/opt/libbsd/include' "
           "LDFLAGS='-static -L/opt/libbsd/lib' LIBS='-lbsd -lmd'",
           "cp nc /tmp/out/"],
    # ARM needs its own libmd and libbsd; alpine cross-ships neither
    arm_build=["make clean || true",
               "mkdir -p /libmd-arm /libbsd-arm /opt/arm-deps",
               f"curl -fsSL --retry 3 {_DEB_POOL}/libm/libmd/libmd_{_LIBMD}.orig.tar.xz "
               "| unxz | tar x -C /libmd-arm --strip-components=1",
               "cd /libmd-arm && ./configure --host=arm-linux-musleabihf --prefix=/opt/arm-deps "
               "--disable-shared --enable-static && make -j$(nproc) && make install && cd /src",
               f"curl -fsSL --retry 3 {_DEB_POOL}/libb/libbsd/libbsd_{_LIBBSD}.orig.tar.xz "
               "| unxz | tar x -C /libbsd-arm --strip-components=1",
               "cd /libbsd-arm && ./configure --host=arm-linux-musleabihf --prefix=/opt/arm-deps "
               "--disable-shared --enable-static CPPFLAGS=-I/opt/arm-deps/include "
               "LDFLAGS=-L/opt/arm-deps/lib && make -j$(nproc) && make install && cd /src",
               f"make CC=arm-linux-musleabihf-gcc CFLAGS='{_NC_CFLAGS} -I/opt/arm-deps/include' "
               "LDFLAGS='-static -L/opt/arm-deps/lib' LIBS='-lbsd -lmd'",
               "mkdir -p /tmp/out-arm && cp nc /tmp/out-arm/"],
)

RECIPES["tangd"] = dict(
    lang="c", slug="latchset/tang", tag_prefix="v",
    bins=[("tangd", "")],
    pkgs=["meson", "jose-dev", "http-parser-dev", "pkgconf"],
    build=["mkdir -p /tmp/out",
           "meson setup build",
           "meson compile -C build",
           "cp build/src/tangd /tmp/out/"],
    experimental=True,
)

