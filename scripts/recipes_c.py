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
        build=["make CC=gcc LDFLAGS=-static -j$(nproc)", "cp dsvpn /tmp/out/"],
        arm_build=["make clean || true",
                   "make CC=arm-linux-musleabihf-gcc LDFLAGS=-static -j$(nproc)",
                   "cp dsvpn /tmp/out-arm/"],
    ),
    "corkscrew": dict(
        lang="c", slug="bryanpkc/corkscrew",
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
        lang="c", slug="koct9i/ioping",
        bins=[("ioping", "")],
        build=["make -j$(nproc) LDFLAGS=-static", "cp ioping /tmp/out/"],
        arm_build=["make clean || true",
                   "make -j$(nproc) CC=arm-linux-musleabihf-gcc LDFLAGS=-static",
                   "cp ioping /tmp/out-arm/"],
    ),
    "icmptunnel": dict(
        lang="c", slug="DhavalKapil/icmptunnel",
        bins=[("icmptunnel", "")],
        build=["make -j$(nproc) LDFLAGS=-static", "cp tunnel /tmp/out/icmptunnel"],
        arm_build=["make clean || true",
                   "make -j$(nproc) CC=arm-linux-musleabihf-gcc LDFLAGS=-static",
                   "cp tunnel /tmp/out-arm/icmptunnel"],
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
        pkgs=["autoconf", "automake"],
        pre=["curl -fsSLO https://raw.githubusercontent.com/troydhanson/uthash/master/include/uthash.h && mkdir -p src && cp uthash.h src/"],
        build=[AUTOGEN, "./configure LDFLAGS=-static", "make -j$(nproc)",
               "cp logtop /tmp/out/"], experimental=True,
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
        pkgs=["autoconf", "automake", "pkgconf", "libevent-static", "ncurses-static", "ncurses-dev"],
        build=[AUTOGEN, "./configure LDFLAGS=-static",
               "make -j$(nproc)", "cp tmux /tmp/out/"],
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
                   "./configure --host=arm-linux-musleabihf LDFLAGS=-static --disable-zlib",
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
        build=["./configure --without-oniguruma LDFLAGS=-static",
               "make -j$(nproc) LC_ALL=C", "cp jq /tmp/out/"],
        arm_build=['mkdir -p /src-arm && curl -fsSL "https://github.com/jqlang/jq/releases/download/jq-${VERSION}/jq-${VERSION}.tar.gz" | gunzip -c | tar x -C /src-arm --strip-components=1',
                   "cd /src-arm && ./configure --host=arm-linux-musleabihf --without-oniguruma LDFLAGS=-static",
                   "make -j$(nproc) LC_ALL=C", "cp jq /tmp/out-arm/"],
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
        clone_url="https://github.com/curl/curl.git", tag_prefix="curl-",
        transform_note="", example_version="8.11.1",
        bins=[("curl", "")],
        pkgs=["autoconf", "automake", "libtool", "openssl-dev", "openssl-libs-static",
              "zlib-static", "nghttp2-static", "nghttp2-dev", "ca-certificates"],
        build=["./buildconf && ./configure --disable-shared --enable-static "
               "--with-openssl --with-nghttp2 --with-zlib --without-libpsl "
               "--without-brotli --without-zstd --without-libidn2 --disable-ldap --disable-ldaps",
               "make -j$(nproc) LDFLAGS=-static", "cp src/curl /tmp/out/"],
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
        lang="cxx", slug="DNS-OARC/PacketQ",
        bins=[("packetq", "")],
        pkgs=["autoconf", "automake", "libtool"],
        build=[AUTOGEN, "./configure LDFLAGS=-static", "make -j$(nproc)",
               "cp src/packetq /tmp/out/"],
    ),

    # ------------------------------------------- experimental / heavy builds --
    "atop": dict(
        lang="c", slug="Atoptool/atop", tag_prefix="v",
        bins=[("atop", "")],
        pkgs=["ncurses-static", "ncurses-dev", "zlib-static"],
        build=["make -j$(nproc) LDFLAGS=-static", "cp atop /tmp/out/"],
        experimental=True,
    ),
    "nmap": dict(
        lang="c",
        tarball="https://nmap.org/dist/nmap-{v}.tar.bz2", tarflags="jx",
        bins=[("nmap", ""), ("nping", "")],
        pkgs=["openssl-dev", "openssl-libs-static", "pcre2-dev", "pcre2-static", "zlib-static", "libssh2-dev"],
        build=["./configure --without-zenmap --without-ndiff --without-nmap-update "
               "--with-libpcap=included --with-libpcre=included --with-zlib=included "
               "--with-openssl=/usr LDFLAGS=-static",
               "make -j$(nproc)", "cp nmap nping /tmp/out/"],
        experimental=True,
    ),
    "lnav": dict(
        lang="cxx", slug="tstack/lnav", tag_prefix="v",
        bins=[("lnav", "")],
        pkgs=["cmake", "autoconf", "automake", "libtool", "ncurses-static", "pcre2-static",
              "sqlite-static", "sqlite-dev", "zlib-static", "curl-dev", "openssl-libs-static"],
        build=["./autogen.sh && ./configure LDFLAGS=-static",
               "make -j$(nproc)", "cp src/lnav /tmp/out/"],
        experimental=True,
    ),
    "sslh": dict(
        lang="c", slug="yrutschle/sslh", tag_prefix="v",
        bins=[("sslh", "")],
        pkgs=["pcre2-dev", "pcre2-static", "libconfig-dev", "libev-dev", "openssl-libs-static"],
        build=["make -j$(nproc) sslh-select CC=gcc LDFLAGS=-static USELIBCONFIG=1",
               "cp sslh-select /tmp/out/sslh"],
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
        lang="c", slug="kristapsdz/openrsync", branch=True,
        bins=[("openrsync", "")],
        pkgs=["autoconf", "automake"],
        build=[AUTOGEN, "./configure LDFLAGS=-static", "make -j$(nproc)",
               "cp openrsync /tmp/out/"],
        experimental=True,
    ),
    "pdns": dict(
        lang="c", slug="gamelinux/passivedns",
        bins=[("pdns", "")],
        pkgs=["autoconf", "automake", "ldns-dev", "libpcap-dev"],
        build=[AUTOGEN, "./configure LDFLAGS=-static", "make -j$(nproc)",
               "cp src/passivedns /tmp/out/pdns"],
        experimental=True,
    ),
    "vi": dict(
        lang="c", slug="johnsonjh/OpenVi",
        bins=[("vi", "")],
        pkgs=["cmake", "ncurses-static"],
        build=["cmake -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_EXE_LINKER_FLAGS=-static",
               "cmake --build build -j$(nproc)", "find build -name 'ovi' -exec cp {} /tmp/out/vi \\; || cp build/bin/ovi /tmp/out/vi"],
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
        lang="c", slug="fish-shell/fish-shell",
        bins=[("fish", "")],
        pkgs=["cmake", "ninja", "rust", "cargo", "pcre2-dev", "pcre2-static", "ncurses-dev"],
        build=["cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release "
               "-DCMAKE_EXE_LINKER_FLAGS=-static", "cmake --build build -j$(nproc)",
               "cp build/fish /tmp/out/"],
        experimental=True, arm=False,
    ),
    "netsniff": dict(
        lang="c", slug="netsniff-ng/netsniff-ng", tag_prefix="v",
        bins=[("netsniff-ng", ""), ("trafgen", ""), ("mausezahn", ""), ("flowtop", ""),
              ("ifpps", ""), ("astraceroute", ""), ("bpfc", ""), ("curvetun", "")],
        pkgs=["autoconf", "automake", "libtool", "libnl3-dev", "libnl3-static", "libpcap-dev",
              "ncurses-static", "libnetfilter-queue-dev"],
        build=[AUTOGEN, "./configure LDFLAGS=-static", "make -j$(nproc)",
               "cp netsniff-ng trafgen mausezahn flowtop ifpps astraceroute bpfc curvetun /tmp/out/"],
        experimental=True,
    ),
    "suricata": dict(
        lang="c",
        tarball="https://www.openinfosecfoundation.org/download/suricata-{v}.tar.gz",
        bins=[("suricata", "")],
        pkgs=["autoconf", "automake", "libtool", "pcre2-dev", "pcre2-static", "yaml-dev",
              "jansson-dev", "libpcap-dev", "openssl-libs-static", "zlib-static", "cargo"],
        build=["./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var "
               "LDFLAGS=-static --disable-python --disable-lua --disable-nfqueue "
               "--disable-nflog --disable-gccmarch-native",
               "make -j$(nproc)", "cp src/suricata /tmp/out/"],
        experimental=True,
    ),
    "wireshark": dict(
        lang="cxx",
        tarball="https://www.wireshark.org/download/src/wireshark-{v}.tar.xz",
        bins=[("tshark", ""), ("dumpcap", ""), ("editcap", ""), ("mergecap", ""),
              ("capinfos", ""), ("captype", ""), ("rawshark", ""), ("text2pcap", ""),
              ("randpkt", ""), ("reordercap", ""), ("sharkd", ""), ("dftest", ""),
              ("tfshark", "")],
        pkgs=["cmake", "ninja", "glib-dev", "glib-static", "libpcap-dev",
              "pcre2-dev", "zlib-static", "speexdsp-dev"],
        build=["cmake -B build -G Ninja -DBUILD_wireshark=OFF -DBUILD_qtapps=OFF "
               "-DBUILD_strstrip=ON -DENABLE_PCAP=ON -DCMAKE_BUILD_TYPE=Release "
               "-DCMAKE_EXE_LINKER_FLAGS=-static", "cmake --build build -j$(nproc)",
               "cp build/run/tshark build/run/dumpcap build/run/editcap build/run/mergecap "
               "build/run/capinfos build/run/captype build/run/rawshark build/run/text2pcap "
               "build/run/randpkt build/run/reordercap build/run/sharkd build/run/dftest /tmp/out/ || true",
               "cp build/run/* /tmp/out/ 2>/dev/null || true"],
        experimental=True, arm=False,
    ),
    "zmap": dict(
        lang="c", slug="zmap/zmap", tag_prefix="v",
        bins=[("zmap", ""), ("ztee", ""), ("zgrab2", "")],
        pkgs=["cmake", "gengetopt", "json-c-dev", "unistring-dev", "libpcap-dev"],
        build=["cmake -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_EXE_LINKER_FLAGS=-static "
               "-DWITH_DEMOS=OFF -DWITH_WERROR=OFF", "cmake --build build -j$(nproc)",
               "cp build/src/zmap /tmp/out/", "cp build/src/ztee /tmp/out/ || true",
               "GOBIN=/tmp/out go install github.com/zmap/zgrab2/cmd/zgrab2@latest || true"],
        experimental=True, arm=False,
    ),
}

# tor is special (C daemon + Go pluggable transports); see build/tor/Dockerfile.
