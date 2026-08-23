"""Go build recipe for the Tor pluggable transports shipped alongside tor:
lyrebird (obfs4), snowflake client, webtunnel client/server.
Cloned from gitlab.torproject.org at branch HEAD (webtunnel cuts no tags).
Consumed by gen_dockerfiles.py."""

RECIPES = {
    "pt_bridges": dict(
        lang="go", branch=True, example_version="HEAD",
        clone_url="https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake.git",
        extra_clones=[
            ("lyrebird", "https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird.git"),
            ("webtunnel", "https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/webtunnel.git"),
        ],
        bins=[
            ("snowflake", "/src/client"),
            ("lyrebird", "/src/lyrebird/cmd/lyrebird"),
            ("webtunnel_client", "/src/webtunnel/main/client"),
            ("webtunnel_server", "/src/webtunnel/main/server"),
        ],
        build=[
            "(cd /src && go build -trimpath -ldflags='-s -w' -o /tmp/x64_snowflake ./client)",
            "(cd /src/lyrebird && go build -trimpath -ldflags='-s -w' -o /tmp/x64_lyrebird ./cmd/lyrebird)",
            "(cd /src/webtunnel && go build -trimpath -ldflags='-s -w' -o /tmp/x64_webtunnel_client ./main/client)",
            "(cd /src/webtunnel && go build -trimpath -ldflags='-s -w' -o /tmp/x64_webtunnel_server ./main/server)",
        ],
        experimental=True, arm=False,
    ),
}
