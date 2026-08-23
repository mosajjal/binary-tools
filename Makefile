YQ := $(shell command -v yq || echo /opt/toolbelt/yq)

# ---- per-tool ------------------------------------------------------------
# make build T=jq V=1.8.2        build image (V defaults to tools.yaml version)
# make test T=jq                 smoke-test only (reuses cached image)
# make extract T=jq              copy binaries out of the image into dist/
# make check                     report outdated upstreams
# make gen                       regenerate all Dockerfiles from recipes
T ?= jq
V ?=

ifeq ($(strip $(V)),)
VER = $(shell $(YQ) -r '.tools[] | select(.name == "$(T)") | .version' tools.yaml)
else
VER = $(V)
endif

.PHONY: build test extract check check-pretty gen list clean

build:
	./scripts/build.sh $(T) $(VER)

test:
	./scripts/build.sh $(T) $(VER)

extract:
	./scripts/build.sh $(T) $(VER) --extract

check:
	@$(YQ) -o=json '.tools' tools.yaml | GITHUB_TOKEN=$${GITHUB_TOKEN:-$$(gh auth token)} \
		python3 scripts/check_upstream.py

check-pretty:
	@$(YQ) -o=json '.tools' tools.yaml | GITHUB_TOKEN=$${GITHUB_TOKEN:-$$(gh auth token)} \
		python3 scripts/check_upstream.py > /dev/null

gen:
	python3 scripts/gen_dockerfiles.py

list:
	@$(YQ) -r '.tools[] | .name' tools.yaml | column -c 120

clean:
	rm -rf dist
