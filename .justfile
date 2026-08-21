# Set the image name
IMAGE_NAME := "haproxy-spoe"
CONTAINER_NAME := "haproxy"
SOCKET_DIR := "${PWD}/spoa_agent"

default: clippy
  @just --list

# Run HAProxy container with port 5000 exposed
#
# "--security-opt label=disable" is needed where SELinux is enforcing: agent_socket creates
# spoa.sock inside the mounted directory *after* the mount is labelled, so the new socket
# carries the host label and the container is denied access to it. ":z" does not help, because
# it only relabels content that already exists at mount time.
run: build prepare
    podman run -d --name {{CONTAINER_NAME}} --network=host --security-opt label=disable -v {{SOCKET_DIR}}:/var/run/haproxy {{IMAGE_NAME}}

# Ensure the socket directory exists and has proper permissions
prepare:
    mkdir -p {{SOCKET_DIR}}
    chmod -R 777 {{SOCKET_DIR}}

# Build the HAProxy image
build:
    podman build -t {{IMAGE_NAME}} .

# Stop and remove HAProxy container
stop:
    podman stop {{CONTAINER_NAME}} || true
    podman rm {{CONTAINER_NAME}} || true

# Restart the container (stop -> build -> run)
restart:
    just stop
    just build
    just run

# Check HAProxy logs
logs:
    podman logs -f {{CONTAINER_NAME}}

# Test the HAProxy response
test:
    curl -v http://0:5000 -H "CF-IPCountry: xx"

# Attach to the running container for debugging
shell:
    podman exec -it {{CONTAINER_NAME}} bash

clippy: fmt cargo-test
  cargo clippy --all-targets --all-features

fmt:
  cargo fmt --all -- --check

cargo-test:
  cargo test --all -- --test-threads=1

# Run the example
agent_socket:
  cargo watch --ignore spoa_agent/ -x 'run --example agent_socket'

agent_tcp:
  cargo watch --ignore spoa_agent/ -x 'run --example agent_tcp'

# Run the benchmarks
bench:
  cargo bench

# Compare the decode benchmark against another revision, defaulting to the previous commit.
#
# Only `benches/decode.rs` can do this: it touches nothing but `parse_frame`, whose signature has
# survived the 0.11/0.12 API changes, so `src/` can be swapped for any revision and the benchmark
# still builds. `roundtrip.rs` and `frames.rs` use current-only API and are not comparable this
# way.
#
#   just bench-ab            # against HEAD~1
#   just bench-ab 0.11.0     # against a tag (this repo tags without a "v" prefix)
bench-ab REF='HEAD~1':
    #!/usr/bin/env bash
    set -euo pipefail

    # This recipe checks out another revision over src/, so refuse to run when that would
    # discard work. `git stash` is deliberately not used: on a clean tree it is a no-op that
    # silently benchmarks the same code twice.
    if ! git diff --quiet -- src/ || ! git diff --cached --quiet -- src/; then
        echo "error: src/ has uncommitted changes; commit or stash them first" >&2
        exit 1
    fi

    baseline_rev=$(git rev-parse --short "{{REF}}^{commit}")
    current_rev=$(git rev-parse --short "HEAD^{commit}")
    echo "==> baseline ${baseline_rev} ({{REF}})  vs  current ${current_rev}"

    restore() { git checkout HEAD -- src/; }
    trap restore EXIT

    git checkout "{{REF}}" -- src/
    cargo bench --bench decode -- --save-baseline baseline

    restore
    trap - EXIT
    cargo bench --bench decode -- --baseline baseline

coverage:
  cargo llvm-cov --all-features --workspace
