# Set the image name
IMAGE_NAME := "haproxy-spoe"
CONTAINER_NAME := "haproxy"
SOCKET_DIR := "${PWD}/spoa_agent"

default: cargo-test
  @just --list

# Run HAProxy container with port 5000 exposed
run: build prepare
    podman run -d --name {{CONTAINER_NAME}} --network=host -v {{SOCKET_DIR}}:/var/run/haproxy {{IMAGE_NAME}}

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

coverage:
  cargo llvm-cov --all-features --workspace
