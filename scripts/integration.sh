#!/usr/bin/env bash
# End-to-end check against a real HAProxy.
#
# Starts both example agents, runs the official HAProxy image with haproxy.cfg and
# spoe-test.conf, and asserts that a request comes back carrying the variable each agent set.
#
#   CONTAINER_ENGINE  podman (default) or docker
#   HAPROXY_VERSION   haproxy image tag, e.g. 3.4 (default: latest)
#
# Linux only: HAProxy reaches the agents through --network=host, which Docker Desktop and
# podman machine (macOS, Windows) do not provide for processes on the host.
set -euo pipefail

engine="${CONTAINER_ENGINE:-podman}"
version="${HAPROXY_VERSION:-latest}"
# Fully qualified, so podman never stops to ask which registry a short name means.
image="docker.io/library/haproxy:${version}"
container="spop-integration"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
target_dir="${CARGO_TARGET_DIR:-target}"

logs="$(mktemp -d)"
pids=()

cleanup() {
    # The ${a[@]+...} form keeps bash 3.2 (macOS) from treating an empty array as unset under
    # `set -u`, which happens when the script fails before any agent has started.
    for pid in ${pids[@]+"${pids[@]}"}; do
        kill "$pid" 2>/dev/null || true
    done
    "$engine" rm -f "$container" >/dev/null 2>&1 || true
}
trap cleanup EXIT

fail() {
    echo "error: $*" >&2
    for log in "$logs"/*.log; do
        echo "==> $(basename "$log")" >&2
        cat "$log" >&2
    done
    echo "==> haproxy" >&2
    "$engine" logs "$container" >&2 2>&1 || true
    exit 1
}

# Waits up to ~10s for a condition, failing if an agent died in the meantime (port in use,
# socket path not writable, ...).
wait_for() {
    local what="$1"
    shift
    for _ in $(seq 1 50); do
        if "$@"; then
            return 0
        fi
        for pid in "${pids[@]}"; do
            kill -0 "$pid" 2>/dev/null || fail "an agent exited while waiting for ${what}"
        done
        sleep 0.2
    done
    fail "timed out waiting for ${what}"
}

cargo build --examples

mkdir -p spoa_agent
chmod 777 spoa_agent
rm -f spoa_agent/spoa.sock

"${target_dir}/debug/examples/agent_tcp" >"$logs/agent_tcp.log" 2>&1 &
pids+=($!)
"${target_dir}/debug/examples/agent_socket" >"$logs/agent_socket.log" 2>&1 &
pids+=($!)

# Rust's stdout is line-buffered even into a file, so the banner shows up as soon as the
# listener is bound. Probing the port instead would open a stray connection on the agent.
wait_for "agent_tcp to listen" grep -q 'listening on port' "$logs/agent_tcp.log"
wait_for "agent_socket to listen" test -S spoa_agent/spoa.sock

"$engine" rm -f "$container" >/dev/null 2>&1 || true
# --pull=always so a cached image cannot pass for the current release of that tag.
"$engine" run -d --name "$container" \
    --pull=always \
    --network=host \
    --security-opt label=disable \
    -v "$root/haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro" \
    -v "$root/spoe-test.conf:/usr/local/etc/haproxy/spoe-test.conf:ro" \
    -v "$root/spoa_agent:/var/run/haproxy" \
    "$image" >/dev/null || fail "could not start ${image}"

# Retry rather than expect the first request to pass:
# - the `option spop-check` health checks need a few seconds to mark both agents UP;
# - haproxy.cfg rejects the connection when the random ip_score is below 20, about one
#   request in five.
for attempt in $(seq 1 30); do
    # Header lines end in CRLF; dropping the CRs lets `grep -x` require the whole line, so a
    # value that merely starts with "tequila" does not count.
    if headers="$(curl -s -o /dev/null -D - --max-time 2 -H 'CF-IPCountry: xx' http://127.0.0.1:5000)" &&
        headers="${headers//$'\r'/}" &&
        grep -q '^HTTP/[0-9.]* 200' <<<"$headers" &&
        grep -qix 'x-spoe-var_socket: tequila' <<<"$headers" &&
        grep -qix 'x-spoe_var_tcp: tequila' <<<"$headers"; then

        # A frame the agent could not decode costs that agent its connection; HAProxy then
        # retries on a new one, so a single success does not rule it out.
        if grep -q 'Frame read error' "$logs"/*.log; then
            fail "an agent failed to decode a frame"
        fi

        haproxy_version="$("$engine" exec "$container" haproxy -v 2>/dev/null | head -n 1)"
        echo "OK: ${haproxy_version:-haproxy:${version}}: both agents answered (attempt ${attempt})"
        exit 0
    fi
    sleep 1
done

fail "no response carried both SPOE variables after ${attempt} attempts"
