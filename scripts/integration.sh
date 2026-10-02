#!/usr/bin/env bash
# End-to-end check against a real HAProxy.
#
# Starts the example agents, runs the official HAProxy image with haproxy.cfg and
# spoe-test.conf, and asserts that a request comes back carrying the variables they set:
#
# - agent_tcp and agent_socket each set a fixed value, over TCP and a UNIX socket;
# - agent_args echoes what it decoded from the echo-args message (unnamed, repeated and
#   non-UTF-8 argument names), which must match what spoe-test.conf tells HAProxy to send.
#
# Finally it sends agent_args a malformed frame and checks the decode error stays short.
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
keep_logs=""
pids=()

cleanup() {
    # The ${a[@]+...} form keeps bash 3.2 (macOS) from treating an empty array as unset under
    # `set -u`, which happens when the script fails before any agent has started.
    for pid in ${pids[@]+"${pids[@]}"}; do
        kill "$pid" 2>/dev/null || true
    done
    "$engine" rm -f "$container" >/dev/null 2>&1 || true

    # Kept after a failure, for a closer look than the dump in `fail` gives.
    if [[ -z "$keep_logs" ]]; then
        rm -rf "$logs"
    fi
}
trap cleanup EXIT

fail() {
    keep_logs=1
    echo "error: $*" >&2
    echo "agent logs kept in $logs" >&2
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
"${target_dir}/debug/examples/agent_args" >"$logs/agent_args.log" 2>&1 &
pids+=($!)

# Rust's stdout is line-buffered even into a file, so the banner shows up as soon as the
# listener is bound. Probing the port instead would open a stray connection on the agent.
wait_for "agent_tcp to listen" grep -q 'listening on port' "$logs/agent_tcp.log"
wait_for "agent_socket to listen" test -S spoa_agent/spoa.sock
wait_for "agent_args to listen" grep -q 'listening on port' "$logs/agent_args.log"

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

# What agent_args must report for spoe-test.conf's echo-args message:
#   answer=int(42)                      named INT64
#   str(first) src str(second)          unnamed, in declaration order (src is 127.0.0.1 here)
#   country=hdr(...) country=str(...)   repeated name: Message::get returns the first, "xx",
#                                       and the later "shadowed" is still in the list
#   bad\xff=str(lossy)                  non-UTF-8 name, looked up as "bad\u{FFFD}"
# `all=` lists every argument in the order received, so a reordered, dropped or altered
# argument fails even where the lookups cannot see it.
expected_args='x-spoe-args: answer=42 country=xx lossy=lossy unnamed=first,127.0.0.1,second'
expected_args+=' all=answer:42,:first,:127.0.0.1,country:xx,country:shadowed,:second,bad\u{fffd}:lossy'

# Strips the CRs from header lines and lowercases the header names, leaving values untouched:
# names are case-insensitive (HAProxy sends them in lowercase), values must match exactly.
normalize_headers() {
    tr -d '\r' | awk '{ i = index($0, ":"); if (i) $0 = tolower(substr($0, 1, i - 1)) substr($0, i); print }'
}

# Retry rather than expect the first request to pass:
# - the `option spop-check` health checks need a few seconds to mark the agents UP;
# - haproxy.cfg rejects the connection when the random ip_score is below 20, about one
#   request in five.
answered=""
for attempt in $(seq 1 30); do
    # `grep -xF` requires the whole line, exactly: a value that merely starts with the expected
    # one, or differs only in case, does not count.
    if headers="$(curl -s -o /dev/null -D - --max-time 2 -H 'CF-IPCountry: xx' http://127.0.0.1:5000 |
        normalize_headers)" &&
        grep -q '^HTTP/[0-9.]* 200' <<<"$headers" &&
        grep -qxF 'x-spoe-var_socket: tequila' <<<"$headers" &&
        grep -qxF 'x-spoe_var_tcp: tequila' <<<"$headers" &&
        grep -qxF "$expected_args" <<<"$headers"; then
        answered=1
        break
    fi
    sleep 1
done

if [[ -z "$answered" ]]; then
    echo "last response headers:" >&2
    echo "${headers:-<none>}" >&2
    fail "no response carried all the SPOE variables after ${attempt} attempts"
fi

# A frame an agent could not decode costs that agent its connection; HAProxy then retries on
# a new one, so a single success does not rule it out.
if grep -q 'Frame read error' "$logs"/*.log; then
    fail "an agent failed to decode a frame"
fi

# Last, a malformed frame straight to agent_args: a 5-byte frame whose type byte is 0, which is
# not a frame type. The codec must name the error kind and offset, not dump the frame's bytes.
printf '\x00\x00\x00\x05\x00\x00\x00\x00\x01' >/dev/tcp/127.0.0.1/12346
wait_for "agent_args to reject the malformed frame" \
    grep -qxF 'Frame read error: Failed to parse frame: Alt at byte 4' "$logs/agent_args.log"

haproxy_version="$("$engine" exec "$container" haproxy -v 2>/dev/null | head -n 1)"
echo "OK: ${haproxy_version:-haproxy:${version}}: all agents answered (attempt ${attempt})"
