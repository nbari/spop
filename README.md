[![Test](https://github.com/nbari/spop/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/nbari/spop/actions/workflows/test.yml)
[![crates.io](https://img.shields.io/crates/v/spop.svg)](https://crates.io/crates/spop)


# spop

Library for parsing HAProxy SPOP protocol messages.

The protocol is described here: https://github.com/haproxy/haproxy/blob/master/doc/SPOE.txt

## Development

Install [Rust](https://www.rust-lang.org/tools/install). For the container-based HAProxy integration flow, also install [podman](https://podman.io). If you want to use the helper recipes, install [just](https://github.com/casey/just) too.

### Library checks

Run the test suite:

```bash
cargo test
```

Check the examples compile:

```bash
cargo check --examples
```

### Manual integration testing

This repository includes three runnable agents:

- `agent_tcp`: listens on `0.0.0.0:12345`
- `agent_socket`: listens on `spoa_agent/spoa.sock`
- `agent_args`: listens on `127.0.0.1:12346` and reads its message arguments back: unnamed
  arguments by position, a repeated name through `Message::get`, and a name that is not valid
  UTF-8. Start here to see how to read what HAProxy sends

Run one of them directly with Cargo:

```bash
cargo run --example agent_tcp
```

```bash
cargo run --example agent_socket
```

```bash
cargo run --example agent_args
```

If you prefer autoreload during development, the helper recipes are:

```bash
just agent_tcp
just agent_socket
just agent_args
```

These recipes require `cargo-watch`.

To run HAProxy in a container using the current helper recipes:

```bash
just build
just run
```

Or directly with podman:

```bash
mkdir -p spoa_agent
chmod -R 777 spoa_agent
podman build -t haproxy-spoe .
podman run -d --name haproxy --network=host --security-opt label=disable -v "${PWD}/spoa_agent:/var/run/haproxy" haproxy-spoe
```

To stop the container:

```bash
just stop
```

Or directly with podman:

```bash
podman stop haproxy
podman rm haproxy
```

To send a request to the haproxy container, type:

```bash
just test
```

Or directly:

```bash
curl -v http://0:5000 -H "CF-IPCountry: xx"
```

The current HAProxy configuration is in `haproxy.cfg`, and the current SPOE configuration is in `spoe-test.conf`.

### Current test topology

The repository currently defines three SPOE engines:

- `test`: TCP backend `127.0.0.1:12345`
- `test-socket`: UNIX socket backend `/var/run/haproxy/spoa.sock`
- `args`: TCP backend `127.0.0.1:12346`, sending the `echo-args` message to `agent_args`. Its
  summary of what it decoded comes back in the `X-SPOE-ARGS` response header

### Integration test

`scripts/integration.sh` runs the whole loop unattended: it starts the three agents, runs the
official HAProxy image with `haproxy.cfg` and `spoe-test.conf`, and checks that a response carries
the variables they set, including `agent_args`' summary of every argument it decoded. It fails if
any agent could not decode a frame. Last, it sends `agent_args` a malformed frame and checks that
the decode error names the problem and its offset without dumping the frame.

```bash
just integration        # haproxy:latest
just integration 3.2    # any haproxy image tag
```

It uses podman by default; set `CONTAINER_ENGINE=docker` to use docker. It needs Linux, because
HAProxy reaches the agents through host networking. CI runs it against HAProxy 3.2 and 3.4.

## Reading message arguments

A NOTIFY frame carries a list of messages, and each message keeps its arguments in declaration
order. Argument names are optional in `spoe-message` (`args [name=]<sample> ...`), so a name can
be empty or repeated:

```rust
use spop::{TypedData, frame::Message};

fn handle(message: &Message) {
    // First argument with this name.
    if let Some(TypedData::String(country)) = message.get("country") {
        println!("country: {country}");
    }

    // Unnamed arguments, by position.
    for (name, value) in &message.args {
        if name.is_empty() {
            println!("unnamed: {value:?}");
        }
    }
}
```

## Example

```conf
global
    log stdout format raw local0
    daemon

defaults
    log     global
    mode    http
    option  httplog
    timeout client 30s
    timeout connect 10s
    timeout server 30s

frontend main
    bind :5000
    filter spoe engine test-socket config /usr/local/etc/haproxy/spoe-test.conf
    filter spoe engine test        config /usr/local/etc/haproxy/spoe-test.conf

    tcp-request content reject if { var(sess.spoe_test_socket.ip_score) -m int lt 20 }

    http-after-response set-header X-SPOE-VAR_SOCKET %[var(txn.spoe_test_socket.my_var)]
    http-after-response set-header X-SPOE_VAR_TCP    %[var(txn.spoe_test.my_var)]

    default_backend app

backend spoe-test
    # "mode spop" is mandatory for backends holding SPOA servers; "mode tcp" is only
    # auto-converted.
    mode spop

    # Health-check with a real SPOP HELLO handshake rather than a bare TCP connect.
    option spop-check

    timeout connect 5s
    timeout server  3m

    server rust-agent 127.0.0.1:12345 check

backend spoe-test-socket
    mode spop
    option spop-check

    timeout connect 5s
    timeout server  3m

    server local-agent unix@/var/run/haproxy/spoa.sock check

backend app
    mode http
    http-request return status 200 content-type "text/plain" string "Hello"
```

And the spoe agent conf:

```conf
[test]
spoe-agent test
    messages    check-client-ip log-request
    option      var-prefix spoe_test
    option      continue-on-error
    timeout     processing 10ms
    use-backend spoe-test
    log         global

spoe-message check-client-ip
    args ip=src
    event on-client-session

# Argument names are optional: src and dst arrive unnamed (empty name), in this order.
spoe-message log-request
    args ip=src country=hdr(CF-IPCountry) user_agent=hdr(User-Agent) src dst
    event on-frontend-http-request

[test-socket]
spoe-agent test-socket
    messages    check-client-ip log-request
    option      var-prefix spoe_test_socket
    option      continue-on-error
    timeout     processing 10ms
    use-backend spoe-test-socket
    log         global

# Each [scope] is self-contained, so the messages are declared again here.
spoe-message check-client-ip
    args ip=src
    event on-client-session

spoe-message log-request
    args ip=src country=hdr(CF-IPCountry) user_agent=hdr(User-Agent) src dst
    event on-frontend-http-request
```
