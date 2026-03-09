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

This repository includes two runnable agents:

- `agent_tcp`: listens on `0.0.0.0:12345`
- `agent_socket`: listens on `spoa_agent/spoa.sock`

Run one of them directly with Cargo:

```bash
cargo run --example agent_tcp
```

```bash
cargo run --example agent_socket
```

If you prefer autoreload during development, the helper recipes are:

```bash
just agent_tcp
just agent_socket
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
podman run -d --name haproxy --network=host -v "${PWD}/spoa_agent:/var/run/haproxy" haproxy-spoe
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

The repository currently defines two SPOE engines:

- `test`: TCP backend `127.0.0.1:12345`
- `test-socket`: UNIX socket backend `/var/run/haproxy/spoa.sock`

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
    mode tcp
    server rust-agent 127.0.0.1:12345

backend spoe-test-socket
    mode tcp
    server local-agent unix@/var/run/haproxy/spoa.sock

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

spoe-message log-request
    args ip=src country=hdr(CF-IPCountry) user_agent=hdr(User-Agent)
    event on-frontend-http-request

[test-socket]
spoe-agent test-socket
    messages    check-client-ip log-request
    option      var-prefix spoe_test_socket
    option      continue-on-error
    timeout     processing 10ms
    use-backend spoe-test-socket
    log         global
```
