Changelog
=========

## 0.12.0 - 2026-08-21

### Fixed
- Fix a permanent decode stall: the frame type and flags were read with `nom::number::streaming`
  parsers even though the frame body is already fully buffered, so a frame declaring a length of
  0-4 returned `Incomplete`, which the codec mapped to `Ok(None)` without consuming the bytes.
  The connection then re-parsed the same input forever while its buffer only grew
- Bound the varint continuation bytes: `decode_varint` had no cap, so an overlong varint
  overflowed the shift and the accumulator - a panic in debug builds, a silently wrong value in
  release. Reachable from the first varint of every frame
- Reject a frame length above `MAX_FRAME_SIZE_LIMIT` (1 MiB). The length prefix is four bytes and
  untrusted, and was only compared against what was currently buffered. A peer claiming ~4 GiB
  produces a frame that never completes, so the codec never advances the read buffer and it
  accumulates everything the peer sends, without bound and never reclaimed. The peer must transmit
  those bytes to occupy them, so this is memory exhaustion rather than amplification. The ceiling
  is derived from what the protocol allows: `max-frame-size`
  must fall in `[256, tune.bufsize - 4]` and `tune.bufsize` defaults to 16384, so the negotiated
  size is normally 16380 — 1 MiB leaves about 64x headroom
- Encode every `TypedData` variant in a KV-LIST. Only `String` and `UInt32` were handled, so the
  other eight - including the `Bool` that HAPROXY-HELLO carries as `healthcheck` - were written as
  a key with no value. Both the encoder and the length calculation now delegate to
  `TypedData::to_bytes` / `TypedData::serialized_len`

### Added
- The codec now also rejects **outgoing** frames above the negotiated size, returning an error
  naming `StatusCode::TooBig`. `HAProxy` checks its own outbound frames the same way
  (`spop_conn->max_frame_size` in `src/mux_spop.c`), and failing locally surfaces the problem in
  the agent that built the frame instead of as an opaque teardown by the peer
- `StatusCode` for the SPOP error codes, with `HAProxy`'s own reason strings. Unassigned values
  round-trip through `StatusCode::Other`, since the spec lets agents define their own
- `SUPPORTED_VERSION`, `MIN_FRAME_SIZE`, and `MAX_FRAME_SIZE_LIMIT` constants
- `HaproxyHello::negotiate_version` and `HaproxyHello::negotiate_max_frame_size`.
  `supported_versions` was parsed but never used, and the examples hardcoded a version;
  `HAProxy` now announces only SPOP 2.0
- `SpopFrame::serialize_into`, which appends to an existing buffer instead of allocating
- `FrameCapabilities::as_str`, and `Copy` for `FrameFlags`, `Metadata`, `VarScope`, and
  `FrameCapabilities`
- `varint::encode_varint_into` and `varint::varint_len` are now public, replacing the removed
  `encode_varint`
- `parser::parse_frame_with_limit`, which enforces an explicit ceiling. `parse_frame` remains and
  applies `MAX_FRAME_SIZE_LIMIT`, so callers using it directly are unaffected
- `SpopCodec::new`, `SpopCodec::set_max_frame_size`, `SpopCodec::max_frame_size`, and a `Default`
  impl
- Benchmarks under `benches/`. `decode.rs` touches only `parse_frame`, whose signature survived
  the 0.11/0.12 API changes, so `just bench-ab [REF]` can swap `src/` for any revision and still
  build — `roundtrip.rs` and `frames.rs` use current-only API and are not comparable that way

### Changed
- `anyhow`, `futures`, `rand` and `tokio` moved from `[dependencies]` to `[dev-dependencies]`.
  None of them was referenced anywhere in `src/` — they are used only by the examples, the
  benchmarks and the doctests. The public API never exposed them, so this is not an API break: a
  downstream crate now compiles 17 crates instead of 42, and no longer has `tokio`'s `full`
  feature set unioned into its build. `tokio` arrives via `tokio-util` with `default,sync`
  rather than `fs`, `process`, `signal`, `net`, `rt-multi-thread` and the rest.

  It can still break a *build* in one narrow case: code that used `tokio` features it never
  declared itself, and compiled only because this crate's `features = ["full"]` enabled them
  through feature unification. The fix is to declare the features that code actually uses.
  Declaring `tokio`, `tokio-util` and `futures` was always required either way — a Cargo
  dependency of this crate was never importable from a downstream one
- `SpopCodec` no longer allocates a `Vec` and copies it for every outbound frame; it stages into
  a reused buffer and hands it over in one write
- Faster on the decode side. The structural changes are described in the next entry; the
  measured effect on a NOTIFY carrying `log-request` with three string arguments, and the ACK
  answering it:

  | | 0.11.0 | 0.12.0 |
  |---|---|---|
  | full loop through `SpopCodec` | ~516 ns | ~410 ns |
  | `parse_frame` | ~399 ns | ~294 ns |
  | decode through `SpopCodec` | ~414 ns | ~319 ns |
  | encode an ACK through `SpopCodec` | ~87.5 ns | ~85.9 ns |

  Treat those as indicative, not precise. Repeated `just bench-ab 0.11.0` runs on one developer
  laptop put the `parse_frame` improvement anywhere between 5% and 25%, because the baseline run
  and the comparison run are separate processes and each picks up whatever CPU and cache state
  the machine happens to be in. The median across runs sits near 20%. Measure on your own
  hardware before relying on a number.

  What does not depend on measurement: the encode path performs one fewer allocation and one
  fewer free per outbound frame, and decoding a KV-LIST or a message argument list no longer
  builds a `Vec` that is immediately discarded. Those are structural, and the encode figure above
  reflects that the change there buys an allocation rather than wall clock.
- Parse KV-LISTs and message arguments straight into their map instead of building a throwaway
  `Vec` first, pre-size the maps where the count is known, and hash each key once instead of twice
- `FrameCapabilities::from_str` no longer allocates via `to_lowercase`

### Breaking
- `SpopCodec` now carries the largest frame it will accept, so it is a struct rather than a unit
  struct. Construct it with `SpopCodec::default()` (starting at `MAX_FRAME_SIZE_LIMIT`) or
  `SpopCodec::new(max_frame_size)`:

  ```diff
  - Framed::new(stream, SpopCodec)
  + Framed::new(stream, SpopCodec::default())
  ```

  Then hold the peer to what the handshake agreed, in the HAPROXY-HELLO branch where you already
  compute the value for AGENT-HELLO:

  ```rust
  socket.codec_mut().set_max_frame_size(max_frame_size);
  ```

  Nothing else changes: the frame loop, `payload()`, `metadata()`, `TypedData`, and the `Ack`
  builders are all untouched
- Removed `Metadata::serialize` and `varint::encode_varint`. Both allocated a `Vec` per call and
  had no callers anywhere, including inside this crate. Use `Metadata::write_to` or
  `varint::encode_varint_into` with a buffer you already own

### Notes
- Fixed the release workflow's changelog extraction. `awk "/## $VERSION/,/^## /"` never worked:
  the range's start line also matches its end pattern, so the range closed immediately and every
  GitHub release fell back to the literal text "Release version X" instead of the changelog
- `spoa_agent/.containerenv`, an artifact podman leaves in the mounted directory, was tracked and
  shipped inside the published `.crate`. Untracked, and `spoa_agent/` is now git-ignored
- CI now runs `cargo doc --no-deps --all-features`. It previously ran fmt, clippy, check and test
  but never rustdoc, so a broken intra-doc link — an error under `warnings = "deny"` — would have
  published a crate that lands on docs.rs with no documentation
- Reviewed against `HAProxy` master a second time. All 15 status codes, both TYPED-DATA nibble
  masks (`SPOP_DATA_T_MASK 0x0F` / `SPOP_DATA_FL_MASK 0xF0`), the boolean `0x10` true flag, all
  six frame type IDs, and the supported-version table match byte for byte. The frame-size
  architecture now mirrors `HAProxy`'s: a pre-negotiation default, narrowed once the handshake
  completes, enforced on both directions
- `decode_varint` bounds the shift but does not reject non-minimal encodings, so a malformed
  varint can decode to a wrong value rather than an error. `HAProxy`'s decoder behaves the same
  way, and it cannot reach past the function: string and binary lengths are bounds-checked
  against the remaining input, so an inflated length errors instead of over-reading
- The examples treat a connection reset, abort, unexpected EOF, or broken pipe as a normal end of
  life rather than logging it as a frame error. `HAProxy` closes abruptly after an
  `option spop-check` health check, so the old code logged a scary-looking error on every one
- Migration is two lines per connection handler, both shown above. `^0.11` consumers must opt in
  by bumping the version, since this is a breaking release
- The codec now enforces the negotiated `max-frame-size` rather than only the 1 MiB backstop.
  Worst-case memory held by one stalled connection drops from 1 MiB to the negotiated size,
  normally 16380 bytes
- Verified against `HAProxy` master (3.4.0 stable, `doc/SPOE.txt` spec version 1.2): the wire
  protocol is unchanged and this crate is conformant
- `haproxy.cfg` now uses `mode spop` with `option spop-check`, which is what current `HAProxy`
  documents and which exercises the health-check path the examples already implemented
- `FramePayload::KVList` is a `HashMap`, so KV pairs are emitted in a nondeterministic order.
  This is protocol-legal but prevents byte-exact round-trip assertions on KV frames
- `just run` now passes `--security-opt label=disable`. With SELinux enforcing, `agent_socket`
  creates `spoa.sock` after the mount is labelled, so the container was denied access to it;
  `:z` does not help because it only relabels pre-existing content. Previously invisible because
  the server health checks were commented out

## 0.11.0 - 2026-03-09

### Changed
- Reduce allocations during frame handling by borrowing metadata, message lists, and action lists instead of cloning them, thanks @famfo
- Update frame serialization to operate on borrowed slices for `NOTIFY` and `ACK` payloads
- Use binary notation for varint bit masks for readability

### Breaking
- Change the public `SpopFrame` trait to return `Cow<'_, Metadata>` and `FramePayload<'_>`
- Change `FramePayload::ListOfMessages` and `FramePayload::ListOfActions` to hold borrowed slices instead of owned `Vec`s

## 0.10.8 - 2026-02-22

### Fixed
- Fix 32-bit build failure: use `usize` instead of `u64` for `nom::take()` lengths (#12)

## 0.10.6 - 2025-12-08

### Fixed
- Fixed all clippy warnings (146+ issues) with strict lints enabled
- Fixed rustdoc broken intra-doc links
- Replaced `unwrap()` with proper error handling in production code

## 0.10.2
- NOTIFY: Handle empty or multiple messages in a list, thanks @chantra

## 0.10.1
- parser: Handle incomplete frames, thanks @chantra

## 0.10.0
- types: Add a macro_rules to generate From/TryFrom implementations for TypedData, thanks @chantra

## 0.9.2
- Fixed disconnect: look up for "status-code", not "max-frame-size", thanks @chantra

## 0.9.1
- Added tcp example

## 0.9.0
- SpopCodec for encoding/decoding to use with tokio_util::codec
- Removed SpopFrameExt

## 0.8.4
- Implement typed data serialization for all types & test_parse_haproxy_hello, thanks @vipera

## 0.8.0
- Using Semver to parse the "supported-versions" field (major.minor)

## 0.7.0
- structs for frames
- SpopFrame trait for frame handling
- SpopFrameExt for serializing the frames

## 0.6.0
- Implemented HAPROXY/AGENT - DISCONNECT

## 0.5.0
- ACK (ACTION-UNSET-VAR) working
- example covering on-client-session and on-frontend-http-request

## 0.4.0
- ACK (ACTION-SET-VAR) working
- Frame handling improved

## 0.1.0
- First release
