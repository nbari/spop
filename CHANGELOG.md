Changelog
=========

## 0.9.2
- Fixed disconnect: look up for "status-code", not "max-frame-size" #4

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
