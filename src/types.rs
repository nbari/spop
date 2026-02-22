use crate::varint::{decode_varint, encode_varint};
use nom::{
    IResult,
    bytes::complete::take,
    error::{Error, ErrorKind},
    number::complete::be_u8,
};
use std::net::{Ipv4Addr, Ipv6Addr};
use thiserror::Error;

/// <https://github.com/haproxy/haproxy/blob/master/doc/SPOE.txt#L635>
///
/// ```text
/// Here is the bytewise representation of typed data:
///
///     TYPED-DATA    : <TYPE:4 bits><FLAGS:4 bits><DATA>
///
/// Supported types and their representation are:
///
///     TYPE                       |  ID | DESCRIPTION
///   -----------------------------+-----+----------------------------------
///      NULL                      |  0  |  NULL   : <0>
///      Boolean                   |  1  |  BOOL   : <1+FLAG>
///      32bits signed integer     |  2  |  INT32  : <2><VALUE:varint>
///      32bits unsigned integer   |  3  |  UINT32 : <3><VALUE:varint>
///      64bits signed integer     |  4  |  INT64  : <4><VALUE:varint>
///      32bits unsigned integer   |  5  |  UNIT64 : <5><VALUE:varint>
///      IPV4                      |  6  |  IPV4   : <6><STRUCT IN_ADDR:4 bytes>
///      IPV6                      |  7  |  IPV6   : <7><STRUCT IN_ADDR6:16 bytes>
///      String                    |  8  |  STRING : <8><LENGTH:varint><BYTES>
///      Binary                    |  9  |  BINARY : <9><LENGTH:varint><BYTES>
///     10 -> 15  unused/reserved  |  -  |  -
///   -----------------------------+-----+----------------------------------
/// ```

#[derive(Error, Debug)]
pub enum TypedDataError {
    #[error("Invalid conversion from TypedData to native type")]
    InvalidConversion,
}

const TYPE_NULL: u8 = 0x00;
const TYPE_BOOL: u8 = 0x01;
const TYPE_INT32: u8 = 0x02;
const TYPE_UINT32: u8 = 0x03;
const TYPE_INT64: u8 = 0x04;
const TYPE_UINT64: u8 = 0x05;
const TYPE_IPV4: u8 = 0x06;
const TYPE_IPV6: u8 = 0x07;
const TYPE_STRING: u8 = 0x08;
const TYPE_BINARY: u8 = 0x09;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum TypedData {
    Null,
    Bool(bool),
    Int32(i32),
    UInt32(u32),
    Int64(i64),
    UInt64(u64),
    IPv4(Ipv4Addr),
    IPv6(Ipv6Addr),
    String(String),
    Binary(Vec<u8>),
}

impl TypedData {
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        match typed_data(bytes) {
            Ok((_rest, typed_data)) => Some(typed_data),
            Err(_) => None,
        }
    }

    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    pub fn to_bytes(&self, buf: &mut Vec<u8>) {
        match self {
            Self::Null => {
                buf.push(TYPE_NULL);
            }
            Self::Bool(val) => {
                let flags = u8::from(*val) << 4;
                buf.push(flags | TYPE_BOOL);
            }
            Self::Int32(val) => {
                buf.push(TYPE_INT32);
                buf.extend(encode_varint(*val as u64));
            }
            Self::UInt32(val) => {
                buf.push(TYPE_UINT32);
                buf.extend(encode_varint(u64::from(*val)));
            }
            Self::Int64(val) => {
                buf.push(TYPE_INT64);
                buf.extend(encode_varint(*val as u64));
            }
            Self::UInt64(val) => {
                buf.push(TYPE_UINT64);
                buf.extend(encode_varint(*val));
            }
            Self::IPv4(addr) => {
                buf.push(TYPE_IPV4);
                buf.extend_from_slice(&addr.octets());
            }
            Self::IPv6(addr) => {
                buf.push(TYPE_IPV6);
                buf.extend_from_slice(&addr.octets());
            }
            Self::String(val) => {
                buf.push(TYPE_STRING);
                buf.extend(encode_varint(val.len() as u64));
                buf.extend_from_slice(val.as_bytes());
            }
            Self::Binary(val) => {
                buf.push(TYPE_BINARY);
                buf.extend(encode_varint(val.len() as u64));
                buf.extend_from_slice(val);
            }
        }
    }
}

// Macro to implement `From<T> for TypedData` and `trait From<Option<T>> for TypedData`
// for native types.
// This allows converting native types directly into TypedData variants.
// For example, `TypedData::from(42u32)` will yield `TypedData::UInt32(42)`
// so will `42u32.into()`, and `TypedData::from(Some(42u32))` will yield
// `TypedData::UInt32(42)` while `TypedData::from(None)` will yield `TypedData::Null`.
// This is useful to easily convert native types to TypedData when sending replies
// back.
macro_rules! from_native_trait {
    ($native_type:ty, $typed_data_variant:ident) => {
        impl From<$native_type> for TypedData {
            #[doc = concat!("Converts a [`", stringify!($native_type), "`] into [`TypedData::", stringify!($typed_data_variant), "`]`(value)`.")]
            fn from(value: $native_type) -> Self {
                TypedData::$typed_data_variant(value)
            }
        }

        impl From<Option<$native_type>> for TypedData {
            #[doc = concat!("Converts a [Option]<[`", stringify!($native_type), "`]> into `TypedData`. If the value is None, it returns [`TypedData::Null`]. If the value is `Some(value)`, it returns [`TypedData::", stringify!($typed_data_variant), "`]`(value)`.")]
            fn from(value: Option<$native_type>) -> Self {
                match value {
                    None => TypedData::Null,
                    Some(value) => TypedData::$typed_data_variant(value),
                }
            }
        }
    };
}

// Macro to implement `TryFrom<TypedData> for T` and `trait TryFrom<TypedData> for Option<T>`.
// This allows converting native types directly into TypedData variants.
// For example, `42u32::try_from(TypedData::UInt32(42))` will yield `Ok(42)`
// so will `TypedData::UInt32(42).try_into()`.
macro_rules! try_from_typed_data {
    ($native_type:ty, $typed_data_variant:ident) => {
        impl TryFrom<TypedData> for $native_type {
            type Error = TypedDataError;

            #[doc = concat!("Converts a [`TypedData::", stringify!($typed_data_variant), "`] to a [`", stringify!($native_type), "`] failing if the type conversion is invalid.")]
            fn try_from(value: TypedData) -> Result<Self, Self::Error> {
                match value {
                    TypedData::$typed_data_variant(val) => Ok(val),
                    _ => Err(TypedDataError::InvalidConversion),
                }
            }
        }

        impl TryFrom<TypedData> for Option<$native_type> {
            type Error = TypedDataError;

            #[doc = concat!("Converts a [`TypedData`] to an [Option]<[`", stringify!($native_type), "`]> failing if the type conversion is invalid.
            If the value is [`TypedData::Null`], it returns [`None`].
            If the value is [`TypedData::", stringify!($typed_data_variant), "`] it returns `Some(", stringify!($native_type), ")`.")]
            fn try_from(value: TypedData) -> Result<Self, Self::Error> {
                match value {
                    TypedData::Null => Ok(None),
                    TypedData::$typed_data_variant(val) => Ok(Some(val)),
                    _ => Err(TypedDataError::InvalidConversion),
                }
            }
        }
    };
}

from_native_trait!(bool, Bool);
from_native_trait!(i32, Int32);
from_native_trait!(u32, UInt32);
from_native_trait!(i64, Int64);
from_native_trait!(u64, UInt64);
from_native_trait!(Ipv4Addr, IPv4);
from_native_trait!(Ipv6Addr, IPv6);
from_native_trait!(String, String);
from_native_trait!(Vec<u8>, Binary);

// Those needs to be implemented manually
impl From<&str> for TypedData {
    /// Converts a [`&str`] into [`TypedData::String`].
    fn from(value: &str) -> Self {
        Self::String(value.to_string())
    }
}

impl From<Option<&str>> for TypedData {
    /// Converts a [Option]<[`&str`]> into `TypedData`. If the value is None, it returns [`TypedData::Null`]. If the value is `Some(value)`, it returns [`TypedData::String`].
    fn from(value: Option<&str>) -> Self {
        value.map_or(Self::Null, |value| Self::String(value.to_string()))
    }
}

try_from_typed_data!(bool, Bool);
try_from_typed_data!(i32, Int32);
try_from_typed_data!(u32, UInt32);
try_from_typed_data!(i64, Int64);
try_from_typed_data!(u64, UInt64);
try_from_typed_data!(Ipv4Addr, IPv4);
try_from_typed_data!(Ipv6Addr, IPv6);
try_from_typed_data!(String, String);
try_from_typed_data!(Vec<u8>, Binary);

/// Returns the Type ID and Flags from the first byte of the input
///
/// # Errors
///
/// Returns an error if the input is empty, incomplete, or contains an unsupported type.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::indexing_slicing
)]
pub fn typed_data(input: &[u8]) -> IResult<&[u8], TypedData> {
    if input.is_empty() {
        return Err(nom::Err::Error(Error::new(input, ErrorKind::Eof)));
    }

    let (input, type_and_flags) = be_u8(input)?;

    // TYPED-DATA    : <TYPE:4 bits><FLAGS:4 bits><DATA>
    //
    // First 4 bits are TYPE, last 4 bits are FLAGS
    let type_id = type_and_flags & 0x0F;
    let flags = type_and_flags >> 4;

    match type_id {
        TYPE_NULL => Ok((input, TypedData::Null)),
        TYPE_BOOL => Ok((input, TypedData::Bool((flags & 1) != 0))),
        TYPE_INT32 => decode_varint(input).map(|(i, v)| (i, TypedData::Int32(v as i32))),
        TYPE_UINT32 => decode_varint(input).map(|(i, v)| (i, TypedData::UInt32(v as u32))),
        TYPE_INT64 => decode_varint(input).map(|(i, v)| (i, TypedData::Int64(v as i64))),
        TYPE_UINT64 => decode_varint(input).map(|(i, v)| (i, TypedData::UInt64(v))),
        TYPE_IPV4 => {
            if input.len() < 4 {
                return Err(nom::Err::Error(Error::new(input, ErrorKind::Eof)));
            }
            let (input, bytes) = take(4usize)(input)?;
            let addr = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
            Ok((input, TypedData::IPv4(addr)))
        }
        TYPE_IPV6 => {
            if input.len() < 16 {
                return Err(nom::Err::Error(Error::new(input, ErrorKind::Eof)));
            }
            let (input, bytes) = take(16usize)(input)?;
            let addr = <[u8; 16]>::try_from(bytes)
                .map(Ipv6Addr::from)
                .map_err(|_| nom::Err::Error(Error::new(input, ErrorKind::Fail)))?;
            Ok((input, TypedData::IPv6(addr)))
        }
        TYPE_STRING | TYPE_BINARY => {
            let (input, length) = decode_varint(input)?;
            let length: usize = length
                .try_into()
                .map_err(|_| nom::Err::Error(Error::new(input, ErrorKind::TooLarge)))?;

            if input.len() < length {
                return Err(nom::Err::Error(Error::new(input, ErrorKind::Eof)));
            }

            let (input, data) = take(length)(input)?;
            if type_id == TYPE_STRING {
                let s = String::from_utf8_lossy(data).into_owned();
                Ok((input, TypedData::String(s)))
            } else {
                Ok((input, TypedData::Binary(data.to_vec())))
            }
        }
        _ => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Tag,
        ))),
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::uninlined_format_args
)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// List of test cases for type parsing
    /// Each test case is a tuple:
    /// (description, input bytes, expected `TypedData`)
    fn test_cases() -> Vec<(&'static str, Vec<u8>, TypedData)> {
        vec![
            // Type 0: NULL
            ("NULL", vec![0x00], TypedData::Null),
            // Type 1: Boolean (false) - lower nibble is 1, flags=0 yields false.
            ("Bool false", vec![0x01], TypedData::Bool(false)),
            // Type 1: Boolean (true) - e.g. 0x11 gives type=1 and flags=1.
            ("Bool true", vec![0x11], TypedData::Bool(true)),
            // Type 2: 32-bit signed integer (INT32)
            // 0x02 followed by a varint-encoded value (here one-byte: 123)
            ("Int32", vec![0x02, 0x7B], TypedData::Int32(123)),
            // Type 3: 32-bit unsigned integer (UINT32)
            ("UInt32", vec![0x03, 0x7B], TypedData::UInt32(123)),
            // Type 4: 64-bit signed integer (INT64)
            ("Int64", vec![0x04, 0x2A], TypedData::Int64(42)),
            // Type 5: 64-bit unsigned integer (UINT64)
            ("UInt64", vec![0x05, 0x2A], TypedData::UInt64(42)),
            // Type 6: IPv4 address: 0x06 followed by 4 bytes.
            (
                "IPv4",
                vec![0x06, 192, 168, 0, 1],
                TypedData::IPv4(Ipv4Addr::new(192, 168, 0, 1)),
            ),
            (
                "IPv4",
                vec![0x06, 10, 0, 0, 42],
                TypedData::IPv4(Ipv4Addr::new(10, 0, 0, 42)),
            ),
            // Type 7: IPv6 address: 0x07 followed by 16 bytes, e.g. ::1.
            (
                "IPv6",
                {
                    let mut v = vec![0x07];
                    v.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
                    v
                },
                TypedData::IPv6(Ipv6Addr::from([
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                ])),
            ),
            // Use arbitrary IPv6 address: 2001:0db8:85a3:0000:0000:8a2e:0370:7334.
            (
                "IPv6",
                {
                    let mut v = vec![0x07];
                    // IPv6 address bytes in network order.
                    // 2001:0db8:85a3:0000:0000:8a2e:0370:7334
                    v.extend_from_slice(&[
                        0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e,
                        0x03, 0x70, 0x73, 0x34,
                    ]);
                    v
                },
                TypedData::IPv6(Ipv6Addr::new(
                    0x2001, 0x0db8, 0x85a3, 0x0000, 0x0000, 0x8a2e, 0x0370, 0x7334,
                )),
            ),
            // Type 8: String: 0x08, then varint length (5), then "hello".
            (
                "String",
                vec![0x08, 0x05, b'h', b'e', b'l', b'l', b'o'],
                TypedData::String("hello".to_string()),
            ),
            // Type 9: Binary: 0x09, then varint length (3), then bytes 0xAA, 0xBB, 0xCC.
            (
                "Binary",
                vec![0x09, 0x03, 0xAA, 0xBB, 0xCC],
                TypedData::Binary(vec![0xAA, 0xBB, 0xCC]),
            ),
        ]
    }

    #[test]
    fn test_loop_typed_data() {
        for (desc, input, expected) in test_cases() {
            let (rest, parsed) = typed_data(&input)
                .unwrap_or_else(|e| panic!("Test case '{}' failed: {:?}", desc, e));
            assert!(
                rest.is_empty(),
                "Test case '{}' did not consume all input: remaining {:?}",
                desc,
                rest
            );
            assert_eq!(parsed, expected, "Test case '{}' failed", desc);
        }
    }

    #[test]
    fn test_to_bytes() {
        for (desc, input, expected) in test_cases() {
            let mut buf = Vec::new();
            expected.to_bytes(&mut buf);
            assert_eq!(buf, input, "Test case '{}' failed", desc);
        }
    }

    // Test conversion from native types to TypedData
    #[test]
    fn test_from_native_types() {
        assert_eq!(TypedData::from(true), TypedData::Bool(true));
        assert_eq!(TypedData::from(false), TypedData::Bool(false));
        assert_eq!(TypedData::from(123i32), TypedData::Int32(123));
        assert_eq!(TypedData::from(123u32), TypedData::UInt32(123));
        assert_eq!(TypedData::from(42i64), TypedData::Int64(42));
        assert_eq!(TypedData::from(42u64), TypedData::UInt64(42));
        assert_eq!(
            TypedData::from(Ipv4Addr::new(192, 168, 0, 1)),
            TypedData::IPv4(Ipv4Addr::new(192, 168, 0, 1))
        );
        assert_eq!(
            TypedData::from(Ipv6Addr::from([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
            ])),
            TypedData::IPv6(Ipv6Addr::from([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
            ]))
        );
        assert_eq!(
            TypedData::from("hello".to_string()),
            TypedData::String("hello".to_string())
        );
        assert_eq!(
            TypedData::from(vec![0xAA, 0xBB, 0xCC]),
            TypedData::Binary(vec![0xAA, 0xBB, 0xCC])
        );

        // Test conversion from native types to TypedData using Into trait
        assert_eq!(TypedData::UInt32(42), 42u32.into());
    }

    // Test conversion from Option<T> to TypedData
    // This should yield TypedData::Null for None and TypedData::Variant for Some(value
    #[test]
    fn test_from_option_native_types() {
        let test_val: Option<u32> = None;
        assert_eq!(TypedData::from(test_val), TypedData::Null);
        assert_eq!(TypedData::from(None::<bool>), TypedData::Null);
        assert_eq!(TypedData::from(Some(true)), TypedData::Bool(true));
        assert_eq!(TypedData::from(Some(false)), TypedData::Bool(false));
        assert_eq!(TypedData::from(Some(123i32)), TypedData::Int32(123));
        assert_eq!(TypedData::from(Some(123u32)), TypedData::UInt32(123));
        assert_eq!(TypedData::from(Some(42i64)), TypedData::Int64(42));
        assert_eq!(TypedData::from(Some(42u64)), TypedData::UInt64(42));
        assert_eq!(
            TypedData::from(Some(Ipv4Addr::new(192, 168, 0, 1))),
            TypedData::IPv4(Ipv4Addr::new(192, 168, 0, 1))
        );
        assert_eq!(
            TypedData::from(Some(Ipv6Addr::from([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
            ]))),
            TypedData::IPv6(Ipv6Addr::from([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
            ]))
        );
        assert_eq!(
            TypedData::from(Some("hello".to_string())),
            TypedData::String("hello".to_string())
        );
        assert_eq!(
            TypedData::from(Some(vec![0xAA, 0xBB, 0xCC])),
            TypedData::Binary(vec![0xAA, 0xBB, 0xCC])
        );

        // Test conversion from native types to TypedData using Into trait
        assert_eq!(TypedData::UInt32(42), Some(42u32).into());
    }

    // test try_from TypedData to native types
    #[test]
    fn test_try_from_typed_data() -> Result<(), TypedDataError> {
        let val = bool::try_from(TypedData::Bool(true))?;
        assert!(val);

        let val: Option<bool> = Option::try_from(TypedData::Null)?;
        assert_eq!(val, None);

        let val: Option<bool> = Option::try_from(TypedData::Bool(true))?;
        assert_eq!(val, Some(true));

        let val: Option<i32> = TypedData::Int32(123).try_into()?;
        assert_eq!(val, Some(123));

        let val: u32 = TypedData::UInt32(123).try_into()?;
        assert_eq!(val, 123);

        let val: Result<u32, TypedDataError> = TypedData::UInt64(42).try_into();
        assert!(val.is_err());
        Ok(())
    }
}
