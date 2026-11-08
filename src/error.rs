//! Error type shared by all modules.

use std::fmt;

/// Everything that can go wrong parsing or verifying cygnus data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Input ended before a field was complete.
    Truncated,
    /// Unsupported link version byte.
    Version(u8),
    /// Unknown link kind byte.
    Kind(u8),
    /// A length-prefixed field is outside its permitted range.
    FieldLength(&'static str),
    /// A field holds a value the spec forbids.
    Field(&'static str),
    /// Trailer length does not match the link's kind and height.
    Trailer {
        /// Required trailer size.
        expected: usize,
        /// Observed trailer size.
        got: usize,
    },
    /// Text field is not valid UTF-8 / ASCII.
    NotAscii(&'static str),
    /// Principal identifier is malformed.
    Principal,
    /// Base64url decoding failed.
    Base64,
    /// A public key is not a valid Ed25519 point encoding.
    PublicKey,
    /// A signature did not verify.
    Signature,
    /// The successor does not follow its parent (`what` names the rule).
    Successor(&'static str),
    /// The revealed rotation key does not match the parent's commitment.
    Commitment,
    /// Device certificate parsing or verification failed.
    Certificate(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("truncated input"),
            Self::Version(version) => write!(f, "unsupported link version {version:#04x}"),
            Self::Kind(kind) => write!(f, "unknown link kind {kind:#04x}"),
            Self::FieldLength(field) => write!(f, "field `{field}` has invalid length"),
            Self::Field(field) => write!(f, "invalid field `{field}`"),
            Self::Trailer { expected, got } => {
                write!(f, "trailer must be {expected} bytes, got {got}")
            }
            Self::NotAscii(field) => write!(f, "field `{field}` is not valid ASCII"),
            Self::Principal => f.write_str("malformed principal identifier"),
            Self::Base64 => f.write_str("invalid base64url"),
            Self::PublicKey => f.write_str("invalid public key"),
            Self::Signature => f.write_str("bad signature"),
            Self::Successor(rule) => write!(f, "successor rule violated: {rule}"),
            Self::Commitment => f.write_str("revealed key does not match commitment"),
            Self::Certificate(what) => write!(f, "invalid device certificate: {what}"),
        }
    }
}

impl std::error::Error for Error {}
