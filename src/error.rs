//! Error type shared by all modules.

/// Everything that can go wrong parsing or verifying cygnus data.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Input ended before a field was complete.
    #[error("truncated input")]
    Truncated,
    /// Unsupported link version byte.
    #[error("unsupported link version {0:#04x}")]
    Version(u8),
    /// Unknown link kind byte.
    #[error("unknown link kind {0:#04x}")]
    Kind(u8),
    /// A length-prefixed field is outside its permitted range.
    #[error("field `{0}` has invalid length")]
    FieldLength(&'static str),
    /// A field holds a value the spec forbids.
    #[error("invalid field `{0}`")]
    Field(&'static str),
    /// Trailer length does not match the link's kind and height.
    #[error("trailer must be {expected} bytes, got {got}")]
    Trailer {
        /// Required trailer size.
        expected: usize,
        /// Observed trailer size.
        got: usize,
    },
    /// Text field is not valid UTF-8 / ASCII.
    #[error("field `{0}` is not valid ASCII")]
    NotAscii(&'static str),
    /// Principal identifier is malformed.
    #[error("malformed principal identifier")]
    Principal,
    /// Base64url decoding failed.
    #[error("invalid base64url")]
    Base64,
    /// A public key is not a valid Ed25519 point encoding.
    #[error("invalid public key")]
    PublicKey,
    /// A signature did not verify.
    #[error("bad signature")]
    Signature,
    /// The successor does not follow its parent (`what` names the rule).
    #[error("successor rule violated: {0}")]
    Successor(&'static str),
    /// The revealed rotation key does not match the parent's commitment.
    #[error("revealed key does not match commitment")]
    Commitment,
}
