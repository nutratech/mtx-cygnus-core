//! Principal identifiers (§2.6): `~` + base64url(D₀) for servers, `@` + the
//! same for users. 44 characters, no `:`, so they never collide with legacy
//! user IDs or server names.

use crate::{link::Kind, Error};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};

/// A server or user principal: the genesis digest D₀ and its kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Principal {
    /// Server (`~`) or user (`@`).
    pub kind: Kind,
    /// SHA-256 of the genesis link body.
    pub root: [u8; 32],
}

impl Principal {
    /// Render as the 44-character identifier.
    #[must_use]
    pub fn to_id(&self) -> String {
        let sigil = match self.kind {
            Kind::Server => '~',
            Kind::User => '@',
        };
        format!("{sigil}{}", B64.encode(self.root))
    }

    /// Parse a 44-character identifier, rejecting padding and legacy forms.
    ///
    /// # Errors
    /// [`Error::Principal`] or [`Error::Base64`] if malformed.
    pub fn parse(s: &str) -> Result<Self, Error> {
        let mut chars = s.chars();
        let kind = match chars.next() {
            Some('~') => Kind::Server,
            Some('@') => Kind::User,
            _ => return Err(Error::Principal),
        };
        let rest = chars.as_str();
        if rest.len() != 43 {
            return Err(Error::Principal);
        }
        let bytes = B64.decode(rest).map_err(|_| Error::Base64)?;
        let root: [u8; 32] = bytes.try_into().map_err(|_| Error::Principal)?;
        Ok(Self { kind, root })
    }
}

impl std::fmt::Display for Principal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_id())
    }
}
