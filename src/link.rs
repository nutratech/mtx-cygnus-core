//! Link codec and verification (§2).
//!
//! A link is `body ‖ trailer`. The digest covers only the body, so signature
//! encoding can never change an identity. Signatures are hash-based (see
//! [`crate::sig`]).

use crate::sig::{SigningKey, SIGNATURE_LEN};
use crate::{commitment, principal::Principal, Error, LINK_TAG};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use sha2::{Digest, Sha256};

const ZERO: [u8; 32] = [0; 32];

/// Principal kind byte (§2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// `0x01`
    Server,
    /// `0x02`
    User,
}

/// Kind-specific payload (§2.2, §2.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payload {
    /// Server link payload.
    Server {
        /// Key that signs events at this height.
        online_key: [u8; 32],
        /// Server name as used in user IDs today.
        server_name: String,
    },
    /// User link payload.
    User {
        /// D₀ of the custodian server principal.
        custodian: [u8; 32],
        /// Cross-signing master key, if present.
        master_key: Option<[u8; 32]>,
        /// ASCII `@localpart:server_name`; display only.
        display_user_id: String,
    },
}

/// The part of a link the digest covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Body {
    /// D₀, or zero at genesis.
    pub root: [u8; 32],
    /// 0 at genesis.
    pub height: u64,
    /// D_{h-1}, or zero at genesis.
    pub prev: [u8; 32],
    /// Commitment to the next rotation key.
    pub next_commit: [u8; 32],
    /// Kind-specific fields.
    pub payload: Payload,
}

impl Payload {
    /// The kind this payload belongs to.
    #[must_use]
    pub fn kind(&self) -> Kind {
        match self {
            Self::Server { .. } => Kind::Server,
            Self::User { .. } => Kind::User,
        }
    }
}

impl Body {
    /// Parse exactly one body without a signature trailer.
    ///
    /// This is used by burn proofs, whose `parent` field contains only the
    /// predecessor body.
    ///
    /// # Errors
    /// Returns the same structural errors as [`Link::parse`], and rejects
    /// trailing bytes after the body.
    pub fn parse_exact(bytes: &[u8]) -> Result<Self, Error> {
        let (body, consumed) = Self::parse(bytes)?;
        if consumed != bytes.len() {
            return Err(Error::Field("trailing bytes after link body"));
        }
        Ok(body)
    }

    /// Canonical wire encoding (§2.1–2.3).
    ///
    /// # Errors
    /// [`Error::FieldLength`] if a name or user ID is out of range.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut out = vec![
            1,
            if self.payload.kind() == Kind::Server {
                1
            } else {
                2
            },
        ];
        out.extend_from_slice(&self.root);
        out.extend_from_slice(&self.height.to_be_bytes());
        out.extend_from_slice(&self.prev);
        out.extend_from_slice(&self.next_commit);
        match &self.payload {
            Payload::Server {
                online_key,
                server_name,
            } => {
                let n = server_name.len();
                if !(1..=255).contains(&n) || !server_name.is_ascii() {
                    return Err(Error::FieldLength("server_name"));
                }
                out.extend_from_slice(online_key);
                out.extend_from_slice(&u16::try_from(n).expect("<=255").to_be_bytes());
                out.extend_from_slice(server_name.as_bytes());
            }
            Payload::User {
                custodian,
                master_key,
                display_user_id,
            } => {
                let n = display_user_id.len();
                if !(4..=255).contains(&n) || !display_user_id.is_ascii() {
                    return Err(Error::FieldLength("display_user_id"));
                }
                out.extend_from_slice(custodian);
                match master_key {
                    Some(k) => {
                        out.push(1);
                        out.extend_from_slice(k);
                    }
                    None => out.push(0),
                }
                out.extend_from_slice(&u16::try_from(n).expect("<=255").to_be_bytes());
                out.extend_from_slice(display_user_id.as_bytes());
            }
        }
        Ok(out)
    }

    /// Parse a body, returning it and the number of bytes consumed.
    fn parse(b: &[u8]) -> Result<(Self, usize), Error> {
        let mut r = Reader(b);
        let version = r.u8()?;
        if version != 1 {
            return Err(Error::Version(version));
        }
        let kind = match r.u8()? {
            1 => Kind::Server,
            2 => Kind::User,
            k => return Err(Error::Kind(k)),
        };
        let root = r.arr()?;
        let height = u64::from_be_bytes(r.take(8)?.try_into().expect("8"));
        let prev = r.arr()?;
        let next_commit = r.arr()?;
        if height == 0 && (root != ZERO || prev != ZERO) {
            return Err(Error::Field("genesis root/prev must be zero"));
        }
        let payload = match kind {
            Kind::Server => {
                let online_key = r.arr()?;
                let n = usize::from(r.u16()?);
                if !(1..=255).contains(&n) {
                    return Err(Error::FieldLength("name_len"));
                }
                Payload::Server {
                    online_key,
                    server_name: r.ascii(n, "server_name")?,
                }
            }
            Kind::User => {
                let custodian = r.arr()?;
                let master_key = match r.u8()? {
                    0 => None,
                    1 => Some(r.arr()?),
                    _ => return Err(Error::Field("msk_flag")),
                };
                let n = usize::from(r.u16()?);
                if !(4..=255).contains(&n) {
                    return Err(Error::FieldLength("uid_len"));
                }
                Payload::User {
                    custodian,
                    master_key,
                    display_user_id: r.ascii(n, "display_user_id")?,
                }
            }
        };
        Ok((
            Self {
                root,
                height,
                prev,
                next_commit,
                payload,
            },
            b.len() - r.0.len(),
        ))
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.0.len() < n {
            return Err(Error::Truncated);
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().expect("2")))
    }
    fn arr(&mut self) -> Result<[u8; 32], Error> {
        Ok(self.take(32)?.try_into().expect("32"))
    }
    fn ascii(&mut self, n: usize, field: &'static str) -> Result<String, Error> {
        let s = self.take(n)?;
        if !s.is_ascii() {
            return Err(Error::NotAscii(field));
        }
        Ok(String::from_utf8(s.to_vec()).expect("ascii"))
    }
}

/// A parsed link: body, its exact bytes, and trailer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    /// Parsed body.
    pub body: Body,
    /// Exact body bytes (what the digest and signatures cover).
    pub body_bytes: Vec<u8>,
    /// Trailer bytes (§2.4): a signature, nothing, or a key plus signature.
    pub trailer: Vec<u8>,
}

impl Link {
    /// Parse `body ‖ trailer`, requiring the exact trailer length for the
    /// link's kind and height.
    ///
    /// # Errors
    /// Any structural violation of §2.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let (body, n) = Body::parse(bytes)?;
        let expected = match (body.height, body.payload.kind()) {
            (0, Kind::Server) => SIGNATURE_LEN,
            (0, Kind::User) => 0,
            _ => 32 + SIGNATURE_LEN,
        };
        let trailer = &bytes[n..];
        if trailer.len() != expected {
            return Err(Error::Trailer {
                expected,
                got: trailer.len(),
            });
        }
        Ok(Self {
            body,
            body_bytes: bytes[..n].to_vec(),
            trailer: trailer.to_vec(),
        })
    }

    /// Parse the unpadded base64url form used in epoch events.
    ///
    /// # Errors
    /// [`Error::Base64`] or any parse error.
    pub fn from_b64(s: &str) -> Result<Self, Error> {
        Self::parse(&B64.decode(s).map_err(|_| Error::Base64)?)
    }

    /// Full wire bytes, `body ‖ trailer`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        [self.body_bytes.as_slice(), &self.trailer].concat()
    }

    /// Unpadded base64url wire form.
    #[must_use]
    pub fn to_b64(&self) -> String {
        B64.encode(self.to_bytes())
    }

    /// `D_h = SHA-256(body)`.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(&self.body_bytes).into()
    }

    /// The principal this link belongs to: genesis digest, or `root`.
    #[must_use]
    pub fn principal(&self) -> Principal {
        let root = if self.body.height == 0 {
            self.digest()
        } else {
            self.body.root
        };
        Principal {
            kind: self.body.payload.kind(),
            root,
        }
    }

    /// Build a signed server genesis (proof of possession by `online`).
    ///
    /// # Errors
    /// Propagates [`Body::encode`] errors.
    pub fn sign_server_genesis(body: Body, online: &SigningKey) -> Result<Self, Error> {
        let body_bytes = body.encode()?;
        let sig = online.sign(&[LINK_TAG, &body_bytes].concat());
        Ok(Self {
            body,
            body_bytes,
            trailer: sig.to_bytes(),
        })
    }

    /// Build an unsigned user genesis.
    ///
    /// # Errors
    /// Propagates [`Body::encode`] errors.
    pub fn user_genesis(body: Body) -> Result<Self, Error> {
        let body_bytes = body.encode()?;
        Ok(Self {
            body,
            body_bytes,
            trailer: Vec::new(),
        })
    }

    /// Build a successor link signed by its (now revealed) rotation key.
    ///
    /// # Errors
    /// Propagates [`Body::encode`] errors.
    pub fn sign_successor(body: Body, rotation: &SigningKey) -> Result<Self, Error> {
        let body_bytes = body.encode()?;
        let key = rotation.verification_key().to_bytes();
        let sig = rotation.sign(&[LINK_TAG, &body_bytes, &key].concat());
        let trailer = [key.as_slice(), &sig.to_bytes()].concat();
        Ok(Self {
            body,
            body_bytes,
            trailer,
        })
    }

    /// `verify_link(L, None)`: validity as a genesis link (§2.5).
    ///
    /// # Errors
    /// [`Error::Field`] if not a genesis, or [`Error::Signature`] if a server
    /// genesis lacks a valid proof of possession.
    pub fn verify_genesis(&self) -> Result<(), Error> {
        if self.body.height != 0 {
            return Err(Error::Field("height must be 0 at genesis"));
        }
        if let Payload::Server { online_key, .. } = &self.body.payload {
            verify(
                online_key,
                &[LINK_TAG, &self.body_bytes].concat(),
                &self.trailer,
            )?;
        }
        Ok(())
    }

    /// `verify_link(L, Some(P))`: validity as the successor of `parent`.
    ///
    /// # Errors
    /// The first violated successor rule.
    pub fn verify_successor(&self, parent: &Self) -> Result<(), Error> {
        let (b, p) = (&self.body, &parent.body);
        if b.payload.kind() != p.payload.kind() {
            return Err(Error::Successor("kind"));
        }
        if p.height.checked_add(1) != Some(b.height) {
            return Err(Error::Successor("height"));
        }
        if b.root != parent.principal().root {
            return Err(Error::Successor("root"));
        }
        if b.prev != parent.digest() {
            return Err(Error::Successor("prev"));
        }
        if let (
            Payload::User {
                master_key: new, ..
            },
            Payload::User {
                master_key: old, ..
            },
        ) = (&b.payload, &p.payload)
        {
            if new != old {
                return Err(Error::Successor("master_key"));
            }
        }
        if self.trailer.len() != 32 + SIGNATURE_LEN {
            return Err(Error::Trailer {
                expected: 32 + SIGNATURE_LEN,
                got: self.trailer.len(),
            });
        }
        let (key, sig) = self.trailer.split_at(32);
        let revealed: [u8; 32] = key.try_into().map_err(|_| Error::PublicKey)?;
        if commitment(&revealed) != p.next_commit {
            return Err(Error::Commitment);
        }
        verify(key, &[LINK_TAG, &self.body_bytes, key].concat(), sig)
    }
}

/// Verify `slice` link by link starting from `parent`; returns the new tip.
///
/// # Errors
/// The first failing link's error.
pub fn verify_slice<'a>(parent: &'a Link, slice: &'a [Link]) -> Result<&'a Link, Error> {
    let mut tip = parent;
    for l in slice {
        l.verify_successor(tip)?;
        tip = l;
    }
    Ok(tip)
}

pub(crate) fn verify(key: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), Error> {
    crate::sig::verify(key, msg, sig)
}
