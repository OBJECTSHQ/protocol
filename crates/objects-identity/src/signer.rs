//! Signer types for identity operations.
//!
//! Supported signer types:
//! - PASSKEY: WebAuthn/FIDO2 credentials using secp256r1 (P-256)
//! - WALLET: Ethereum EOA using secp256k1

use serde::{Deserialize, Serialize};

use crate::Error;

/// Signer type identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u32)]
pub enum SignerType {
    /// WebAuthn/FIDO2 credential using secp256r1 (P-256).
    Passkey = 1,
    /// Ethereum EOA using secp256k1.
    Wallet = 2,
}

impl SignerType {
    /// Parses a signer type from its numeric value.
    pub fn from_u32(value: u32) -> Result<Self, Error> {
        match value {
            1 => Ok(Self::Passkey),
            2 => Ok(Self::Wallet),
            _ => Err(Error::UnsupportedSignerType(value)),
        }
    }

    /// Returns the numeric value of this signer type.
    pub fn as_u32(self) -> u32 {
        self as u32
    }
}

/// A signer that can create signatures.
#[derive(Debug, Clone)]
pub struct Signer {
    /// The type of signer.
    pub signer_type: SignerType,
    /// The compressed SEC1 public key (33 bytes).
    pub public_key: [u8; 33],
}

impl Signer {
    /// Creates a new signer from a public key.
    pub fn new(signer_type: SignerType, public_key: [u8; 33]) -> Self {
        Self {
            signer_type,
            public_key,
        }
    }

    /// Returns the public key as a hex string.
    pub fn public_key_hex(&self) -> String {
        hex::encode(&self.public_key)
    }
}

// Include hex encoding for public keys
mod hex {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

    pub fn encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            s.push(HEX_CHARS[(b >> 4) as usize] as char);
            s.push(HEX_CHARS[(b & 0xf) as usize] as char);
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signer_type_from_u32() {
        assert_eq!(SignerType::from_u32(1).unwrap(), SignerType::Passkey);
        assert_eq!(SignerType::from_u32(2).unwrap(), SignerType::Wallet);
        assert!(SignerType::from_u32(0).is_err());
        assert!(SignerType::from_u32(3).is_err());
    }

    #[test]
    fn test_signer_type_as_u32() {
        assert_eq!(SignerType::Passkey.as_u32(), 1);
        assert_eq!(SignerType::Wallet.as_u32(), 2);
    }
}
