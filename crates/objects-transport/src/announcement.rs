//! Discovery announcement for peer presence.
//!
//! Per RFC-002 §3.5.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::{Error, NodeId, RelayUrl, Result, SecretKey};

/// Default threshold for considering an announcement stale.
///
/// Per RFC-002 §5.4.2, nodes SHOULD discard announcements older than 24 hours.
pub const STALE_THRESHOLD: Duration = Duration::from_secs(24 * 60 * 60);

/// Maximum allowed length for relay URLs to prevent DoS attacks.
const MAX_RELAY_URL_LEN: usize = 2048;

/// Signed announcement broadcast on the discovery topic.
///
/// Per RFC-002 §3.5, this message is broadcast to announce a node's
/// presence on the network.
///
/// # Security
///
/// - Announcements MUST be signed with the node's secret key
/// - Recipients MUST verify signatures before accepting
/// - Stale announcements (>24h old) SHOULD be rejected
#[derive(Debug, Clone)]
pub struct DiscoveryAnnouncement {
    /// The announcing node's public key.
    node_id: NodeId,

    /// The announcing node's relay URL, if any.
    relay_url: Option<RelayUrl>,

    /// Unix timestamp in seconds when this announcement was created.
    timestamp: u64,

    /// Ed25519 signature over the announcement data.
    signature: [u8; 64],
}

impl DiscoveryAnnouncement {
    /// Create and sign a new discovery announcement.
    ///
    /// The announcement is signed with the provided secret key.
    /// The timestamp is set to the current time.
    pub fn new(secret_key: &SecretKey, relay_url: Option<RelayUrl>) -> Self {
        let node_id = secret_key.public();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after unix epoch")
            .as_secs();

        let message = Self::signing_message(&node_id, relay_url.as_ref(), timestamp);
        let sig = secret_key.sign(&message);

        Self {
            node_id,
            relay_url,
            timestamp,
            signature: sig.to_bytes(),
        }
    }

    /// Verify that this announcement's signature is valid.
    ///
    /// Per RFC-002 §7.5, nodes MUST verify signatures before accepting
    /// announcements.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidSignature`] if verification fails.
    pub fn verify(&self) -> Result<()> {
        let message = Self::signing_message(&self.node_id, self.relay_url.as_ref(), self.timestamp);

        let signature = iroh::Signature::from_bytes(&self.signature);
        self.node_id
            .verify(&message, &signature)
            .map_err(|e| Error::InvalidSignature(e.to_string()))
    }

    /// Check if this announcement is stale (older than 24 hours).
    ///
    /// Per RFC-002 §5.4.2, nodes SHOULD discard stale announcements.
    pub fn is_stale(&self) -> bool {
        self.age() > STALE_THRESHOLD
    }

    /// Get the age of this announcement.
    ///
    /// Returns `Duration::ZERO` if the timestamp is in the future.
    /// Use [`is_from_future`](Self::is_from_future) to check for future timestamps.
    pub fn age(&self) -> Duration {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after unix epoch")
            .as_secs();

        if now >= self.timestamp {
            Duration::from_secs(now - self.timestamp)
        } else {
            // Announcement is from the future (clock skew)
            Duration::ZERO
        }
    }

    /// Check if this announcement's timestamp is too far in the future.
    ///
    /// Returns `true` if the timestamp exceeds `now + tolerance`, indicating
    /// either clock skew beyond acceptable bounds or a malicious announcement.
    pub fn is_from_future(&self, tolerance: Duration) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after unix epoch")
            .as_secs();

        self.timestamp > now + tolerance.as_secs()
    }

    /// Returns the announcing node's public key.
    pub fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Returns the announcing node's relay URL, if any.
    pub fn relay_url(&self) -> Option<&RelayUrl> {
        self.relay_url.as_ref()
    }

    /// Returns the Unix timestamp in seconds when this announcement was created.
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// Encode this announcement for transmission.
    ///
    /// Format:
    /// - node_id: 32 bytes
    /// - relay_url_len: 2 bytes (u16 big-endian)
    /// - relay_url: variable bytes (UTF-8)
    /// - timestamp: 8 bytes (u64 big-endian)
    /// - signature: 64 bytes
    pub fn encode(&self) -> Vec<u8> {
        let relay_bytes = self
            .relay_url
            .as_ref()
            .map(|u| u.as_str().as_bytes())
            .unwrap_or(&[]);

        let mut buf = Vec::with_capacity(32 + 2 + relay_bytes.len() + 8 + 64);

        // node_id (32 bytes)
        buf.extend_from_slice(self.node_id.as_bytes());

        // relay_url_len (2 bytes) + relay_url (variable)
        buf.extend_from_slice(&(relay_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(relay_bytes);

        // timestamp (8 bytes)
        buf.extend_from_slice(&self.timestamp.to_be_bytes());

        // signature (64 bytes)
        buf.extend_from_slice(&self.signature);

        buf
    }

    /// Decode an announcement from received bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Decode`] if the bytes are malformed.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        // Minimum size: 32 (node_id) + 2 (len) + 0 (relay) + 8 (ts) + 64 (sig) = 106
        if bytes.len() < 106 {
            return Err(Error::Decode("announcement too short".into()));
        }

        let mut offset = 0;

        // node_id (32 bytes)
        let node_id_bytes: [u8; 32] = bytes[offset..offset + 32]
            .try_into()
            .map_err(|_| Error::Decode("invalid node_id".into()))?;
        let node_id = NodeId::from_bytes(&node_id_bytes)
            .map_err(|_| Error::Decode("invalid node_id".into()))?;
        offset += 32;

        // relay_url_len (2 bytes)
        let relay_len = u16::from_be_bytes(
            bytes[offset..offset + 2]
                .try_into()
                .map_err(|_| Error::Decode("invalid relay length".into()))?,
        ) as usize;
        offset += 2;

        // Validate relay URL length to prevent DoS attacks
        if relay_len > MAX_RELAY_URL_LEN {
            return Err(Error::Decode("relay URL too long".into()));
        }

        // Check we have enough bytes for the relay URL
        if bytes.len() < offset + relay_len + 8 + 64 {
            return Err(Error::Decode("announcement truncated".into()));
        }

        // relay_url (variable)
        let relay_url = if relay_len > 0 {
            let relay_str = std::str::from_utf8(&bytes[offset..offset + relay_len])
                .map_err(|_| Error::Decode("invalid relay URL encoding".into()))?;
            Some(
                relay_str
                    .parse()
                    .map_err(|_| Error::Decode("invalid relay URL".into()))?,
            )
        } else {
            None
        };
        offset += relay_len;

        // timestamp (8 bytes)
        let timestamp = u64::from_be_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .map_err(|_| Error::Decode("invalid timestamp".into()))?,
        );
        offset += 8;

        // signature (64 bytes)
        let signature: [u8; 64] = bytes[offset..offset + 64]
            .try_into()
            .map_err(|_| Error::Decode("invalid signature".into()))?;

        Ok(Self {
            node_id,
            relay_url,
            timestamp,
            signature,
        })
    }

    /// Construct the message that is signed.
    ///
    /// Per RFC-002 §3.5.3:
    /// `signed_data = node_id (32) || relay_url_bytes (var) || timestamp_be (8)`
    fn signing_message(node_id: &NodeId, relay_url: Option<&RelayUrl>, timestamp: u64) -> Vec<u8> {
        let relay_bytes = relay_url.map(|u| u.as_str().as_bytes()).unwrap_or(&[]);

        let mut msg = Vec::with_capacity(32 + relay_bytes.len() + 8);
        msg.extend_from_slice(node_id.as_bytes());
        msg.extend_from_slice(relay_bytes);
        msg.extend_from_slice(&timestamp.to_be_bytes());
        msg
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_secret_key() -> SecretKey {
        SecretKey::generate(&mut rand::rng())
    }

    #[test]
    fn sign_and_verify() {
        let key = test_secret_key();
        let relay_url: RelayUrl = "https://relay.example.com".parse().unwrap();

        let announcement = DiscoveryAnnouncement::new(&key, Some(relay_url));

        assert!(announcement.verify().is_ok());
        assert!(!announcement.is_stale());
    }

    #[test]
    fn sign_and_verify_no_relay() {
        let key = test_secret_key();

        let announcement = DiscoveryAnnouncement::new(&key, None);

        assert!(announcement.verify().is_ok());
    }

    #[test]
    fn encode_decode_roundtrip() {
        let key = test_secret_key();
        let relay_url: RelayUrl = "https://relay.example.com".parse().unwrap();

        let original = DiscoveryAnnouncement::new(&key, Some(relay_url));
        let encoded = original.encode();
        let decoded = DiscoveryAnnouncement::decode(&encoded).unwrap();

        assert_eq!(original.node_id(), decoded.node_id());
        assert_eq!(original.relay_url(), decoded.relay_url());
        assert_eq!(original.timestamp(), decoded.timestamp());
        assert!(decoded.verify().is_ok());
    }

    #[test]
    fn encode_decode_no_relay() {
        let key = test_secret_key();

        let original = DiscoveryAnnouncement::new(&key, None);
        let encoded = original.encode();
        let decoded = DiscoveryAnnouncement::decode(&encoded).unwrap();

        assert_eq!(original.node_id(), decoded.node_id());
        assert!(decoded.relay_url().is_none());
        assert!(decoded.verify().is_ok());
    }

    #[test]
    fn reject_invalid_signature() {
        let key = test_secret_key();
        let announcement = DiscoveryAnnouncement::new(&key, None);

        // Tamper with the signature
        let mut tampered = announcement.clone();
        tampered.signature[0] ^= 0xff;

        assert!(tampered.verify().is_err());
    }

    #[test]
    fn reject_tampered_timestamp() {
        let key = test_secret_key();
        let announcement = DiscoveryAnnouncement::new(&key, None);

        // Tamper with the timestamp
        let mut tampered = announcement.clone();
        tampered.timestamp += 1;

        assert!(tampered.verify().is_err());
    }

    #[test]
    fn decode_too_short() {
        let result = DiscoveryAnnouncement::decode(&[0u8; 50]);
        assert!(result.is_err());
    }

    // --- Security tests (T1-T4) ---

    #[test]
    fn reject_tampered_node_id() {
        let key1 = test_secret_key();
        let key2 = test_secret_key();
        let announcement = DiscoveryAnnouncement::new(&key1, None);

        // Encode, replace node_id bytes with a different key, decode
        let mut encoded = announcement.encode();
        let key2_public = key2.public();
        encoded[..32].copy_from_slice(key2_public.as_bytes());

        let tampered = DiscoveryAnnouncement::decode(&encoded).unwrap();
        assert!(matches!(tampered.verify(), Err(Error::InvalidSignature(_))));
    }

    #[test]
    fn decode_invalid_utf8_relay() {
        let key = test_secret_key();
        let announcement =
            DiscoveryAnnouncement::new(&key, Some("https://relay.example.com".parse().unwrap()));
        let mut encoded = announcement.encode();

        // Corrupt UTF-8 in relay URL section (after node_id + length prefix)
        // Position 34 is within the relay URL bytes
        encoded[34] = 0xFF; // Invalid UTF-8 byte

        assert!(matches!(
            DiscoveryAnnouncement::decode(&encoded),
            Err(Error::Decode(_))
        ));
    }

    #[test]
    fn decode_truncated_relay() {
        let key = test_secret_key();
        let relay: RelayUrl = "https://relay.example.com".parse().unwrap();
        let announcement = DiscoveryAnnouncement::new(&key, Some(relay));
        let encoded = announcement.encode();

        // Truncate in the middle of the message
        let truncated = &encoded[..40];

        assert!(matches!(
            DiscoveryAnnouncement::decode(truncated),
            Err(Error::Decode(_))
        ));
    }

    #[test]
    fn reject_tampered_relay_url() {
        let key = test_secret_key();
        let relay: RelayUrl = "https://relay.example.com".parse().unwrap();
        let announcement = DiscoveryAnnouncement::new(&key, Some(relay));
        let mut encoded = announcement.encode();

        // Tamper with the relay URL bytes (change a character in the URL)
        // Format: node_id (32) + relay_len (2) + relay_url (variable) + ...
        // Position 34 is the start of relay URL data (after "https://")
        encoded[42] = b'X'; // Change 'e' in "example" to 'X'

        let decoded = DiscoveryAnnouncement::decode(&encoded).unwrap();

        // Signature verification should fail because relay URL is part of signed data
        assert!(matches!(decoded.verify(), Err(Error::InvalidSignature(_))));
    }

    #[test]
    fn reject_future_timestamp() {
        let key = test_secret_key();
        let announcement = DiscoveryAnnouncement::new(&key, None);

        // Check within tolerance (5 seconds ahead should be fine)
        assert!(!announcement.is_from_future(Duration::from_secs(300)));

        // Create an announcement with timestamp 1 hour in future by tampering encoded bytes
        let future_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;

        // Encode, replace timestamp bytes (after node_id + relay_len), decode
        let mut encoded = announcement.encode();
        // Format: node_id (32) + relay_len (2) + relay (0) + timestamp (8) + sig (64)
        // Timestamp starts at offset 34 for announcements with no relay
        encoded[34..42].copy_from_slice(&future_ts.to_be_bytes());

        let future_announcement = DiscoveryAnnouncement::decode(&encoded).unwrap();

        // 1 hour ahead should be rejected with 5 minute tolerance
        assert!(future_announcement.is_from_future(Duration::from_secs(300)));
    }
}
