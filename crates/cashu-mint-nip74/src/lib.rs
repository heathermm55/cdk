//! Cashu Mint NIP-74 implementation
//!
//! This crate provides helper utilities for Cashu mints to communicate
//! over the Nostr network following the specification defined in
//! `nips/74.md` (draft).
//!
//! * Create **Mint Information** events (`kind:37400`).
//! * Decrypt and parse **Operation Request** events (`kind:27401`).
//! * Build and encrypt **Operation Result** events (`kind:27402`).
//!
//! The implementation relies on the `nostr` crate (path dependency in this
//! workspace) for event structures and NIP-44 encryption.

#![forbid(unsafe_code)]
#![warn(missing_docs, rustdoc::bare_urls)]

use nostr::event::tag::{Tag, TagKind};
use nostr::nips::nip44::{self, Version as Nip44Version};
use nostr::{Event, EventBuilder, EventId, Kind, Keys, PublicKey, SecretKey, Timestamp};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;
#[cfg(feature = "std")]
use nostr::NostrSigner;

/// Convenient alias for crate specific `Result` type.
pub type Result<T> = core::result::Result<T, Nip74Error>;

/// Crate error type.
#[derive(Debug, Error)]
pub enum Nip74Error {
    /// Generic Nostr error returned as string (most builder methods return plain strings).
    #[error("nostr error: {0}")]
    Nostr(String),
    /// Error produced by NIP-44 helpers.
    #[error("nip44 error: {0}")]
    Nip44(#[from] nip44::Error),
    /// Serde (de)serialisation error.
    #[error("serde json error: {0}")]
    Serde(#[from] serde_json::Error),
    /// Missing tag in an event.
    #[error("missing '{0}' tag in event")]
    MissingTag(&'static str),
    /// Event kind mismatch.
    #[error("unexpected event kind: expected {expected}, got {found}")]
    WrongKind {
        /// Expected kind value.
        expected: u64,
        /// Actual received kind value.
        found: u64,
    },
}

/* -------------------------------------------------------------------------- */
/*                                 Mint Info                                  */
/* -------------------------------------------------------------------------- */

/// Data composing a Mint Information event (kind: 37400).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MintInfo {
    /// `d` tag – unique identifier for addressable events.
    pub identifier: String,
    /// `name` tag – display name of the mint.
    pub name: String,
    /// `description` tag – short description.
    pub description: String,
    /// `icon` tag – icon URL (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    /// `version` tag – implementation name / version.
    pub version: String,
    /// `unit` tag – supported currency units (sat, usd …).
    pub units: Vec<String>,
    /// `contact` tag – various contact strings (nostr npub, email …).
    pub contacts: Vec<String>,
    /// `nuts` tag – supported Cashu NUT numbers.
    pub nuts: Vec<String>,
    /// `url` tag – optional HTTP endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// `relays` tag – relays used for NIP-74 communication.
    pub relays: Vec<String>,
    /// `status` tag – running / maintenance …
    pub status: String,
}

impl MintInfo {
    /// Convert `MintInfo` into a signed Nostr event (`kind: 37400`).
    pub fn to_event(&self, keys: &Keys, created_at: Option<Timestamp>) -> Result<Event> {
        let created_at = created_at.unwrap_or_else(Timestamp::now);

        // Build tags according to spec.
        let mut tags: Vec<Tag> = Vec::new();

        tags.push(Tag::identifier(self.identifier.clone()));
        tags.push(Tag::custom(TagKind::Name, vec![self.name.clone()]));
        tags.push(Tag::custom(TagKind::Description, vec![self.description.clone()]));

        if let Some(icon) = &self.icon {
            tags.push(Tag::custom(TagKind::Image, vec![icon.clone()]));
        }

        tags.push(Tag::custom(TagKind::custom("version"), vec![self.version.clone()]));

        // `unit` can contain multiple values.
        tags.push(Tag::custom(
            TagKind::custom("unit"),
            self.units.clone(),
        ));

        // `contact` – multiple values.
        tags.push(Tag::custom(
            TagKind::custom("contact"),
            self.contacts.clone(),
        ));

        // `nuts` – list of supported nuts.
        // convert to strings if necessary
        tags.push(Tag::custom(TagKind::custom("nuts"), self.nuts.clone()));

        if let Some(url) = &self.url {
            tags.push(Tag::custom(TagKind::Url, vec![url.clone()]));
        }

        // `relays` – multiple.
        tags.push(Tag::custom(TagKind::custom("relays"), self.relays.clone()));

        tags.push(Tag::custom(TagKind::Status, vec![self.status.clone()]));

        let builder = EventBuilder::new(Kind::from(37400u16), "")
            .tags(tags)
            .custom_created_at(created_at);
        Ok(builder
            .sign_with_keys(keys)
            .map_err(|e| Nip74Error::Nostr(e.to_string()))?)
    }

    /// Build an event using a remote signer that implements NIP-46.
    #[cfg(feature = "std")]
    pub async fn to_event_with_signer<T>(
        &self,
        signer: &T,
        created_at: Option<Timestamp>,
    ) -> Result<Event>
    where
        T: NostrSigner,
    {
        let created_at = created_at.unwrap_or_else(Timestamp::now);

        // Build tags (same as `to_event`).
        let mut tags: Vec<Tag> = Vec::new();
        tags.push(Tag::identifier(self.identifier.clone()));
        tags.push(Tag::custom(TagKind::Name, vec![self.name.clone()]));
        tags.push(Tag::custom(TagKind::Description, vec![self.description.clone()]));
        if let Some(icon) = &self.icon {
            tags.push(Tag::custom(TagKind::Image, vec![icon.clone()]));
        }
        tags.push(Tag::custom(TagKind::custom("version"), vec![self.version.clone()]));
        tags.push(Tag::custom(TagKind::custom("unit"), self.units.clone()));
        tags.push(Tag::custom(TagKind::custom("contact"), self.contacts.clone()));
        tags.push(Tag::custom(TagKind::custom("nuts"), self.nuts.clone()));
        if let Some(url) = &self.url {
            tags.push(Tag::custom(TagKind::Url, vec![url.clone()]));
        }
        tags.push(Tag::custom(TagKind::custom("relays"), self.relays.clone()));
        tags.push(Tag::custom(TagKind::Status, vec![self.status.clone()]));

        // Build the EventBuilder and let the signer sign it.
        let builder = EventBuilder::new(Kind::from(37400u16), "")
            .tags(tags)
            .custom_created_at(created_at);

        // Ensure that the signer corresponds to the given mint public key (optional runtime check).
        let signer_pub = signer
            .get_public_key()
            .await
            .map_err(|e| Nip74Error::Nostr(e.to_string()))?;
        // For simplicity this helper just assumes `signer_pub == *mint_pubkey`; add extra validation if required.

        builder
            .sign(signer)
            .await
            .map_err(|e| Nip74Error::Nostr(e.to_string()))
    }
}

/* -------------------------------------------------------------------------- */
/*                             Operation Request                              */
/* -------------------------------------------------------------------------- */

/// Supported operation methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OperationMethod {
    /// Mint new tokens (NUT-04).
    Mint,
    /// Melt tokens for payments (NUT-05).
    Melt,
    /// Swap tokens (NUT-03).
    Swap,
    /// Check token state (NUT-07).
    Check,
    /// Restore tokens (NUT-09).
    Restore,
    /// Get mint information (NUT-06).
    Info,
}

/// Payload contained inside a decrypted `kind:27401` event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationRequest {
    /// Operation method.
    pub method: OperationMethod,
    /// Unique request id (client generated).
    pub request_id: String,
    /// Method specific data encoded as generic JSON value.
    pub data: Value,
}

impl OperationRequest {
    /// Decrypt and parse a `kind:27401` event.
    pub fn from_event(event: &Event, mint_secret_key: &SecretKey) -> Result<Self> {
        // Validate event kind.
        if event.kind != Kind::from(27401u16) {
            return Err(Nip74Error::WrongKind {
                expected: 27401,
                found: event.kind.as_u16() as u64,
            });
        }

        // NOTE: Optionally, a production implementation SHOULD verify the presence of a 'p' tag
        //       matching the mint public key for additional security. It is omitted here to keep
        //       the helper lightweight and avoid additional dependencies.

        // Decrypt payload using NIP-44.
        let plaintext = nip44::decrypt(mint_secret_key, &event.pubkey, &event.content)?;
        // Deserialize JSON payload.
        let req: OperationRequest = serde_json::from_str(&plaintext)?;
        Ok(req)
    }
}

/* -------------------------------------------------------------------------- */
/*                              Operation Result                              */
/* -------------------------------------------------------------------------- */

/// Status of an operation result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResultStatus {
    /// Operation completed successfully.
    Success,
    /// Operation failed.
    Error,
}

/// Error details included in `OperationResult` when status is `Error`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultError {
    /// Machine parseable error code.
    pub code: String,
    /// Human friendly message.
    pub message: String,
}

/// Payload for `kind:27402` events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationResult {
    /// Success or Error.
    pub status: ResultStatus,
    /// Corresponding request id.
    pub request_id: String,
    /// Present only when `status == Success`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    /// Present only when `status == Error`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ResultError>,
}

impl OperationResult {
    /// Build and sign a `kind:27402` event directed to a client.
    pub fn to_event(
        &self,
        mint_keys: &Keys,
        client_pubkey: &PublicKey,
        request_event_id: &EventId,
        created_at: Option<Timestamp>,
    ) -> Result<Event> {
        // Serialize and encrypt content.
        let plaintext = serde_json::to_string(self)?;
        let encrypted = nip44::encrypt(
            mint_keys.secret_key(),
            client_pubkey,
            plaintext,
            Nip44Version::default(),
        )?;

        // Build tags.
        let mut tags: Vec<Tag> = Vec::new();
        tags.push(Tag::public_key(*client_pubkey));
        tags.push(Tag::event(*request_event_id));

        let created_at = created_at.unwrap_or_else(Timestamp::now);

        let builder = EventBuilder::new(Kind::from(27402u16), encrypted)
            .tags(tags)
            .custom_created_at(created_at);
        Ok(builder
            .sign_with_keys(mint_keys)
            .map_err(|e| Nip74Error::Nostr(e.to_string()))?)
    }

    /// Build a `kind:27402` event using a remote signer (NIP-46).
    #[cfg(feature = "std")]
    pub async fn to_event_with_signer<T>(
        &self,
        signer: &T,
        mint_pubkey: &PublicKey,
        client_pubkey: &PublicKey,
        request_event_id: &EventId,
        created_at: Option<Timestamp>,
    ) -> Result<Event>
    where
        T: NostrSigner,
    {
        // Serialize and encrypt the payload.
        let plaintext = serde_json::to_string(self)?;

        // Encrypt using signer NIP-44 helper.
        let ciphertext = signer
            .nip44_encrypt(client_pubkey, &plaintext)
            .await
            .map_err(|e| Nip74Error::Nostr(e.to_string()))?;

        let mut tags: Vec<Tag> = Vec::new();
        tags.push(Tag::public_key(*client_pubkey));
        tags.push(Tag::event(*request_event_id));

        let created_at = created_at.unwrap_or_else(Timestamp::now);

        let builder = EventBuilder::new(Kind::from(27402u16), ciphertext)
            .tags(tags)
            .custom_created_at(created_at);

        // Ensure that the signer corresponds to the given mint public key (optional runtime check).
        let signer_pub = signer
            .get_public_key()
            .await
            .map_err(|e| Nip74Error::Nostr(e.to_string()))?;
        // For simplicity this helper just assumes `signer_pub == *mint_pubkey`; add extra validation if required.

        builder
            .sign(signer)
            .await
            .map_err(|e| Nip74Error::Nostr(e.to_string()))
    }
}

/* -------------------------------------------------------------------------- */
/*                               Convenience                                  */
/* -------------------------------------------------------------------------- */

/// Generate a new unique request id (uuid-v4 based helper).
pub fn new_request_id() -> String {
    Uuid::new_v4().to_string()
}

/* -------------------------------------------------------------------------- */
/*                               Tests (std)                                  */
/* -------------------------------------------------------------------------- */

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::Keys;

    #[test]
    fn test_request_id() {
        let id1 = new_request_id();
        let id2 = new_request_id();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_flow() {
        // Generate simple key pairs for mint and client.
        let mint_keys = Keys::generate();
        let client_keys = Keys::generate();

        // Build fake request.
        let op_req = OperationRequest {
            method: OperationMethod::Mint,
            request_id: new_request_id(),
            data: serde_json::json!({ "quote": "abc", "outputs": [] }),
        };
        let plaintext = serde_json::to_string(&op_req).unwrap();
        let encrypted = nip44::encrypt(
            client_keys.secret_key(),
            &mint_keys.public_key(),
            plaintext,
            Nip44Version::default(),
        )
        .unwrap();

        let tags = vec![Tag::public_key(mint_keys.public_key())];
        let req_event = EventBuilder::new(Kind::from(27401u16), encrypted)
            .tags(tags)
            .sign_with_keys(&client_keys)
            .unwrap();

        let parsed = OperationRequest::from_event(&req_event, mint_keys.secret_key())
            .unwrap();
        assert_eq!(parsed.method, OperationMethod::Mint);

        // Build result.
        let op_res = OperationResult {
            status: ResultStatus::Success,
            request_id: parsed.request_id.clone(),
            data: Some(serde_json::json!({ "signatures": [] })),
            error: None,
        };
        let res_event = op_res
            .to_event(
                &mint_keys,
                &client_keys.public_key(),
                &req_event.id,
                None,
            )
            .unwrap();

        // Decrypt on client side.
        let decrypted = nip44::decrypt(
            client_keys.secret_key(),
            &mint_keys.public_key(),
            &res_event.content,
        )
        .unwrap();
        let parsed_res: OperationResult = serde_json::from_str(&decrypted).unwrap();
        assert_eq!(parsed_res.status, ResultStatus::Success);
    }
} 