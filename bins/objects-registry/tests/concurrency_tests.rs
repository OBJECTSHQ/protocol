//! Concurrency tests for OBJECTS Registry database operations.
//!
//! These tests verify that race conditions are handled correctly.

use objects_identity::IdentityId;
use objects_registry::db::{IdentityRow, insert_identity, signer_type_to_i16};
use objects_registry::error::RegistryError;
use objects_test_utils::crypto;
use p256::ecdsa::SigningKey as P256SigningKey;
use sqlx::PgPool;
use tokio::task::JoinSet;

#[sqlx::test]
async fn test_concurrent_identity_creation_with_same_handle(pool: PgPool) {
    // Spawn 10 tasks trying to create identity with handle "alice" concurrently
    // Exactly 1 should succeed, 9 should fail with HandleTaken

    let mut tasks = JoinSet::new();
    let handle = "alice";

    for _i in 0..10 {
        let pool = pool.clone();
        let signing_key = crypto::passkey_keypair().signing_key;
        let public_key: [u8; 33] = signing_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .unwrap();
        let nonce = rand::random::<[u8; 8]>();
        let identity_id = IdentityId::derive(&public_key, &nonce);

        tasks.spawn(async move {
            let row = IdentityRow {
                id: identity_id.to_string(),
                handle: handle.to_string(),
                signer_type: signer_type_to_i16(objects_identity::SignerType::Passkey),
                signer_public_key: public_key.to_vec(),
                nonce: nonce.to_vec(),
                wallet_address: None,
                created_at: 1000,
                updated_at: 1000,
            };
            insert_identity(&pool, &row).await
        });
    }

    let mut successes = 0;
    let mut handle_taken_errors = 0;

    while let Some(result) = tasks.join_next().await {
        match result.unwrap() {
            Ok(_) => successes += 1,
            Err(RegistryError::HandleTaken(_)) => handle_taken_errors += 1,
            Err(e) => panic!("unexpected error: {}", e),
        }
    }

    assert_eq!(successes, 1, "Expected exactly 1 success");
    assert_eq!(
        handle_taken_errors, 9,
        "Expected exactly 9 handle taken errors"
    );
}

#[sqlx::test]
async fn test_concurrent_identity_creation_with_same_id(pool: PgPool) {
    // Spawn 10 tasks trying to create identity with same ID concurrently
    // Exactly 1 should succeed, 9 should fail with DuplicateId

    let signing_key = crypto::passkey_keypair().signing_key;
    let public_key: [u8; 33] = signing_key
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap();
    let nonce = rand::random::<[u8; 8]>();
    let identity_id = IdentityId::derive(&public_key, &nonce);

    let mut tasks = JoinSet::new();

    for i in 0..10 {
        let pool = pool.clone();
        let identity_id = identity_id.clone();
        let public_key = public_key.clone();
        let nonce = nonce.clone();

        tasks.spawn(async move {
            let row = IdentityRow {
                id: identity_id.to_string(),
                handle: format!("user{}", i), // Different handles
                signer_type: signer_type_to_i16(objects_identity::SignerType::Passkey),
                signer_public_key: public_key.to_vec(),
                nonce: nonce.to_vec(),
                wallet_address: None,
                created_at: 1000,
                updated_at: 1000,
            };
            insert_identity(&pool, &row).await
        });
    }

    let mut successes = 0;
    let mut duplicate_errors = 0;

    while let Some(result) = tasks.join_next().await {
        match result.unwrap() {
            Ok(_) => successes += 1,
            Err(RegistryError::IdentityExists(_)) => duplicate_errors += 1,
            Err(e) => panic!("unexpected error: {}", e),
        }
    }

    assert_eq!(successes, 1, "Expected exactly 1 success");
    assert_eq!(
        duplicate_errors, 9,
        "Expected exactly 9 duplicate ID errors"
    );
}

#[sqlx::test]
async fn test_concurrent_wallet_linking(pool: PgPool) {
    // Create 2 identities
    let signing_key1 = crypto::passkey_keypair().signing_key;
    let public_key1: [u8; 33] = signing_key1
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap();
    let nonce1 = rand::random::<[u8; 8]>();
    let identity_id1 = IdentityId::derive(&public_key1, &nonce1);

    let signing_key2 = crypto::passkey_keypair().signing_key;
    let public_key2: [u8; 33] = signing_key2
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap();
    let nonce2 = rand::random::<[u8; 8]>();
    let identity_id2 = IdentityId::derive(&public_key2, &nonce2);

    // Insert both identities
    let row1 = IdentityRow {
        id: identity_id1.to_string(),
        handle: "alice".to_string(),
        signer_type: signer_type_to_i16(objects_identity::SignerType::Passkey),
        signer_public_key: public_key1.to_vec(),
        nonce: nonce1.to_vec(),
        wallet_address: None,
        created_at: 1000,
        updated_at: 1000,
    };
    insert_identity(&pool, &row1).await.unwrap();

    let row2 = IdentityRow {
        id: identity_id2.to_string(),
        handle: "bob".to_string(),
        signer_type: signer_type_to_i16(objects_identity::SignerType::Passkey),
        signer_public_key: public_key2.to_vec(),
        nonce: nonce2.to_vec(),
        wallet_address: None,
        created_at: 1000,
        updated_at: 1000,
    };
    insert_identity(&pool, &row2).await.unwrap();

    // Concurrently link same wallet to both identities
    let wallet_address = "0x1234567890abcdef1234567890abcdef12345678";

    let mut tasks = JoinSet::new();

    for id in [identity_id1.to_string(), identity_id2.to_string()] {
        let pool = pool.clone();
        let wallet_address = wallet_address.to_string();

        tasks.spawn(async move {
            objects_registry::db::update_identity_wallet(&pool, &id, &wallet_address, 1001).await
        });
    }

    let mut successes = 0;
    let mut wallet_linked_errors = 0;

    while let Some(result) = tasks.join_next().await {
        match result.unwrap() {
            Ok(_) => successes += 1,
            Err(RegistryError::WalletLinked(_)) => wallet_linked_errors += 1,
            Err(e) => panic!("unexpected error: {}", e),
        }
    }

    // Exactly 1 should succeed
    assert_eq!(successes, 1, "Expected exactly 1 success");
    assert_eq!(
        wallet_linked_errors, 1,
        "Expected exactly 1 wallet already linked error"
    );
}
