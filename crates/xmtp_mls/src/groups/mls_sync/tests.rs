use super::*;
use crate::{builder::ClientBuilder, utils::TestMlsGroup};
use mockall::predicate::eq;
use std::sync::Arc;
use xmtp_cryptography::utils::generate_local_wallet;
use xmtp_db::mock::MockDbQuery;

/// This test is not reproducible in webassembly, b/c webassembly has only one thread.
#[cfg_attr(
    not(target_arch = "wasm32"),
    tokio::test(flavor = "multi_thread", worker_threads = 10)
)]
#[cfg(not(target_family = "wasm"))]
async fn publish_intents_worst_case_scenario() {
    use crate::tester;

    tester!(amal_a, triggers);
    let amal_group_a: Arc<MlsGroup<_>> =
        Arc::new(amal_a.create_group(None, Default::default()).unwrap());

    let db = amal_a.context.db();

    // create group intent
    amal_group_a.sync().await.unwrap();
    assert_eq!(db.intents_processed(), 1);

    for _ in 0..100 {
        use crate::groups::send_message_opts::SendMessageOpts;

        let s = xmtp_common::rand_string::<100>();
        amal_group_a
            .send_message_optimistic(s.as_bytes(), SendMessageOpts::default())
            .unwrap();
    }

    let mut set = tokio::task::JoinSet::new();
    for _ in 0..50 {
        let g = amal_group_a.clone();
        set.spawn(async move { g.publish_intents().await });
    }

    let res = set.join_all().await;
    let errs: Vec<&Result<_, _>> = res.iter().filter(|r| r.is_err()).collect();
    errs.iter().for_each(|e| {
        tracing::error!("{}", e.as_ref().unwrap_err());
    });

    let published = db.intents_published();
    assert_eq!(published, 101);
    let created = db.intents_created();
    assert_eq!(created, 101);
    if !errs.is_empty() {
        panic!("Errors during publish");
    }
}

#[xmtp_common::test]
async fn hmac_keys_work_as_expected() {
    let wallet = generate_local_wallet();
    let amal = Arc::new(ClientBuilder::new_test_client(&wallet).await);
    let amal_group: Arc<TestMlsGroup> =
        Arc::new(amal.create_group(None, Default::default()).unwrap());

    let hmac_keys = amal_group.hmac_keys(-1..=1).unwrap();
    let current_hmac_key = amal_group.hmac_keys(0..=0).unwrap().pop().unwrap();
    assert_eq!(hmac_keys.len(), 3);
    assert_eq!(hmac_keys[1].key, current_hmac_key.key);
    assert_eq!(hmac_keys[1].epoch, current_hmac_key.epoch);

    // Make sure the keys are different
    assert_ne!(hmac_keys[0].key, hmac_keys[1].key);
    assert_ne!(hmac_keys[0].key, hmac_keys[2].key);
    assert_ne!(hmac_keys[1].key, hmac_keys[2].key);

    // Make sure the epochs align
    let current_epoch = hmac_epoch();
    assert_eq!(hmac_keys[0].epoch, current_epoch - 1);
    assert_eq!(hmac_keys[1].epoch, current_epoch);
    assert_eq!(hmac_keys[2].epoch, current_epoch + 1);
}

#[test]
fn send_failures_for_published_intents_revert_to_to_publish() {
    let intent = StoredGroupIntent {
        id: 42,
        kind: IntentKind::SendMessage,
        group_id: xmtp_common::rand_vec::<16>(),
        data: Vec::new(),
        state: IntentState::Published,
        payload_hash: Some(xmtp_common::rand_vec::<32>()),
        post_commit_data: None,
        publish_attempts: 0,
        staged_commit: None,
        published_in_epoch: Some(7),
        should_push: false,
        sequence_id: None,
        originator_id: None,
    };

    let mut db = MockDbQuery::new();
    db.expect_increment_intent_publish_attempt_count()
        .with(eq(intent.id))
        .times(1)
        .returning(|_| Ok(()));
    db.expect_set_group_intent_to_publish()
        .with(eq(intent.id))
        .times(1)
        .returning(|_| Ok(()));

    let result = handle_published_intent_send_failure(&db, &intent);
    assert!(result.is_ok());
}

/// Test that process_delete_message handles completely malformed bytes gracefully
///
/// This verifies sync resilience when receiving corrupted DeleteMessage protos.
#[xmtp_common::test(unwrap_try = true)]
async fn test_process_delete_message_malformed_encoded_content() {
    use crate::tester;
    use xmtp_db::group_message::{ContentType, DeliveryStatus, GroupMessageKind};

    tester!(alix);
    let alix_group = alix.create_group(None, None)?;

    // Create a message with completely invalid EncodedContent proto
    let malformed_message = xmtp_db::group_message::StoredGroupMessage {
        id: vec![1, 2, 3],
        group_id: alix_group.group_id.clone(),
        decrypted_message_bytes: vec![0xFF, 0xFE, 0xFD], // Invalid protobuf
        sent_at_ns: xmtp_common::time::now_ns(),
        kind: GroupMessageKind::Application,
        sender_installation_id: vec![1, 2, 3],
        sender_inbox_id: alix.inbox_id().to_string(),
        delivery_status: DeliveryStatus::Published,
        content_type: ContentType::DeleteMessage,
        version_major: 1,
        version_minor: 0,
        authority_id: "xmtp.org".to_string(),
        reference_id: None,
        expire_at_ns: None,
        sequence_id: 1,
        originator_id: 1,
        inserted_at_ns: 0,
        should_push: false,
    };

    // Use load_mls_group_with_lock to get access to the MLS group and call process_delete_message
    let storage = alix.context.mls_storage();
    let result: Result<(), crate::groups::GroupError> =
        alix_group.load_mls_group_with_lock(storage, |mls_group| {
            let inner_result =
                alix_group.process_delete_message(&mls_group, storage, &malformed_message);
            match inner_result {
                Ok(()) => Ok(()),
                Err(_) => Err(crate::groups::GroupError::InvalidGroupMembership),
            }
        });

    assert!(
        result.is_ok(),
        "Malformed EncodedContent should not cause error"
    );
}

/// Test that process_delete_message handles valid EncodedContent with malformed inner proto
#[xmtp_common::test(unwrap_try = true)]
async fn test_process_delete_message_malformed_inner_proto() {
    use crate::tester;
    use prost::Message;
    use xmtp_db::group_message::{ContentType, DeliveryStatus, GroupMessageKind};
    use xmtp_proto::xmtp::mls::message_contents::EncodedContent;

    tester!(alix);
    let alix_group = alix.create_group(None, None)?;

    // Create a valid EncodedContent wrapper but with invalid inner DeleteMessage content
    let encoded_content = EncodedContent {
        r#type: Some(xmtp_proto::xmtp::mls::message_contents::ContentTypeId {
            authority_id: "xmtp.org".to_string(),
            type_id: "deleteMessage".to_string(),
            version_major: 1,
            version_minor: 0,
        }),
        parameters: std::collections::HashMap::new(),
        fallback: None,
        compression: None,
        content: vec![0xFF, 0xFE, 0xFD], // Invalid DeleteMessage proto bytes
    };

    let mut encoded_bytes = Vec::new();
    encoded_content.encode(&mut encoded_bytes)?;

    let malformed_message = xmtp_db::group_message::StoredGroupMessage {
        id: vec![4, 5, 6],
        group_id: alix_group.group_id.clone(),
        decrypted_message_bytes: encoded_bytes,
        sent_at_ns: xmtp_common::time::now_ns(),
        kind: GroupMessageKind::Application,
        sender_installation_id: vec![1, 2, 3],
        sender_inbox_id: alix.inbox_id().to_string(),
        delivery_status: DeliveryStatus::Published,
        content_type: ContentType::DeleteMessage,
        version_major: 1,
        version_minor: 0,
        authority_id: "xmtp.org".to_string(),
        reference_id: None,
        expire_at_ns: None,
        sequence_id: 2,
        originator_id: 1,
        inserted_at_ns: 0,
        should_push: false,
    };

    let storage = alix.context.mls_storage();
    let result: Result<(), crate::groups::GroupError> =
        alix_group.load_mls_group_with_lock(storage, |mls_group| {
            let inner_result =
                alix_group.process_delete_message(&mls_group, storage, &malformed_message);
            match inner_result {
                Ok(()) => Ok(()),
                Err(_) => Err(crate::groups::GroupError::InvalidGroupMembership),
            }
        });

    assert!(
        result.is_ok(),
        "Malformed inner DeleteMessage proto should not cause error"
    );
}

/// Test that process_delete_message handles invalid hex message_id gracefully
#[xmtp_common::test(unwrap_try = true)]
async fn test_process_delete_message_invalid_hex_message_id() {
    use crate::tester;
    use prost::Message;
    use xmtp_db::group_message::{ContentType, DeliveryStatus, GroupMessageKind};
    use xmtp_proto::xmtp::mls::message_contents::EncodedContent;
    use xmtp_proto::xmtp::mls::message_contents::content_types::DeleteMessage;

    tester!(alix);
    let alix_group = alix.create_group(None, None)?;

    // Create a valid DeleteMessage but with invalid hex in message_id
    let delete_msg = DeleteMessage {
        message_id: "not_valid_hex!!!".to_string(), // Invalid hex
    };

    let mut delete_bytes = Vec::new();
    delete_msg.encode(&mut delete_bytes)?;

    let encoded_content = EncodedContent {
        r#type: Some(xmtp_proto::xmtp::mls::message_contents::ContentTypeId {
            authority_id: "xmtp.org".to_string(),
            type_id: "deleteMessage".to_string(),
            version_major: 1,
            version_minor: 0,
        }),
        parameters: std::collections::HashMap::new(),
        fallback: None,
        compression: None,
        content: delete_bytes,
    };

    let mut encoded_bytes = Vec::new();
    encoded_content.encode(&mut encoded_bytes)?;

    let message_with_bad_hex = xmtp_db::group_message::StoredGroupMessage {
        id: vec![7, 8, 9],
        group_id: alix_group.group_id.clone(),
        decrypted_message_bytes: encoded_bytes,
        sent_at_ns: xmtp_common::time::now_ns(),
        kind: GroupMessageKind::Application,
        sender_installation_id: vec![1, 2, 3],
        sender_inbox_id: alix.inbox_id().to_string(),
        delivery_status: DeliveryStatus::Published,
        content_type: ContentType::DeleteMessage,
        version_major: 1,
        version_minor: 0,
        authority_id: "xmtp.org".to_string(),
        reference_id: None,
        expire_at_ns: None,
        sequence_id: 3,
        originator_id: 1,
        inserted_at_ns: 0,
        should_push: false,
    };

    let storage = alix.context.mls_storage();
    let result: Result<(), crate::groups::GroupError> =
        alix_group.load_mls_group_with_lock(storage, |mls_group| {
            let inner_result =
                alix_group.process_delete_message(&mls_group, storage, &message_with_bad_hex);
            match inner_result {
                Ok(()) => Ok(()),
                Err(_) => Err(crate::groups::GroupError::InvalidGroupMembership),
            }
        });

    assert!(
        result.is_ok(),
        "Invalid hex message_id should not cause error"
    );
}
