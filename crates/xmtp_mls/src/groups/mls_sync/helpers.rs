use super::*;

/// Shared helper utilities for the sync pipeline.

/// Extract the sender identity from a processed MLS message.
///
/// This trusts the credential embedded in the message; inbox membership checks
/// happen in higher-level validation paths.
pub(super) fn extract_message_sender(
    openmls_group: &mut OpenMlsGroup,
    decrypted_message: &ProcessedMessage,
    message_created_ns: u64,
) -> Result<(InboxId, Vec<u8>), GroupMessageProcessingError> {
    if let Sender::Member(leaf_node_index) = decrypted_message.sender()
        && let Some(member) = openmls_group.member_at(*leaf_node_index)
        && member.credential.eq(decrypted_message.credential())
    {
        let basic_credential = BasicCredential::try_from(member.credential)?;
        let sender_inbox_id = parse_credential(basic_credential.identity())?;
        return Ok((sender_inbox_id, member.signature_key));
    }

    let basic_credential = BasicCredential::try_from(decrypted_message.credential().clone())?;
    Err(GroupMessageProcessingError::InvalidSender {
        message_time_ns: message_created_ns,
        credential: basic_credential.identity().to_vec(),
    })
}

/// Execute a commit-creating operation using a savepoint pattern.
///
/// This function:
/// 1. Runs the operation in a transaction savepoint
/// 2. Extracts the pending commit data
/// 3. Rolls back the transaction (avoiding the need for clear_pending_commit)
/// 4. Returns the operation result, the staged commit, and the group epoch the commit was created in
///
/// This is more reliable than using `clear_pending_commit` because it uses
/// SQLite's built-in savepoint rollback mechanism.
///
/// The epoch is captured from within the transaction before the operation,
/// ensuring it reflects the state used during the commit creation even if
/// the database is updated between the transaction and when the caller uses it.
pub(in crate::groups) fn generate_commit_with_rollback<S, R, E, F>(
    storage: &S,
    openmls_group: &mut OpenMlsGroup,
    operation: F,
) -> Result<(R, Option<Vec<u8>>, u64), GroupError>
where
    S: XmtpMlsStorageProvider,
    E: Into<GroupError>,
    F: for<'a> FnOnce(
        &mut OpenMlsGroup,
        &XmtpOpenMlsProviderRef<<S::TxQuery as TransactionalKeyStore>::Store<'a>>,
    ) -> Result<R, E>,
{
    let mut result = None;
    let mut staged_commit = None;
    let mut group_epoch = None;

    // TXN-EDGE: staged MLS commit snapshot + pre-commit epoch capture - unresolved (intentional rollback snapshot, not durable state)
    let transaction_result = storage.transaction(|conn| {
        let key_store = conn.key_store();
        let provider = XmtpOpenMlsProviderRef::new(&key_store);

        // Capture the epoch before the operation to ensure we have the correct
        // epoch even if the database is updated after the transaction and before we save the intent locally.
        group_epoch = Some(openmls_group.epoch().as_u64());

        // Execute the operation (e.g., self_update, update_group_context_extensions, etc.)
        result = Some(operation(openmls_group, &provider));

        // Extract the staged commit data before rollback
        staged_commit = openmls_group
            .pending_commit()
            .as_ref()
            .map(xmtp_db::db_serialize)
            .transpose()
            .inspect_err(|error| tracing::error!(%error, "Error serializing staged commit"))
            .ok()
            .flatten();

        // Rollback the transaction to avoid persisting the commit
        Err::<(), StorageError>(StorageError::IntentionalRollback)
    });

    let Err(e) = transaction_result else {
        unreachable!("Transaction never returns ok");
    };

    // Check if the transaction was intentionally rolled back (expected)
    // or if there was a real error
    if !matches!(e, StorageError::IntentionalRollback) {
        return Err(e.into());
    }

    // Return early if group epoch is not set otherwise unwrap the group epoch
    let group_epoch = group_epoch.expect("Group epoch should have been captured in transaction");

    // This must go after error checking
    // Reload the group to clear its internal cache after rollback
    openmls_group.reload(storage)?;

    // Extract and handle the operation result
    let operation_result = result
        .expect("Operation should have been called")
        .map_err(|e| e.into())?;

    Ok((operation_result, staged_commit, group_epoch))
}

pub(crate) fn decode_staged_commit(
    data: &[u8],
) -> Result<StagedCommit, GroupMessageProcessingError> {
    Ok(xmtp_db::db_deserialize(data)?)
}

/// Reset or fail a published intent after transport send fails.
///
/// Retryable failures go back to `ToPublish` so the next attempt re-encrypts at
/// the latest epoch. Non-retryable failures are recorded as terminal intent
/// errors along with their synthetic failed message rows.
pub(super) fn handle_published_intent_send_failure<Db: QueryGroupIntent>(
    db: &Db,
    intent: &StoredGroupIntent,
) -> Result<(), GroupError> {
    if (intent.publish_attempts + 1) as usize >= MAX_INTENT_PUBLISH_ATTEMPTS {
        tracing::error!(
            intent.id,
            intent.kind = %intent.kind,
            "intent {} has reached max publish attempts",
            intent.id
        );
        let id = utils::id::calculate_message_id_for_intent(intent)?;
        db.set_group_intent_error_and_fail_msg(intent, id)?;
    } else {
        // Reset so the next retry re-encrypts at the current epoch.
        db.increment_intent_publish_attempt_count(intent.id)?;
        db.set_group_intent_to_publish(intent.id)?;
    }

    Ok(())
}
