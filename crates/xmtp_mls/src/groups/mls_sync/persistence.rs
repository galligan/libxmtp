//! Durable side effects that outlive one sync attempt.
//!
//! This module is where successfully validated work becomes transcript rows,
//! cursor movement, mirrored metadata, and post-error bookkeeping.

use super::*;
use crate::groups::QueryableContentFields;
use xmtp_common::{MaybeSend, MaybeSync};

/// Storage hooks needed when sync detects evidence of a fork.
pub(super) trait ForkDetectionContext: MaybeSend + MaybeSync {
    fn inbox_id(&self) -> InboxIdRef<'_>;
    fn installation_id_string(&self) -> String;
    fn mark_group_as_maybe_forked(
        &self,
        group_id: &[u8],
        details: String,
    ) -> Result<(), StorageError>;
}

/// Post-processing hooks that intentionally happen outside the main apply path.
pub(super) trait ReceivePostProcessContext: ForkDetectionContext {
    fn prune_icebox(&self) -> Result<(), GroupMessageProcessingError>;
    fn set_group_paused(
        &self,
        group_id: &[u8],
        min_version: &str,
    ) -> Result<(), GroupMessageProcessingError>;
}

impl<Context> ForkDetectionContext for Context
where
    Context: XmtpSharedContext,
{
    fn inbox_id(&self) -> InboxIdRef<'_> {
        self.inbox_id()
    }

    fn installation_id_string(&self) -> String {
        self.installation_id().to_string()
    }

    fn mark_group_as_maybe_forked(
        &self,
        group_id: &[u8],
        details: String,
    ) -> Result<(), StorageError> {
        self.db().mark_group_as_maybe_forked(group_id, details)
    }
}

impl<Context> ReceivePostProcessContext for Context
where
    Context: XmtpSharedContext,
{
    fn prune_icebox(&self) -> Result<(), GroupMessageProcessingError> {
        self.db().prune_icebox()?;
        Ok(())
    }

    fn set_group_paused(
        &self,
        group_id: &[u8],
        min_version: &str,
    ) -> Result<(), GroupMessageProcessingError> {
        self.db().set_group_paused(group_id, min_version)?;
        Ok(())
    }
}

/// Record a likely fork only when the epoch mismatch points forward in time.
fn mark_probable_fork<Context>(
    context: &Context,
    group_id: &[u8],
    message_cursor: u64,
    message_epoch: GroupEpoch,
    group_epoch: u64,
    error: &GroupMessageProcessingError,
) -> Result<(), GroupMessageProcessingError>
where
    Context: ForkDetectionContext,
{
    let fork_details = format!(
        "Message cursor [{}] epoch [{}] is greater than group epoch [{}], your group may be forked",
        message_cursor, message_epoch, group_epoch
    );
    tracing::error!(
        inbox_id = context.inbox_id(),
        installation_id = %context.installation_id_string(),
        group_id = hex::encode(group_id),
        original_error = error.to_string(),
        fork_details
    );
    let _ = context.mark_group_as_maybe_forked(group_id, fork_details);
    Ok(())
}

/// Best-effort cleanup after a successful receive pass.
pub(super) fn prune_processed_icebox<Context>(
    context: &Context,
) -> Result<(), GroupMessageProcessingError>
where
    Context: ReceivePostProcessContext,
{
    context.prune_icebox()?;
    Ok(())
}

/// Pause a group when we prove local protocol support is too old to continue safely.
pub(super) fn pause_group_for_protocol_version<Context>(
    context: &Context,
    group_id: &[u8],
    min_version: &str,
) -> Result<(), GroupMessageProcessingError>
where
    Context: ReceivePostProcessContext,
{
    context.set_group_paused(group_id, min_version)?;
    tracing::warn!(
        "Group [{}] paused due to minimum protocol version requirement",
        hex::encode(group_id)
    );
    Ok(())
}

impl<Context> MlsGroup<Context>
where
    Context: XmtpSharedContext,
{
    /// Mirror metadata writes from a local intent into the group row.
    ///
    /// These updates are visible before the matching transcript message is
    /// observed again from the network, so the local DB view stays consistent
    /// with the intent state machine.
    pub(super) fn handle_metadata_update_from_intent(
        &self,
        intent: &StoredGroupIntent,
        storage: &impl XmtpMlsStorageProvider,
    ) -> Result<(), IntentError> {
        if intent.kind == MetadataUpdate {
            let data = UpdateMetadataIntentData::try_from(intent.data.clone())?;

            match data.field_name.as_str() {
                field_name if field_name == MetadataField::MessageDisappearFromNS.as_str() => {
                    storage.db().update_message_disappearing_from_ns(
                        self.group_id.clone(),
                        data.field_value.parse::<i64>().ok(),
                    )?
                }
                field_name if field_name == MetadataField::MessageDisappearInNS.as_str() => {
                    storage.db().update_message_disappearing_in_ns(
                        self.group_id.clone(),
                        data.field_value.parse::<i64>().ok(),
                    )?
                }
                _ => {} // handle other metadata updates
            }
        }

        Ok(())
    }

    /// Mirror metadata changes derived from a validated remote commit.
    pub(super) fn handle_metadata_update_from_commit(
        &self,
        metadata_field_changes: &Vec<group_updated::MetadataFieldChange>,
        storage: &impl XmtpMlsStorageProvider,
    ) -> Result<(), StorageError> {
        for change in metadata_field_changes {
            match change.field_name.as_str() {
                field_name if field_name == MetadataField::MessageDisappearFromNS.as_str() => {
                    let parsed_value = change
                        .new_value
                        .as_deref()
                        .and_then(|v| v.parse::<i64>().ok());
                    storage
                        .db()
                        .update_message_disappearing_from_ns(self.group_id.clone(), parsed_value)?
                }
                field_name if field_name == MetadataField::MessageDisappearInNS.as_str() => {
                    let parsed_value = change
                        .new_value
                        .as_deref()
                        .and_then(|v| v.parse::<i64>().ok());
                    storage
                        .db()
                        .update_message_disappearing_in_ns(self.group_id.clone(), parsed_value)?
                }
                _ => {} // Handle other metadata updates if needed
            }
        }

        Ok(())
    }

    /// Advance the per-originator cursor if this message is newer than durable state.
    #[tracing::instrument(skip_all, level = "trace")]
    pub(super) fn maybe_update_cursor(
        &self,
        db: &impl DbQuery,
        message: &xmtp_proto::types::GroupMessage,
    ) -> Result<bool, StorageError> {
        let updated = db.update_cursor(&message.group_id, message.entity_kind(), message.cursor)?;
        if updated {
            log_event!(
                Event::GroupCursorUpdate,
                self.context.installation_id(),
                group_id = message.group_id.as_slice(),
                cursor = message.cursor.sequence_id,
                originator = message.cursor.originator_id
            );
        } else {
            tracing::debug!("no cursor update required");
        }
        Ok(updated)
    }

    /// Persist the derived `GroupUpdated` transcript row for a validated commit.
    ///
    /// This is intentionally the point where commit metadata is mirrored and
    /// DM-stitch dedupe is checked, because both decisions depend on the fully
    /// validated commit payload rather than raw MLS bytes.
    pub(super) fn save_transcript_message(
        &self,
        validated_commit: ValidatedCommit,
        timestamp_ns: u64,
        cursor: Cursor,
        storage: &impl XmtpMlsStorageProvider,
    ) -> Result<Option<(StoredGroupMessage, GroupUpdated)>, GroupMessageProcessingError> {
        if validated_commit.is_empty() {
            return Ok(None);
        }
        let sender_installation_id = validated_commit.actor_installation_id();
        let sender_inbox_id = validated_commit.actor_inbox_id();

        let pending_remove_users = &storage
            .db()
            .get_pending_remove_users(self.group_id.as_slice())?;
        let payload: GroupUpdated = validated_commit.into_with(pending_remove_users);
        tracing::info!("Storing transcript message");
        let encoded_payload = GroupUpdatedCodec::encode(payload.clone())?;
        let mut encoded_payload_bytes = Vec::new();
        encoded_payload.encode(&mut encoded_payload_bytes)?;

        let message_id = calculate_message_id(
            &self.group_id,
            encoded_payload_bytes.as_slice(),
            &timestamp_ns.to_string(),
        );
        let content_type = encoded_payload.r#type.unwrap_or_else(|| {
            tracing::warn!("Missing content type in encoded payload, using default values");
            xmtp_proto::xmtp::mls::message_contents::ContentTypeId {
                authority_id: "unknown".to_string(),
                type_id: "unknown".to_string(),
                version_major: 0,
                version_minor: 0,
            }
        });

        self.apply_commit_metadata_mirror(&payload, storage)?;

        // When a DM is stitched, it can repeat group updates. We want to prevent saving those messages.
        if self.update_already_exists(&payload, storage)? {
            return Ok(None);
        }

        let msg = StoredGroupMessage {
            id: message_id,
            group_id: self.group_id.clone(),
            decrypted_message_bytes: encoded_payload_bytes,
            sent_at_ns: timestamp_ns as i64,
            kind: GroupMessageKind::MembershipChange,
            sender_installation_id,
            sender_inbox_id,
            delivery_status: DeliveryStatus::Published,
            content_type: content_type.type_id.into(),
            version_major: content_type.version_major as i32,
            version_minor: content_type.version_minor as i32,
            authority_id: content_type.authority_id.to_string(),
            reference_id: None,
            sequence_id: cursor.sequence_id as i64,
            originator_id: cursor.originator_id as i64,
            expire_at_ns: None,
            inserted_at_ns: 0,
            should_push: true,
        };

        msg.store_or_ignore(&storage.db())?;
        Ok(Some((msg, payload)))
    }

    /// Persist a fully decoded external application message.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn persist_external_application_message(
        &self,
        decrypted_message_bytes: Vec<u8>,
        envelope_timestamp_ns: i64,
        cursor: Cursor,
        sender_installation_id: &[u8],
        sender_inbox_id: &str,
        content_type: QueryableContentFields,
        message_id: Vec<u8>,
        expire_at_ns: Option<i64>,
        storage: &impl XmtpMlsStorageProvider,
    ) -> Result<StoredGroupMessage, GroupMessageProcessingError> {
        let message = StoredGroupMessage {
            id: message_id,
            group_id: self.group_id.clone(),
            decrypted_message_bytes,
            sent_at_ns: envelope_timestamp_ns,
            kind: GroupMessageKind::Application,
            sender_installation_id: sender_installation_id.to_vec(),
            sender_inbox_id: sender_inbox_id.to_string(),
            delivery_status: DeliveryStatus::Published,
            content_type: content_type.content_type,
            version_major: content_type.version_major,
            version_minor: content_type.version_minor,
            authority_id: content_type.authority_id,
            reference_id: content_type.reference_id,
            sequence_id: cursor.sequence_id as i64,
            originator_id: cursor.originator_id as i64,
            expire_at_ns,
            inserted_at_ns: 0,
            should_push: true,
        };
        message.store_or_ignore(&storage.db())?;
        Ok(message)
    }

    /// Apply local mirrors that must survive even when transcript dedupe wins.
    fn apply_commit_metadata_mirror(
        &self,
        payload: &GroupUpdated,
        storage: &impl XmtpMlsStorageProvider,
    ) -> Result<(), StorageError> {
        // TXN-EDGE: mirrored metadata updates + transcript persistence - co-location convenience
        //
        // Metadata mirrors are derived from the validated commit itself and must still be
        // applied even when DM stitching later dedupes the transcript message.
        self.handle_metadata_update_from_commit(&payload.metadata_field_changes, storage)
    }

    /// Finalize the durable side effects of an applied staged commit.
    ///
    /// Transcript persistence, pending-remove cleanup, and super-admin updates
    /// all derive from the same validated commit and need to stay in lockstep.
    pub(super) fn finalize_applied_staged_commit(
        &self,
        mls_group: &OpenMlsGroup,
        validated_commit: &ValidatedCommit,
        timestamp_ns: u64,
        cursor: Cursor,
        storage: &impl XmtpMlsStorageProvider,
    ) -> Result<Option<(StoredGroupMessage, GroupUpdated)>, GroupMessageProcessingError> {
        Self::mark_readd_requests_as_responded(
            storage,
            &self.group_id,
            &validated_commit.readded_installations,
            cursor.sequence_id as i64,
        )?;

        let transcript =
            self.save_transcript_message(validated_commit.clone(), timestamp_ns, cursor, storage)?;

        // remove left/removed members from the pending_remove list
        self.clean_pending_remove_list(storage, &validated_commit.removed_inboxes);

        // Handle super_admin status changes for the current user
        // If promoted: check for pending remove members and mark group accordingly
        // If demoted: clear the pending leave request status
        self.handle_super_admin_status_change(
            storage,
            mls_group,
            &validated_commit.metadata_validation_info,
        );

        Ok(transcript)
    }

    /// Mark a locally-authored application message as durably published.
    pub(super) fn finalize_published_own_application_message(
        &self,
        mls_group: &OpenMlsGroup,
        message_id: &[u8],
        envelope_timestamp_ns: i64,
        cursor: Cursor,
        storage: &impl XmtpMlsStorageProvider,
    ) -> Result<(), GroupMessageProcessingError> {
        let message_expire_at_ns = Self::get_message_expire_at_ns(mls_group);
        storage.db().set_delivery_status_to_published(
            &message_id,
            envelope_timestamp_ns as u64,
            cursor,
            message_expire_at_ns,
        )?;
        self.process_own_leave_request_message(mls_group, storage, message_id);
        self.process_own_delete_message(storage, message_id);
        Ok(())
    }

    /// Check whether a stitched DM has already materialized an equivalent update.
    pub(super) fn update_already_exists(
        &self,
        payload: &GroupUpdated,
        storage: &impl XmtpMlsStorageProvider,
    ) -> Result<bool, GroupMessageProcessingError> {
        if self.dm_id.is_none() || payload.added_inboxes.is_empty() {
            return Ok(false);
        }

        let mut deduper = GroupUpdateDeduper::default();
        let mut inserted_after_ns = None;
        let mut msgs;
        loop {
            msgs = self.find_messages_v2_with_conn(
                &MsgQueryArgs {
                    content_types: Some(vec![ContentType::GroupUpdated]),
                    inserted_after_ns,
                    limit: Some(100),
                    ..Default::default()
                },
                storage.db(),
            )?;

            let Some(msg) = msgs.last() else {
                break;
            };
            inserted_after_ns = Some(msg.metadata.inserted_at_ns);

            for msg in msgs {
                let MessageBody::GroupUpdated(update) = msg.content else {
                    continue;
                };

                deduper.consume(&update);
            }
        }

        Ok(deduper.is_dupe(payload))
    }

    /// Escalate epoch-validation failures into fork detection only for forward jumps.
    pub(super) async fn process_group_message_error_for_fork_detection(
        &self,
        message_cursor: u64,
        message_epoch: GroupEpoch,
        error: &GroupMessageProcessingError,
        mls_group: &OpenMlsGroup,
    ) -> Result<(), GroupMessageProcessingError> {
        if !matches!(
            error,
            OpenMlsProcessMessage(ProcessMessageError::ValidationError(
                ValidationError::WrongEpoch,
            ))
        ) {
            return Ok(());
        }

        let group_epoch = mls_group.epoch().as_u64();
        let epoch_validation_result = Self::validate_message_epoch(
            self.context.inbox_id(),
            0,
            GroupEpoch::from(group_epoch),
            message_epoch,
            MAX_PAST_EPOCHS,
        );

        if let Err(GroupMessageProcessingError::FutureEpoch(_, _)) = &epoch_validation_result {
            mark_probable_fork(
                &self.context,
                &self.group_id,
                message_cursor,
                message_epoch,
                group_epoch,
                error,
            )?;
            return epoch_validation_result;
        }

        Ok(())
    }
}
