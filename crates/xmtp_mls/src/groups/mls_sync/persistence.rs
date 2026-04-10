use super::*;

impl<Context> MlsGroup<Context>
where
    Context: XmtpSharedContext,
{
    /// In case of metadataUpdate will extract the updated fields and store them to the db
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

        // TXN-EDGE: mirrored metadata updates + transcript persistence - unresolved
        self.handle_metadata_update_from_commit(&payload.metadata_field_changes, storage)?;

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
            let fork_details = format!(
                "Message cursor [{}] epoch [{}] is greater than group epoch [{}], your group may be forked",
                message_cursor, message_epoch, group_epoch
            );
            tracing::error!(
                inbox_id = self.context.inbox_id(),
                installation_id = %self.context.installation_id(),
                group_id = hex::encode(&self.group_id),
                original_error = error.to_string(),
                fork_details
            );
            let _ = self
                .context
                .db()
                .mark_group_as_maybe_forked(&self.group_id, fork_details);
            return epoch_validation_result;
        }

        Ok(())
    }
}
