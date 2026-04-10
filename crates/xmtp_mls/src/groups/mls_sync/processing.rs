use super::*;
use crate::groups::check_proposals_enabled;
use crate::groups::validated_commit::CommitValidationContext;
use crate::identity_updates::IdentityStateContext;
use xmtp_proto::types::{Cursor, InstallationId};

async fn validate_staged_commit<Context>(
    context: &Context,
    staged_commit: &StagedCommit,
    mls_group: &OpenMlsGroup,
) -> Result<ValidatedCommit, CommitValidationError>
where
    Context: CommitValidationContext + Clone,
{
    ValidatedCommit::from_staged_commit(context.clone(), staged_commit, mls_group).await
}

fn validate_external_proposal_message(
    mls_group: &OpenMlsGroup,
    queued_proposal: &openmls::group::QueuedProposal,
) -> Result<(), CommitValidationError> {
    let proposal_type = queued_proposal.proposal().proposal_type();
    if !check_proposals_enabled(mls_group.extensions())
        && proposal_type != ProposalType::GroupContextExtensions
    {
        return Err(CommitValidationError::ProposalsNotEnabled);
    }

    let extensions = mls_group.extensions();
    let policy_set = extract_group_permissions(mls_group)?;
    let immutable_metadata = extract_group_metadata(extensions)?;
    let mutable_metadata = extract_group_mutable_metadata(mls_group)?;

    validate_proposal(
        queued_proposal,
        mls_group,
        &policy_set.policies,
        &immutable_metadata,
        &mutable_metadata,
    )?;

    Ok(())
}

async fn validate_staged_commit_for_intent<Context>(
    context: &Context,
    local_inbox_id: InboxIdRef<'_>,
    local_installation_id: InstallationId,
    group_id: &[u8],
    cursor: &Cursor,
    intent: &StoredGroupIntent,
    staged_commit: &StagedCommit,
    mls_group: &OpenMlsGroup,
    envelope_timestamp_ns: i64,
) -> Result<ValidatedCommit, IntentResolutionError>
where
    Context: CommitValidationContext + Clone,
{
    tracing::info!(
        "[{}] Validating commit for intent {}. Message timestamp: ({})",
        local_inbox_id,
        intent.id,
        envelope_timestamp_ns,
    );

    let maybe_validated_commit = validate_staged_commit(context, staged_commit, mls_group).await;

    match maybe_validated_commit {
        Err(err) => {
            tracing::error!(
                inbox_id = local_inbox_id,
                installation_id = %local_installation_id,
                group_id = hex::encode(group_id),
                cursor = %cursor,
                intent.id,
                intent.kind = %intent.kind,
                "Error validating commit for own message. Intent ID [{}]: {err:?}",
                intent.id,
            );
            Err(IntentResolutionError {
                processing_error: GroupMessageProcessingError::CommitValidation(err),
                next_intent_state: IntentState::Error,
            })
        }
        Ok(validated_commit) => Ok(validated_commit),
    }
}

impl<Context> MlsGroup<Context>
where
    Context: XmtpSharedContext,
{
    fn process_own_message_transaction<Provider>(
        &self,
        provider: &Provider,
        mls_group: &mut OpenMlsGroup,
        intent: &StoredGroupIntent,
        validation_result: Result<Option<(StagedCommit, ValidatedCommit)>, IntentResolutionError>,
        identifier: &mut MessageIdentifierBuilder,
        envelope: &GroupMessage,
        allow_cursor_increment: bool,
    ) -> Result<(), GroupMessageProcessingError>
    where
        Provider: MlsProviderExt,
    {
        let storage = provider.key_store();
        let db = storage.db();
        let cursor = envelope.cursor;
        let intent_id = intent.id;

        // TXN-EDGE: cursor advancement + intent state transition + MLS apply/store writes - unresolved
        let requires_processing = if allow_cursor_increment {
            self.maybe_update_cursor(&db, envelope)?
        } else {
            tracing::info!(
                "will not call update cursor for group {}, with cursor {}, allow_cursor_increment is false",
                hex::encode(envelope.group_id.as_slice()),
                cursor
            );
            let current_cursor = db.get_last_cursor_for_originator(
                &envelope.group_id,
                envelope.entity_kind(),
                envelope.originator_id(),
            )?;
            current_cursor.sequence_id < envelope.sequence_id()
        };
        if !requires_processing {
            tracing::debug!(
                "message @cursor=[{}] for group=[{}] created_at=[{}] no longer require processing, should be available in database",
                envelope.cursor,
                xmtp_common::fmt::debug_hex(&envelope.group_id),
                envelope.created_ns
            );

            // early return if the message is already processed
            // _NOTE_: Not early returning and re-processing a message that
            // has already been processed, has the potential to result in forks.
            // In some cases, we may want to roll back the cursor if we updated the
            // cursor, but actually cannot process the message.
            identifier.previously_processed(true);
            return Ok(());
        }
        let result: Result<Option<Vec<u8>>, IntentResolutionError> = match validation_result {
            Err(err) => Err(err),
            Ok(validated_intent) => {
                self.process_own_message(mls_group, validated_intent, intent, envelope, storage)
            }
        };
        let (next_intent_state, internal_message_id) = match result {
            Err(err) => {
                if err.processing_error.is_retryable() {
                    // Rollback the transaction so that we can retry
                    return Err(err.processing_error);
                }
                if envelope.is_commit()
                    && let Err(accounting_error) = mls_group.mark_failed_commit_logged(
                        provider,
                        cursor.sequence_id,
                        envelope.message.epoch(),
                        &err.processing_error,
                    )
                {
                    tracing::error!(
                        "Error inserting commit entry for failed self commit: {}",
                        accounting_error
                    );
                }
                (err.next_intent_state, None)
            }
            Ok(internal_message_id) => (IntentState::Committed, internal_message_id),
        };
        identifier.internal_id(internal_message_id.clone());

        if next_intent_state == intent.state {
            tracing::warn!(
                "Intent [{}] is already in state [{:?}]",
                intent_id,
                next_intent_state
            );
            return Ok(());
        }
        match next_intent_state {
            IntentState::ToPublish => {
                db.set_group_intent_to_publish(intent_id)?;
            }
            IntentState::Committed => {
                self.handle_metadata_update_from_intent(intent, storage)?;
                db.set_group_intent_committed(intent_id, cursor)?;
            }
            IntentState::Published => {
                tracing::error!(
                    "Unexpected behaviour: returned intent state published from process_own_message"
                );
            }
            IntentState::Error => {
                tracing::error!("Intent [{}] moved to error status", intent_id);
                db.set_group_intent_error(intent_id)?;
            }
            IntentState::Processed => {
                tracing::debug!("Intent [{}] moved to Processed status", intent_id);
                db.set_group_intent_processed(intent_id)?;
            }
        }
        Ok(())
    }

    /// This function is idempotent. No need to wrap in a transaction.
    ///
    /// # Parameters
    /// * `envelope` - The message envelope to process
    /// * `trust_message_order` - Controls whether to allow epoch increments from commits and msg cursor increments.
    ///   Set to `true` when processing messages from trusted ordered sources (queries), and `false` when
    ///   processing from potentially out-of-order sources like streams.
    #[cfg_attr(
        any(test, feature = "test-utils"),
        tracing::instrument(level = "info", skip(self), fields(envelope = %envelope))
    )]
    #[cfg_attr(
        not(any(test, feature = "test-utils")),
        tracing::instrument(level = "trace", skip_all)
    )]
    pub(crate) async fn process_message(
        &self,
        envelope: &GroupMessage,
        trust_message_order: bool,
    ) -> Result<MessageIdentifier, GroupMessageProcessingError> {
        if trust_message_order {
            let last_cursor = self.context.db().get_last_cursor_for_originator(
                &envelope.group_id,
                envelope.entity_kind(),
                envelope.originator_id(),
            )?;
            tracing::info!("last cursor of processed = {}", last_cursor);
            if last_cursor.sequence_id >= envelope.sequence_id() {
                tracing::info!(
                    inbox_id = self.context.inbox_id(),
                    installation_id = %self.context.installation_id(),
                    group_id = hex::encode(&envelope.group_id),
                    "Message already processed: skipped cursor:[{}] last cursor in db: [{}]",
                    envelope.cursor,
                    last_cursor
                );
                // early return if the message is already processed
                // _NOTE_: Not early returning and re-processing a message that
                // has already been processed, has the potential to result in forks.
                return MessageIdentifierBuilder::from(envelope).build();
            }
        }

        self.load_mls_group_with_lock_async(async |mut mls_group| {
            // ensure we are processing a private message
            match &envelope.message {
                ProtocolMessage::PrivateMessage(_) => (),
                other => {
                    return Err(GroupMessageProcessingError::UnsupportedMessageType(
                        discriminant(other),
                    ));
                }
            };
            let mut result = self
                .process_message_inner(&mut mls_group, envelope, trust_message_order)
                .await;
            if trust_message_order {
                result = self
                    .post_process_message(&mls_group, result, envelope)
                    .await;
            }
            result
        })
        .await
    }

    #[tracing::instrument(skip(self, mls_group, envelope), level = "trace")]
    async fn process_message_inner(
        &self,
        mls_group: &mut OpenMlsGroup,
        envelope: &GroupMessage,
        trust_message_order: bool,
    ) -> Result<MessageIdentifier, GroupMessageProcessingError> {
        let db = self.context.db();
        let allow_epoch_increment = trust_message_order;
        let allow_cursor_increment = trust_message_order;
        if !allow_epoch_increment && envelope.is_commit() {
            return Err(GroupMessageProcessingError::EpochIncrementNotAllowed);
        }

        let intent = db
            .find_group_intent_by_payload_hash(envelope.payload_hash.as_slice())
            .map_err(GroupMessageProcessingError::Storage)?;

        let group_cursor = db.get_last_cursor_for_originator(
            &self.group_id,
            envelope.entity_kind(),
            envelope.originator_id(),
        )?;
        if group_cursor.sequence_id >= envelope.sequence_id() {
            // early return if the message is already processed
            // _NOTE_: Not early returning and re-processing a message that
            // has already been processed, has the potential to result in forks.
            return MessageIdentifierBuilder::from(envelope)
                .previously_processed(true)
                .build();
        }

        tracing::info!(
            inbox_id = self.context.inbox_id(),
            installation_id = %self.context.installation_id(),
            group_id = hex::encode(&self.group_id),
            cursor = %envelope.cursor,
            "Processing envelope with hash {}, cursor = {}, is_own_intent={}",
            hex::encode(&envelope.payload_hash),
            envelope.cursor,
            intent.is_some()
        );
        match intent {
            // Intent with the payload hash matches
            Some(intent) => {
                let mut identifier = MessageIdentifierBuilder::from(envelope);
                identifier.intent_kind(intent.kind);
                let intent_id = intent.id;
                tracing::info!(
                    inbox_id = self.context.inbox_id(),
                    installation_id = %self.context.installation_id(),
                    group_id = hex::encode(&self.group_id),
                    cursor = %envelope.cursor,
                    intent_id,
                    intent.kind = %intent.kind,
                    "client [{}] is about to process own envelope [{}] for intent [{}] [{}]",
                    self.context.inbox_id(),
                    envelope.cursor,
                    intent_id,
                    intent.kind
                );

                let validation_result = self
                    .stage_and_validate_intent(mls_group, &intent, envelope)
                    .await;

                self.context.mls_storage().transaction(|conn| {
                    let key_store = conn.key_store();
                    let provider = XmtpOpenMlsProviderRef::new(&key_store);
                    self.process_own_message_transaction(
                        &provider,
                        mls_group,
                        &intent,
                        validation_result,
                        &mut identifier,
                        envelope,
                        allow_cursor_increment,
                    )
                })?;
                identifier.build()
            }
            // No matching intent found. The message did not originate here.
            None => {
                tracing::info!(
                    inbox_id = self.context.inbox_id(),
                    installation_id = %self.context.installation_id(),
                    group_id = hex::encode(&self.group_id),
                    cursor = %envelope.cursor,
                    "client [{}] is about to process external envelope [{}]",
                    self.context.inbox_id(),
                    envelope.cursor
                );
                let identifier = self
                    .validate_and_process_external_message(
                        mls_group,
                        envelope,
                        allow_cursor_increment,
                    )
                    .await?;
                Ok(identifier)
            }
        }
    }

    pub(super) fn validate_message_epoch(
        inbox_id: InboxIdRef<'_>,
        intent_id: i32,
        group_epoch: GroupEpoch,
        message_epoch: GroupEpoch,
        max_past_epochs: usize,
    ) -> Result<(), GroupMessageProcessingError> {
        #[cfg(any(test, feature = "test-utils"))]
        utils::test_mocks_helpers::maybe_mock_future_epoch_for_tests()?;

        if message_epoch.as_u64() + max_past_epochs as u64 <= group_epoch.as_u64() {
            tracing::warn!(
                inbox_id,
                message_epoch = message_epoch.as_u64(),
                group_epoch = group_epoch.as_u64(),
                intent_id,
                "[{}] message epoch {} is {} or more less than the group epoch {} for intent {}. Retrying message",
                inbox_id,
                message_epoch,
                max_past_epochs,
                group_epoch.as_u64(),
                intent_id
            );
            return Err(GroupMessageProcessingError::OldEpoch(
                message_epoch.as_u64(),
                group_epoch.as_u64(),
            ));
        } else if message_epoch.as_u64() > group_epoch.as_u64() {
            // Should not happen, logging proactively
            tracing::error!(
                inbox_id,
                message_epoch = message_epoch.as_u64(),
                group_epoch = group_epoch.as_u64(),
                intent_id,
                "[{}] message epoch {} is greater than group epoch {} for intent {}. Retrying message",
                inbox_id,
                message_epoch,
                group_epoch,
                intent_id
            );
            return Err(GroupMessageProcessingError::FutureEpoch(
                message_epoch.as_u64(),
                group_epoch.as_u64(),
            ));
        }
        Ok(())
    }

    // This function is intended to isolate the async validation code to
    // validate the message and prepare it for database insertion synchronously.
    pub(super) async fn stage_and_validate_intent(
        &self,
        mls_group: &openmls::group::MlsGroup,
        intent: &StoredGroupIntent,
        envelope: &GroupMessage,
    ) -> Result<Option<(StagedCommit, ValidatedCommit)>, IntentResolutionError> {
        let GroupMessage {
            message, cursor, ..
        } = &envelope;
        let group_epoch = mls_group.epoch();
        let message_epoch = message.epoch();

        match intent.kind {
            // GCE proposal phase of CommitPendingProposals: no staged_commit means the
            // message coming back is our GCE proposal, not a commit. Validate epoch only.
            IntentKind::CommitPendingProposals if intent.staged_commit.is_none() => {
                Self::validate_message_epoch(
                    self.context.inbox_id(),
                    intent.id,
                    group_epoch,
                    message_epoch,
                    MAX_PAST_EPOCHS,
                )
                .map_err(|err| IntentResolutionError {
                    processing_error: err,
                    next_intent_state: IntentState::ToPublish,
                })?;
            }

            IntentKind::KeyUpdate
            | IntentKind::UpdateGroupMembership
            | IntentKind::UpdateAdminList
            | IntentKind::MetadataUpdate
            | IntentKind::UpdatePermission
            | IntentKind::ReaddInstallations
            | IntentKind::CommitPendingProposals => {
                if let Some(published_in_epoch) = intent.published_in_epoch {
                    let group_epoch = group_epoch.as_u64() as i64;
                    let message_epoch = message_epoch.as_u64() as i64;

                    // TODO(rich): Merge into validate_message_epoch()
                    if message_epoch != group_epoch {
                        tracing::warn!(
                            inbox_id = self.context.inbox_id(),
                            installation_id = %self.context.installation_id(),
                            group_id = hex::encode(&self.group_id),
                            cursor = %cursor,
                            intent.id,
                            intent.kind = %intent.kind,
                            "Intent for msg = [{cursor}] was published in epoch {} with local save intent epoch of {} but group is currently in epoch {}",
                            message_epoch,
                            published_in_epoch,
                            group_epoch
                        );
                        let processing_error = if message_epoch < group_epoch {
                            GroupMessageProcessingError::OldEpoch(
                                message_epoch as u64,
                                group_epoch as u64,
                            )
                        } else {
                            GroupMessageProcessingError::FutureEpoch(
                                message_epoch as u64,
                                group_epoch as u64,
                            )
                        };

                        return Err(IntentResolutionError {
                            processing_error,
                            next_intent_state: IntentState::ToPublish,
                        });
                    }

                    let staged_commit = intent
                        .staged_commit
                        .as_ref()
                        .map_or(
                            Err(GroupMessageProcessingError::IntentMissingStagedCommit),
                            |staged_commit| decode_staged_commit(staged_commit),
                        )
                        .map_err(|err| {
                            // If we can't retrieve the cached staged commit from the intent, we can't
                            // apply it. It is indeterminate whether other members were able to apply it
                            // or not - if they did apply it, then we are forked.
                            tracing::error!(
                                inbox_id = self.context.inbox_id(),
                                installation_id = %self.context.installation_id(),
                                group_id = hex::encode(&self.group_id),
                                cursor = %cursor,
                                intent_id = intent.id,
                                intent.kind = %intent.kind,
                                "Error decoding staged commit for intent, now may be forked: {err:?}",
                            );
                            IntentResolutionError {
                                processing_error: err,
                                next_intent_state: IntentState::Error,
                            }
                        })?;

                    let validated_commit = validate_staged_commit_for_intent(
                        &self.context,
                        self.context.inbox_id(),
                        IdentityStateContext::installation_id(&self.context),
                        &self.group_id,
                        cursor,
                        intent,
                        &staged_commit,
                        mls_group,
                        envelope.timestamp(),
                    )
                    .await;
                    let validated_commit = validated_commit?;

                    return Ok(Some((staged_commit, validated_commit)));
                }
            }

            IntentKind::SendMessage
            | IntentKind::ProposeMemberUpdate
            | IntentKind::ProposeGroupContextExtensions => {
                // Proposals and messages don't produce commits, just validate epoch
                Self::validate_message_epoch(
                    self.context.inbox_id(),
                    intent.id,
                    group_epoch,
                    message_epoch,
                    MAX_PAST_EPOCHS,
                )
                .map_err(|err| IntentResolutionError {
                    processing_error: err,
                    next_intent_state: IntentState::ToPublish,
                })?;
            }
        }

        Ok(None)
    }

    // Applies the message/commit to the mls group. If it was successfully applied, return Ok(()),
    // so that the caller can mark the intent as committed.
    // If any error occurs, return an IntentResolutionError with the error, and the next intent state
    // to use in the event the error is non-retriable.
    #[allow(clippy::too_many_arguments)]
    #[tracing::instrument(level = "trace", skip_all)]
    pub(super) fn process_own_message(
        &self,
        mls_group: &mut OpenMlsGroup,
        commit: Option<(StagedCommit, ValidatedCommit)>,
        intent: &StoredGroupIntent,
        envelope: &GroupMessage,
        storage: &impl XmtpMlsStorageProvider,
    ) -> Result<Option<Vec<u8>>, IntentResolutionError> {
        if intent.state == IntentState::Committed
            || intent.state == IntentState::Processed
            || intent.state == IntentState::Error
        {
            tracing::warn!(
                "Skipping already processed intent {} of kind {} because it is in state {:?}",
                intent.id,
                intent.kind,
                intent.state
            );
            return Err(IntentResolutionError {
                processing_error: GroupMessageProcessingError::IntentAlreadyProcessed,
                next_intent_state: intent.state,
            });
        }

        // GCE proposal phase of CommitPendingProposals: the GCE proposal was received back
        // from the network. Re-queue the intent to create the actual commit in the next sync.
        if intent.kind == IntentKind::CommitPendingProposals && commit.is_none() {
            tracing::info!(
                "CommitPendingProposals: GCE proposal received back, re-queuing to create commit"
            );
            return Err(IntentResolutionError {
                processing_error: GroupMessageProcessingError::PreCommitProposalPhaseComplete,
                next_intent_state: IntentState::ToPublish,
            });
        }

        let message_epoch = envelope.message.epoch();
        let GroupMessage { cursor, .. } = envelope;
        let envelope_timestamp_ns = envelope.timestamp();

        tracing::debug!(
            inbox_id = self.context.inbox_id(),
            installation_id = %self.context.installation_id(),
            group_id = hex::encode(&self.group_id),
            cursor = %cursor,
            intent.id,
            intent.kind = %intent.kind,
            "[{}]-[{}] processing own message for intent {} / {}, message_epoch: {}",
            self.context.inbox_id(),
            hex::encode(self.group_id.clone()),
            intent.id,
            intent.kind,
            message_epoch.clone()
        );

        if let Some((staged_commit, validated_commit)) = commit {
            tracing::info!(
                "[{}] merging pending commit for intent {}",
                self.context.inbox_id(),
                intent.id
            );

            if let Err(err) = mls_group.merge_staged_commit_logged(
                &XmtpOpenMlsProviderRef::new(storage),
                staged_commit,
                &validated_commit,
                cursor.sequence_id as i64,
            ) {
                tracing::error!("error merging commit: {err}");
                return Err(IntentResolutionError {
                    processing_error: err,
                    // If the error is non-retriable, it means the commit failed to apply due to some
                    // issue with the commit (e.g. encryption problem). We reset the intent state to
                    // ToPublish so that we can republish it.
                    next_intent_state: IntentState::ToPublish,
                });
            }
            Self::mark_readd_requests_as_responded(
                storage,
                &self.group_id,
                &validated_commit.readded_installations,
                cursor.sequence_id as i64,
            )
            .map_err(|err| IntentResolutionError {
                processing_error: err.into(),
                next_intent_state: IntentState::Error,
            })?;

            // If no error committing the change, write a transcript message
            let msg = self
                .save_transcript_message(
                    validated_commit.clone(),
                    envelope_timestamp_ns as u64,
                    *cursor,
                    storage,
                )
                .map_err(|err| IntentResolutionError {
                    processing_error: err,
                    // If it is a non-retriable error, the commit will be applied, but the transcript message
                    // will be missing. We mark the intent state as errored and continue.
                    next_intent_state: IntentState::Error,
                })?;

            // Clean up pending_remove list for removed members
            self.clean_pending_remove_list(storage, &validated_commit.removed_inboxes);

            // Handle super_admin status changes
            self.handle_super_admin_status_change(
                storage,
                mls_group,
                &validated_commit.metadata_validation_info,
            );

            if let Some((_, payload)) = &msg {
                log_event!(
                    Event::MLSProcessedStagedCommit,
                    self.context.installation_id(),
                    group_id = self.group_id,
                    epoch = mls_group.epoch().as_u64(),
                    epoch_auth = mls_group.epoch_authenticator().as_slice(),
                    actor_installation_id = validated_commit.actor.installation_id,
                    added_inboxes = $payload.added_inboxes,
                    removed_inboxes = $payload.removed_inboxes,
                    left_inboxes = $payload.left_inboxes,
                    metadata_changes = $payload.metadata_field_changes,
                    cursor = cursor.sequence_id,
                    originator = cursor.originator_id
                );
            }

            return Ok(msg.map(|(m, _)| m.id));
        }

        let id: Option<Vec<u8>> = calculate_message_id_for_intent(intent)
            .map_err(GroupMessageProcessingError::Intent)
            .map_err(|err| {
                if !err.is_retryable() {
                    tracing::error!(
                        "Message identifier not found for intent {} with kind {}, {err:?}",
                        intent.id,
                        intent.kind
                    );
                }
                IntentResolutionError {
                    processing_error: err,
                    // If the error is non-retriable, it means that the optimistic message (which is already in
                    // the db) will never have its delivery status updated to published. We mark the intent state
                    // as errored and continue.
                    next_intent_state: IntentState::Error,
                }
            })?;
        let Some(id) = id else {
            // The message is likely to be a legacy envelope, probably from legacy device sync.
            // We don't need to set the delivery status for these.
            return Ok(None);
        };
        tracing::debug!("setting message @cursor=[{}] to published", envelope.cursor);
        let message_expire_at_ns = Self::get_message_expire_at_ns(mls_group);
        storage
            .db()
            .set_delivery_status_to_published(
                &id,
                envelope_timestamp_ns as u64,
                envelope.cursor,
                message_expire_at_ns,
            )
            .map_err(|err| IntentResolutionError {
                processing_error: GroupMessageProcessingError::Db(err),
                next_intent_state: IntentState::Error,
            })?;
        self.process_own_leave_request_message(mls_group, storage, &id);
        self.process_own_delete_message(storage, &id);
        Ok(Some(id))
    }

    #[tracing::instrument(level = "trace", skip(mls_group, envelope))]
    pub(super) async fn validate_and_process_external_message(
        &self,
        mls_group: &mut OpenMlsGroup,
        envelope: &GroupMessage,
        allow_cursor_increment: bool,
    ) -> Result<MessageIdentifier, GroupMessageProcessingError> {
        #[cfg(any(test, feature = "test-utils"))]
        {
            use crate::utils::test_mocks_helpers::maybe_mock_wrong_epoch_for_tests;
            maybe_mock_wrong_epoch_for_tests()?;
        }

        let provider = self.context.mls_provider();

        let GroupMessage {
            cursor, message, ..
        } = envelope;
        let envelope_timestamp_ns = envelope.timestamp();
        let mut identifier = MessageIdentifierBuilder::from(envelope);

        // We need to process the message twice to avoid an async transaction.
        // We'll process for the first time, get the processed message,
        // and roll the transaction back, so we can fetch updates from the server before
        // being ready to process the message for a second time.
        let mut processed_message = None;
        // TXN-EDGE: external message preflight + forced MLS reload - unresolved (intentional rollback before durable apply)
        let result = provider.key_store().transaction(|conn| {
            let storage = conn.key_store();
            let provider = XmtpOpenMlsProvider::new(storage);
            processed_message = Some(mls_group.process_message(&provider, message.clone()));
            // Rollback the transaction. We want to synchronize with the server before committing.
            Err::<(), StorageError>(StorageError::IntentionalRollback)
        });
        if !matches!(result, Err(StorageError::IntentionalRollback)) {
            result.inspect_err(|e| tracing::debug!("immutable process message failed {}", e))?;
        }
        let processed_message = processed_message.expect("Was just set to Some")?;

        // Reload the mlsgroup to clear the it's internal cache
        mls_group.reload(provider.storage())?;

        let (sender_inbox_id, sender_installation_id) =
            extract_message_sender(mls_group, &processed_message, envelope_timestamp_ns as u64)?;

        tracing::info!(
            inbox_id = self.context.inbox_id(),
            installation_id = %self.context.installation_id(),sender_inbox_id = sender_inbox_id,
            sender_installation_id = hex::encode(&sender_installation_id),
            group_id = hex::encode(&self.group_id),
            current_epoch = mls_group.epoch().as_u64(),
            msg_epoch = processed_message.epoch().as_u64(),
            msg_group_id = hex::encode(processed_message.group_id().as_slice()),
            cursor = %cursor,
            "[{}] extracted sender inbox id: {}",
            self.context.inbox_id(),
            sender_inbox_id
        );

        let validated_commit = match &processed_message.content() {
            ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                let result = validate_staged_commit(&self.context, staged_commit, mls_group).await;

                let validated_commit = match result {
                    Err(e) if !e.is_retryable() => {
                        match &e {
                            CommitValidationError::ProtocolVersionTooLow(_) => {}
                            _ => {
                                self.maybe_update_cursor(&self.context.db(), envelope)?;
                            }
                        };

                        Err(e)
                    }
                    v => v,
                }?;

                identifier.group_context(staged_commit.group_context().clone());
                Some(validated_commit)
            }
            ProcessedMessageContent::ProposalMessage(queued_proposal) => {
                // Reject Add/Remove proposals if proposals are not enabled on this group.
                // GCE proposals are exempt because enable_proposals() uses them to bootstrap
                // proposal support — they must be allowed through to flip the flag on.
                let proposal_type = queued_proposal.proposal().proposal_type();
                if let Err(e) = validate_external_proposal_message(mls_group, queued_proposal) {
                    match &e {
                        CommitValidationError::ProposalsNotEnabled => {
                            tracing::warn!(
                                inbox_id = self.context.inbox_id(),
                                group_id = hex::encode(&self.group_id),
                                ?proposal_type,
                                "Received proposal but proposals are not enabled on this group"
                            );
                        }
                        _ => {
                            tracing::warn!(
                                inbox_id = self.context.inbox_id(),
                                installation_id = %self.context.installation_id(),
                                group_id = hex::encode(&self.group_id),
                                proposal_type = ?proposal_type,
                                error = %e,
                                "Received invalid proposal, rejecting"
                            );
                        }
                    }

                    // Update cursor so we don't reprocess this invalid proposal
                    self.maybe_update_cursor(&self.context.db(), envelope)?;
                    return Err(e.into());
                }

                None
            }
            _ => None,
        };

        let mut deferred_events = DeferredEvents::new();
        // TXN-EDGE: cursor advancement + MLS message apply + transcript/event persistence - unresolved
        let identifier = provider.key_store().transaction(|conn| {
            let storage = conn.key_store();
            let db = storage.db();
            let provider = XmtpOpenMlsProviderRef::new(&storage);
            tracing::debug!(
                inbox_id = self.context.inbox_id(),
                installation_id = %self.context.installation_id(),
                group_id = hex::encode(&self.group_id),
                current_epoch = mls_group.epoch().as_u64(),
                msg_epoch = processed_message.epoch().as_u64(),
                cursor = ?cursor,
                "[{}] processing message in transaction epoch = {}, cursor = {:?}",
                self.context.inbox_id(),
                mls_group.epoch().as_u64(),
                cursor
            );
            let requires_processing = if allow_cursor_increment {
                self.maybe_update_cursor(&db, envelope)?
            } else {
                tracing::info!(
                    "will not call update cursor for group {}, with cursor {}, allow_cursor_increment is false",
                    hex::encode(envelope.group_id.as_slice()),
                    *cursor
                );
                let current_cursor = db.get_last_cursor_for_originator(
                    &envelope.group_id,
                    envelope.entity_kind(),
                    envelope.originator_id(),
                )?;
                current_cursor.sequence_id < envelope.cursor.sequence_id
            };
            if !requires_processing {
                // early return if the message is already processed
                // _NOTE_: Not early returning and re-processing a message that
                // has already been processed, has the potential to result in forks.
                tracing::debug!(
                    "message @cursor=[{}] for group=[{}] created_at=[{}] no longer require processing, should be available in database",
                    envelope.cursor,
                    xmtp_common::fmt::debug_hex(&envelope.group_id),
                    envelope.created_ns
                );
                identifier.previously_processed(true);
                return identifier.build();
            }
            // once the checks for processing pass, actually process the message
            let processed_message = mls_group.process_message(&provider, message.clone())?;
            let identifier = self.process_external_message(
                mls_group,
                processed_message,
                envelope,
                validated_commit.clone(),
                &storage,
                &mut deferred_events,
            )?;
            Ok::<_, GroupMessageProcessingError>(identifier)
        })?;

        // Send all deferred events after the transaction completes
        deferred_events.send_all(&self.context);

        Ok(identifier)
    }

    /// Process an external message
    /// returns a MessageIdentifier, identifying the message processed if any.
    #[tracing::instrument(level = "trace", skip_all)]
    pub(super) fn process_external_message(
        &self,
        mls_group: &mut OpenMlsGroup,
        processed_message: ProcessedMessage,
        message_envelope: &GroupMessage,
        validated_commit: Option<ValidatedCommit>,
        storage: &impl XmtpMlsStorageProvider,
        deferred_events: &mut DeferredEvents,
    ) -> Result<MessageIdentifier, GroupMessageProcessingError> {
        let GroupMessage { cursor, .. } = &message_envelope;
        let envelope_timestamp_ns = message_envelope.timestamp();
        let msg_epoch = processed_message.epoch().as_u64();
        let msg_group_id = processed_message.group_id().as_slice().to_vec();
        let (sender_inbox_id, sender_installation_id) =
            extract_message_sender(mls_group, &processed_message, envelope_timestamp_ns as u64)?;

        let mut identifier = MessageIdentifierBuilder::from(message_envelope);
        match processed_message.into_content() {
            ProcessedMessageContent::ApplicationMessage(application_message) => {
                log_event!(
                    Event::MLSReceivedApplicationMessage,
                    self.context.installation_id(),
                    inbox_id = self.context.inbox_id(),
                    sender_inbox_id,
                    sender_installation_id,
                    group_id = self.group_id,
                    epoch = mls_group.epoch().as_u64(),
                    msg_epoch,
                    msg_group_id,
                    cursor = %cursor,
                );
                let message_bytes = application_message.into_bytes();

                let mut bytes = Bytes::from(message_bytes);
                let envelope = PlaintextEnvelope::decode(&mut bytes)?;

                match envelope.content {
                    Some(Content::V1(V1 {
                        idempotency_key,
                        content,
                    })) => {
                        let message_id =
                            calculate_message_id(&self.group_id, &content, &idempotency_key);
                        let queryable_content_fields =
                            Self::extract_queryable_content_fields(&content);

                        let message = StoredGroupMessage {
                            id: message_id.clone(),
                            group_id: self.group_id.clone(),
                            decrypted_message_bytes: content,
                            sent_at_ns: envelope_timestamp_ns,
                            kind: GroupMessageKind::Application,
                            sender_installation_id,
                            sender_inbox_id: sender_inbox_id.clone(),
                            delivery_status: DeliveryStatus::Published,
                            content_type: queryable_content_fields.content_type,
                            version_major: queryable_content_fields.version_major,
                            version_minor: queryable_content_fields.version_minor,
                            authority_id: queryable_content_fields.authority_id,
                            reference_id: queryable_content_fields.reference_id,
                            sequence_id: cursor.sequence_id as i64,
                            originator_id: cursor.originator_id as i64,
                            expire_at_ns: Self::get_message_expire_at_ns(mls_group),
                            inserted_at_ns: 0, // Will be set by database
                            should_push: true,
                        };
                        message.store_or_ignore(&storage.db())?;
                        identifier.internal_id(message_id);

                        // If this message was sent by us on another installation, check if it
                        // belongs to a sync group, and if it is - notify the worker.
                        if sender_inbox_id == self.context.inbox_id() {
                            tracing::info!(
                                installation_id = hex::encode(self.context.installation_id()),
                                "new sync group message event"
                            );
                            if let Some(StoredGroup {
                                conversation_type: ConversationType::Sync,
                                ..
                            }) = storage.db().find_group(&self.group_id)?
                            {
                                // Send this event after the transaction completes
                                deferred_events.add_worker_event(SyncWorkerEvent::NewSyncGroupMsg);
                            }
                        }
                        if message.content_type == ContentType::LeaveRequest {
                            self.process_leave_request_message(mls_group, storage, &message)?;
                        }

                        if message.content_type == ContentType::DeleteMessage {
                            self.process_delete_message(mls_group, storage, &message)?;
                        }

                        Ok::<_, GroupMessageProcessingError>(())
                    }
                    Some(Content::V2(V2 { .. })) => {
                        // V2 was used for DeviceSync V1, which is now removed.
                        // Device Sync V2 reverted back to using V1 envelopes.
                        Ok::<_, GroupMessageProcessingError>(())
                    }
                    None => Err(GroupMessageProcessingError::InvalidPayload),
                }
            }
            ProcessedMessageContent::ProposalMessage(proposal_ptr) => {
                tracing::debug!(
                    inbox_id = self.context.inbox_id(),
                    installation_id = %self.context.installation_id(),
                    group_id = hex::encode(&self.group_id),
                    proposal_type = ?proposal_ptr.proposal().proposal_type(),
                    "Received and storing proposal in proposal store"
                );
                // Explicitly persist the proposal to the key store so it survives group reloads.
                // process_message() only stores proposals in-memory; without this call,
                // they are lost when the group is reloaded from storage.
                mls_group.store_pending_proposal(storage, *proposal_ptr)?;
                Ok(())
            }
            ProcessedMessageContent::ExternalJoinProposalMessage(_external_proposal_ptr) => {
                Ok(())
                // intentionally left blank.
            }
            ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                let staged_commit = *staged_commit;
                let validated_commit =
                    validated_commit.expect("Needs to be present when this is a staged commit");

                log_event!(
                    Event::MLSReceivedStagedCommit,
                    self.context.installation_id(),
                    inbox_id = self.context.inbox_id(),
                    sender_inbox = sender_inbox_id,
                    sender_installation_id,
                    group_id = self.group_id,
                    epoch = mls_group.epoch().as_u64(),
                    msg_epoch,
                    msg_group_id,
                    cursor = %cursor,
                    hash = #message_envelope.payload_hash
                );

                identifier.group_context(staged_commit.group_context().clone());

                mls_group.merge_staged_commit_logged(
                    &XmtpOpenMlsProviderRef::new(storage),
                    staged_commit,
                    &validated_commit,
                    cursor.sequence_id as i64,
                )?;

                Self::mark_readd_requests_as_responded(
                    storage,
                    &self.group_id,
                    &validated_commit.readded_installations,
                    cursor.sequence_id as i64,
                )?;

                let transcript = self.save_transcript_message(
                    validated_commit.clone(),
                    envelope_timestamp_ns as u64,
                    *cursor,
                    storage,
                )?;

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

                if let Some((msg, payload)) = transcript {
                    identifier.internal_id(msg.id);

                    log_event!(
                        Event::MLSProcessedStagedCommit,
                        self.context.installation_id(),
                        group_id = self.group_id,
                        epoch = mls_group.epoch().as_u64(),
                        epoch_auth = mls_group.epoch_authenticator().as_slice(),
                        actor_installation_id = validated_commit.actor.installation_id,
                        added_inboxes = $payload.added_inboxes,
                        removed_inboxes = $payload.removed_inboxes,
                        left_inboxes = $payload.left_inboxes,
                        metadata_changes = $payload.metadata_field_changes,
                        cursor = cursor.sequence_id,
                        originator = cursor.originator_id
                    );
                }

                Ok(())
            }
        }?;
        identifier.build()
    }

    fn get_message_expire_at_ns(mls_group: &OpenMlsGroup) -> Option<i64> {
        let mutable_metadata = extract_group_mutable_metadata(mls_group).ok()?;
        let group_disappearing_settings =
            Self::conversation_message_disappearing_settings_from_extensions(&mutable_metadata)
                .ok()?;

        if group_disappearing_settings.is_enabled() {
            Some(now_ns() + group_disappearing_settings.in_ns)
        } else {
            None
        }
    }
}
