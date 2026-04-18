//! Local-intent publishing and staged-commit capture.
//!
//! Publishing is where local intent state becomes network-visible work. The
//! helpers here keep staged commit snapshots and payload hashes aligned so the
//! later receive path can recognize its own messages deterministically.

use super::*;
use crate::groups::group_membership::GroupMembership;
use crate::identity_updates::{IdentityStateContext, load_identity_updates};
use openmls_traits::signatures::Signer;

/// Build publish payloads for a group-context extension update without persisting the commit yet.
fn build_group_context_extensions_publish_data<S, SignerT>(
    storage: &S,
    openmls_group: &mut OpenMlsGroup,
    extensions: Extensions<GroupContext>,
    signer: SignerT,
    should_send_push_notification: bool,
) -> Result<PublishIntentData, GroupError>
where
    S: XmtpMlsStorageProvider,
    SignerT: Signer,
{
    let ((commit, _, _), staged_commit, group_epoch) =
        generate_commit_with_rollback(storage, openmls_group, |group, provider| {
            group.update_group_context_extensions(provider, extensions.clone(), &signer)
        })?;

    Ok(PublishIntentData {
        payloads_to_publish: vec![commit.tls_serialize_detached()?],
        staged_commit,
        post_commit_action: None,
        should_send_push_notification,
        group_epoch,
    })
}

/// Refresh membership sequence ids before generating publish payloads that depend on them.
async fn refresh_membership_sequence_ids<Context>(
    context: &Context,
    membership: &mut GroupMembership,
    inbox_ids: &[String],
) -> Result<(), GroupError>
where
    Context: IdentityStateContext,
{
    if inbox_ids.is_empty() {
        return Ok(());
    }

    let inbox_ids_refs: Vec<&str> = inbox_ids.iter().map(|inbox_id| inbox_id.as_str()).collect();
    load_identity_updates(context.api(), &context.db(), &inbox_ids_refs).await?;
    let latest_sequence_ids = context.db().get_latest_sequence_id(&inbox_ids_refs)?;

    for inbox_id in inbox_ids {
        let sequence_id = latest_sequence_ids
            .get(inbox_id.as_str())
            .copied()
            .ok_or(GroupError::MissingSequenceId)?;
        membership.add(inbox_id.clone(), sequence_id as u64);
    }

    Ok(())
}

impl<Context> MlsGroup<Context>
where
    Context: XmtpSharedContext,
{
    /// Publish every locally pending intent in durable order.
    ///
    /// Each intent is marked `Published` before transport send so the receive
    /// path can correlate the returning payload with the staged commit snapshot.
    #[tracing::instrument]
    pub(in crate::groups) async fn publish_intents(&self) -> Result<(), GroupError> {
        let db = self.context.db();
        self.load_mls_group_with_lock_async(async |mut mls_group| {
            let intents = db.find_group_intents(
                self.group_id.clone(),
                Some(vec![IntentState::ToPublish]),
                None,
            )?;

            for intent in intents {
                let result = retry_async!(
                    Retry::default(),
                    (async {
                        self.get_publish_intent_data(&mut mls_group, &intent).await
                    })
                );

                match result {
                    Err(err) => {
                        tracing::error!(error = %err, "error getting publish intent data {:?}", err);
                        if (intent.publish_attempts + 1) as usize >= MAX_INTENT_PUBLISH_ATTEMPTS {
                            tracing::error!(
                                intent.id,
                                intent.kind = %intent.kind,
                                inbox_id = self.context.inbox_id(),
                                installation_id = %self.context.installation_id(),group_id = hex::encode(&self.group_id),
                                "intent {} has reached max publish attempts", intent.id);
                            // TODO: Eventually clean up errored attempts
                            let id = utils::id::calculate_message_id_for_intent(&intent)?;
                            db.set_group_intent_error_and_fail_msg(&intent, id)?;
                        } else {
                            db.increment_intent_publish_attempt_count(intent.id)?;
                        }

                        return Err(err);
                    }
                    Ok(Some(PublishIntentData {
                        payloads_to_publish,
                        post_commit_action,
                        staged_commit,
                        should_send_push_notification,
                        group_epoch,
                    })) => {
                        // Hash the last payload for intent matching. For single-payload intents
                        // this is the only payload. For multi-payload intents (ProposeMemberUpdate),
                        // hashing the last payload ensures all preceding payloads have been received
                        // before the intent resolves. Because the proposals go through the blockchain.
                        let has_staged_commit = staged_commit.is_some();
                        let last_payload = payloads_to_publish
                            .last()
                            .ok_or(GroupError::UninitializedResult)?;
                        let intent_hash = sha256(last_payload);
                        // TXN-EDGE: intent published state + staged MLS commit snapshot — protocol-required
                        // removing this transaction causes missed messages
                        self.context.mls_storage().transaction(|conn| {
                            let storage = conn.key_store();
                            let db = storage.db();
                            db.set_group_intent_published(
                                intent.id,
                                &intent_hash,
                                post_commit_action,
                                staged_commit,
                                group_epoch as i64,
                            )
                        })?;
                        tracing::debug!(
                            inbox_id = self.context.inbox_id(),
                            installation_id = %self.context.installation_id(),
                            intent.id,
                            intent.kind = %intent.kind,
                            group_id = hex::encode(&self.group_id),
                            "[{}] set stored intent [{}] with hash [{}] to state `published`",
                            self.context.inbox_id(),
                            intent.id,
                            hex::encode(&intent_hash)
                        );

                        // Prepare messages for all payloads
                        let payload_pairs: Vec<_> = payloads_to_publish
                            .iter()
                            .map(|p| (p.as_slice(), should_send_push_notification))
                            .collect();
                        let messages = self.prepare_group_messages(payload_pairs)?;
                        let result = self.context.api().send_group_messages(messages).await;

                        match (intent.kind, result) {
                            (IntentKind::SendMessage, Ok(_)) => {
                                log_event!(
                                    Event::GroupSyncApplicationMessagePublishSuccess,
                                    self.context.installation_id(),
                                    group_id = intent.group_id,
                                    intent_id = intent.id
                                );
                            }
                            (kind, Err(err)) => {
                                log_event!(
                                    Event::GroupSyncPublishFailed,
                                    self.context.installation_id(),
                                    group_id = intent.group_id,
                                    intent_id = intent.id,
                                    intent_kind = ?kind,
                                    err = ?err
                                );

                                handle_published_intent_send_failure(
                                    &db,
                                    &intent,
                                    err.is_retryable(),
                                )?;
                                return Err(err)?;
                            }
                            (kind, Ok(_)) => {
                                log_event!(
                                    Event::GroupSyncCommitPublishSuccess,
                                    self.context.installation_id(),
                                    group_id = intent.group_id,
                                    intent_id = intent.id,
                                    intent_kind = ?kind,
                                    commit_hash = hex::encode(&intent_hash)
                                )
                            }
                        }

                        if has_staged_commit {
                            log_event!(
                                Event::GroupSyncStagedCommitPresent,
                                self.context.installation_id(),
                                group_id = intent.group_id,
                                hash = #intent_hash
                            );
                            return Ok(());
                        }
                    }
                    Ok(None) => {
                        tracing::info!(
                            inbox_id = self.context.inbox_id(),
                            installation_id = %self.context.installation_id(),
                            "Skipping intent because no publish data returned"
                        );
                        db.set_group_intent_processed(intent.id)?
                    }
                }
            }

            Ok(())
        })
        .await
    }

    /// Derive the payloads and staged side effects for one pending intent.
    ///
    /// Returning `None` means the intent is already a no-op against current
    /// state and can be marked processed without publishing network traffic.
    #[allow(clippy::type_complexity)]
    #[tracing::instrument(level = "trace", skip_all)]
    async fn get_publish_intent_data(
        &self,
        openmls_group: &mut OpenMlsGroup,
        intent: &StoredGroupIntent,
    ) -> Result<Option<PublishIntentData>, GroupError> {
        let storage = self.context.mls_storage();
        match intent.kind {
            IntentKind::UpdateGroupMembership => {
                let intent_data =
                    UpdateGroupMembershipIntentData::try_from(intent.data.as_slice())?;
                let signer = &self.context.identity().installation_keys;
                apply_update_group_membership_intent(
                    &self.context,
                    openmls_group,
                    intent_data,
                    signer,
                )
                .await
            }
            IntentKind::SendMessage => {
                let intent_data = SendMessageIntentData::from_bytes(intent.data.as_slice())?;
                let group_epoch = openmls_group.epoch().as_u64();
                let msg = openmls_group.create_message(
                    &self.context.mls_provider(),
                    &self.context.identity().installation_keys,
                    intent_data.message.as_slice(),
                )?;

                Ok(Some(PublishIntentData {
                    payloads_to_publish: vec![msg.tls_serialize_detached()?],
                    post_commit_action: None,
                    staged_commit: None,
                    should_send_push_notification: intent.should_push,
                    group_epoch,
                }))
            }
            IntentKind::KeyUpdate => {
                let keys = self.context.identity().installation_keys.clone();
                let (bundle, staged_commit, group_epoch) =
                    generate_commit_with_rollback(storage, openmls_group, |group, provider| {
                        group.self_update(provider, &keys, LeafNodeParameters::default())
                    })?;
                Ok(Some(PublishIntentData {
                    payloads_to_publish: vec![bundle.commit().tls_serialize_detached()?],
                    staged_commit,
                    post_commit_action: None,
                    should_send_push_notification: intent.should_push,
                    group_epoch,
                }))
            }
            IntentKind::MetadataUpdate => {
                let metadata_intent = UpdateMetadataIntentData::try_from(intent.data.clone())?;
                let mutable_metadata_extensions = build_extensions_for_metadata_update(
                    openmls_group,
                    metadata_intent.field_name,
                    metadata_intent.field_value,
                )?;

                let keys = self.context.identity().installation_keys.clone();
                Ok(Some(build_group_context_extensions_publish_data(
                    storage,
                    openmls_group,
                    mutable_metadata_extensions,
                    keys,
                    intent.should_push,
                )?))
            }
            IntentKind::UpdateAdminList => {
                let admin_list_update_intent =
                    UpdateAdminListIntentData::try_from(intent.data.clone())?;
                let mutable_metadata_extensions = build_extensions_for_admin_lists_update(
                    openmls_group,
                    admin_list_update_intent,
                )?;

                let keys = self.context.identity().installation_keys.clone();
                Ok(Some(build_group_context_extensions_publish_data(
                    storage,
                    openmls_group,
                    mutable_metadata_extensions,
                    keys,
                    intent.should_push,
                )?))
            }
            IntentKind::UpdatePermission => {
                let update_permissions_intent =
                    UpdatePermissionIntentData::try_from(intent.data.clone())?;
                let group_permissions_extensions = build_extensions_for_permissions_update(
                    openmls_group,
                    update_permissions_intent,
                )?;

                let keys = self.context.identity().installation_keys.clone();
                Ok(Some(build_group_context_extensions_publish_data(
                    storage,
                    openmls_group,
                    group_permissions_extensions,
                    keys,
                    intent.should_push,
                )?))
            }
            IntentKind::ReaddInstallations => {
                let intent_data = ReaddInstallationsIntentData::try_from(intent.data.as_slice())?;
                let signer = &self.context.identity().installation_keys;
                apply_readd_installations_intent(&self.context, openmls_group, intent_data, signer)
                    .await
            }
            IntentKind::ProposeMemberUpdate => {
                if !self.proposals_enabled(openmls_group) {
                    return Err(GroupError::from(CommitValidationError::ProposalsNotEnabled));
                }

                let intent_data = ProposeMemberUpdateIntentData::try_from(intent.data.as_slice())?;
                let group_epoch = openmls_group.epoch().as_u64();
                let signer = &self.context.identity().installation_keys;
                let mut proposal_payloads = Vec::new();

                if !intent_data.add_inbox_ids.is_empty() {
                    let extensions: Extensions<GroupContext> = openmls_group.extensions().clone();
                    let old_group_membership = extract_group_membership(&extensions)?;

                    let mut new_membership = old_group_membership.clone();
                    refresh_membership_sequence_ids(
                        &self.context,
                        &mut new_membership,
                        &intent_data.add_inbox_ids,
                    )
                    .await?;

                    let changes_with_kps = calculate_membership_changes_with_keypackages(
                        &self.context,
                        &self.group_id,
                        &new_membership,
                        &old_group_membership,
                    )
                    .await?;

                    if !changes_with_kps.failed_installations.is_empty()
                        && changes_with_kps.new_key_packages.is_empty()
                    {
                        return Err(GroupError::FailedToVerifyInstallations);
                    }

                    for key_package in &changes_with_kps.new_key_packages {
                        let (proposal_msg, _proposal_ref) = openmls_group
                            .propose_add_member(&self.context.mls_provider(), signer, key_package)
                            .map_err(GroupError::ProposeAddMember)?;
                        proposal_payloads.push(proposal_msg.tls_serialize_detached()?);
                    }
                }

                if !intent_data.remove_inbox_ids.is_empty() {
                    let inbox_ids_to_remove: HashSet<_> =
                        intent_data.remove_inbox_ids.iter().cloned().collect();
                    let mut members_to_remove = Vec::new();
                    for member in openmls_group.members() {
                        let credential = BasicCredential::try_from(member.credential.clone())?;
                        let member_inbox_id = parse_credential(credential.identity())?;
                        if inbox_ids_to_remove.contains(&member_inbox_id) {
                            members_to_remove.push(member.index);
                        }
                    }

                    for member_index in members_to_remove {
                        let (proposal_msg, _proposal_ref) = openmls_group
                            .propose_remove_member(
                                &self.context.mls_provider(),
                                signer,
                                member_index,
                            )
                            .map_err(GroupError::ProposeRemoveMember)?;
                        proposal_payloads.push(proposal_msg.tls_serialize_detached()?);
                    }
                }

                if proposal_payloads.is_empty() {
                    tracing::debug!(
                        inbox_id = self.context.inbox_id(),
                        group_id = hex::encode(&self.group_id),
                        add_inbox_ids = ?intent_data.add_inbox_ids,
                        remove_inbox_ids = ?intent_data.remove_inbox_ids,
                        "ProposeMemberUpdate produced no proposals (members may already be in desired state)"
                    );
                    return Ok(None);
                }

                Ok(Some(PublishIntentData {
                    payloads_to_publish: proposal_payloads,
                    staged_commit: None,
                    post_commit_action: None,
                    should_send_push_notification: intent.should_push,
                    group_epoch,
                }))
            }
            IntentKind::ProposeGroupContextExtensions => {
                use openmls::prelude::tls_codec::Deserialize;

                let intent_data =
                    ProposeGroupContextExtensionsIntentData::try_from(intent.data.as_slice())?;
                let group_epoch = openmls_group.epoch().as_u64();
                let extensions =
                    Extensions::tls_deserialize(&mut intent_data.extensions_bytes.as_slice())?;

                let signer = &self.context.identity().installation_keys;
                let (proposal_msg, _proposal_ref) = openmls_group
                    .propose_group_context_extensions(
                        &self.context.mls_provider(),
                        extensions,
                        signer,
                    )
                    .map_err(GroupError::Proposal)?;

                Ok(Some(PublishIntentData {
                    payloads_to_publish: vec![proposal_msg.tls_serialize_detached()?],
                    staged_commit: None,
                    post_commit_action: None,
                    should_send_push_notification: intent.should_push,
                    group_epoch,
                }))
            }
            IntentKind::CommitPendingProposals => {
                use xmtp_id::key_package::VerifiedKeyPackageV2;

                let _intent_data =
                    CommitPendingProposalsIntentData::try_from(intent.data.as_slice())?;

                if openmls_group.pending_proposals().next().is_none() {
                    tracing::debug!("No pending proposals to commit");
                    return Ok(None);
                }

                let signer = &self.context.identity().installation_keys;
                let current_extensions: Extensions<GroupContext> =
                    openmls_group.extensions().clone();
                let current_membership = extract_group_membership(&current_extensions)?;

                let mut inbox_ids_to_add: Vec<String> = Vec::new();
                let mut inbox_ids_to_remove: Vec<String> = Vec::new();
                let mut installations_to_welcome: Vec<Installation> = Vec::new();
                let mut key_packages_to_add: Vec<openmls::key_packages::KeyPackage> = Vec::new();

                for proposal_ref in openmls_group.pending_proposals() {
                    match proposal_ref.proposal() {
                        Proposal::Add(add_proposal) => {
                            let key_package = add_proposal.key_package();
                            let credential = BasicCredential::try_from(
                                key_package.leaf_node().credential().clone(),
                            )?;
                            let inbox_id = parse_credential(credential.identity())?;
                            if !inbox_ids_to_add.contains(&inbox_id)
                                && current_membership.get(&inbox_id).is_none()
                            {
                                inbox_ids_to_add.push(inbox_id);
                                key_packages_to_add.push(key_package.clone());

                                if let Ok(verified_kp) =
                                    VerifiedKeyPackageV2::try_from(key_package.clone())
                                    && let Ok(installation) =
                                        Installation::from_verified_key_package(&verified_kp)
                                {
                                    installations_to_welcome.push(installation);
                                }
                            }
                        }
                        Proposal::Remove(remove_proposal) => {
                            if let Some(member) = openmls_group.member_at(remove_proposal.removed())
                            {
                                let credential = BasicCredential::try_from(member.credential)?;
                                let inbox_id = parse_credential(credential.identity())?;
                                if !inbox_ids_to_remove.contains(&inbox_id) {
                                    inbox_ids_to_remove.push(inbox_id);
                                }
                            }
                        }
                        _ => {}
                    }
                }

                let mut new_membership = current_membership.clone();

                if !inbox_ids_to_add.is_empty() {
                    refresh_membership_sequence_ids(
                        &self.context,
                        &mut new_membership,
                        &inbox_ids_to_add,
                    )
                    .await?;
                }

                for inbox_id in &inbox_ids_to_remove {
                    new_membership.remove(inbox_id);
                }

                if !inbox_ids_to_add.is_empty() {
                    let changes_with_kps = calculate_membership_changes_with_keypackages(
                        &self.context,
                        &self.group_id,
                        &new_membership,
                        &current_membership,
                    )
                    .await?;

                    new_membership.failed_installations = changes_with_kps.failed_installations;
                }

                let membership_changed =
                    !inbox_ids_to_add.is_empty() || !inbox_ids_to_remove.is_empty();

                let has_pending_gce_with_membership = membership_changed
                    && openmls_group.pending_proposals().any(|p| {
                        if let Proposal::GroupContextExtensions(gce) = p.proposal() {
                            extract_group_membership(gce.extensions())
                                .map(|m| m.members == new_membership.members)
                                .unwrap_or(false)
                        } else {
                            false
                        }
                    });

                if membership_changed && !has_pending_gce_with_membership {
                    let base_extensions = openmls_group
                        .pending_proposals()
                        .find_map(|p| {
                            if let Proposal::GroupContextExtensions(gce) = p.proposal() {
                                Some(gce.extensions().clone())
                            } else {
                                None
                            }
                        })
                        .unwrap_or_else(|| openmls_group.extensions().clone());

                    let mut new_extensions = base_extensions;
                    new_extensions
                        .add_or_replace(build_group_membership_extension(&new_membership))?;

                    let proposals_currently_enabled = self.proposals_enabled(openmls_group);
                    if proposals_currently_enabled && !key_packages_to_add.is_empty() {
                        let new_members_support_proposals = self
                            .validate_key_packages_support_proposals(&key_packages_to_add)
                            .is_ok();

                        if !new_members_support_proposals {
                            tracing::info!(
                                "Disabling proposals: new members don't support proposal extension"
                            );
                            new_extensions
                                .remove(ExtensionType::Unknown(PROPOSAL_SUPPORT_EXTENSION_ID));
                            update_required_capabilities_for_proposals(&mut new_extensions, false)?;
                        }
                    }

                    let new_membership_for_filter = new_membership.clone();
                    let signer = self.context.identity().installation_keys.clone();
                    let ((gce_payload, bundle), staged_commit, group_epoch) =
                        generate_commit_with_rollback(
                            storage,
                            openmls_group,
                            |group, provider| -> Result<_, GroupError> {
                                let (gce_msg, _) = group
                                    .propose_group_context_extensions(
                                        provider,
                                        new_extensions.clone(),
                                        &signer,
                                    )
                                    .map_err(GroupError::Proposal)?;
                                let gce_payload = gce_msg.tls_serialize_detached()?;

                                let bundle = group
                                    .commit_builder()
                                    .consume_proposal_store(true)
                                    .load_psks(provider.storage())
                                    .map_err(CommitToPendingProposalsError::from)?
                                    .build(provider.rand(), provider.crypto(), &signer, |qp| {
                                        match qp.proposal() {
                                            Proposal::GroupContextExtensions(gce) => {
                                                extract_group_membership(gce.extensions())
                                                    .map(|m| {
                                                        m.members
                                                            == new_membership_for_filter.members
                                                    })
                                                    .unwrap_or(false)
                                            }
                                            _ => true,
                                        }
                                    })
                                    .map_err(CommitToPendingProposalsError::from)?
                                    .stage_commit(provider)
                                    .map_err(CommitToPendingProposalsError::from)?;

                                Ok((gce_payload, bundle))
                            },
                        )?;

                    let (commit, maybe_welcome, _group_info) = bundle.into_messages();
                    let staged_commit =
                        staged_commit.ok_or_else(|| GroupError::MissingPendingCommit)?;

                    let post_commit_action = match maybe_welcome {
                        Some(welcome_message) => Some(PostCommitAction::from_welcome(
                            welcome_message,
                            installations_to_welcome,
                        )?),
                        None => None,
                    };

                    Ok(Some(PublishIntentData {
                        payloads_to_publish: vec![gce_payload, commit.tls_serialize_detached()?],
                        staged_commit: Some(staged_commit),
                        post_commit_action: post_commit_action.map(|action| action.to_bytes()),
                        should_send_push_notification: intent.should_push,
                        group_epoch,
                    }))
                } else {
                    let new_membership_for_filter = new_membership.clone();
                    let (bundle, staged_commit, group_epoch) = generate_commit_with_rollback(
                        storage,
                        openmls_group,
                        |group,
                         provider|
                         -> Result<
                            _,
                            CommitToPendingProposalsError<sql_key_store::SqlKeyStoreError>,
                        > {
                            Ok(group
                                .commit_builder()
                                .consume_proposal_store(true)
                                .load_psks(provider.storage())?
                                .build(provider.rand(), provider.crypto(), signer, |qp| {
                                    match qp.proposal() {
                                        Proposal::GroupContextExtensions(gce) => {
                                            if !membership_changed {
                                                return true;
                                            }
                                            extract_group_membership(gce.extensions())
                                                .map(|m| {
                                                    m.members == new_membership_for_filter.members
                                                })
                                                .unwrap_or(false)
                                        }
                                        _ => true,
                                    }
                                })?
                                .stage_commit(provider)?)
                        },
                    )?;
                    let (commit, maybe_welcome, _group_info) = bundle.into_messages();
                    let staged_commit =
                        staged_commit.ok_or_else(|| GroupError::MissingPendingCommit)?;
                    let post_commit_action = match maybe_welcome {
                        Some(welcome_message) => Some(PostCommitAction::from_welcome(
                            welcome_message,
                            installations_to_welcome,
                        )?),
                        None => None,
                    };

                    Ok(Some(PublishIntentData {
                        payloads_to_publish: vec![commit.tls_serialize_detached()?],
                        staged_commit: Some(staged_commit),
                        post_commit_action: post_commit_action.map(|action| action.to_bytes()),
                        should_send_push_notification: intent.should_push,
                        group_epoch,
                    }))
                }
            }
        }
    }

    #[tracing::instrument(skip_all)]
    pub(crate) async fn post_commit(&self) -> Result<(), GroupError> {
        let db = self.context.db();
        let intents = db.find_group_intents(
            self.group_id.clone(),
            Some(vec![IntentState::Committed]),
            None,
        )?;

        for intent in intents {
            if let Some(post_commit_data) = intent.post_commit_data {
                tracing::debug!(
                    inbox_id = self.context.inbox_id(),
                    installation_id = %self.context.installation_id(),
                    intent.id,
                    intent.kind = %intent.kind,
                    "taking post commit action"
                );

                let post_commit_action = PostCommitAction::from_bytes(post_commit_data.as_slice())?;
                match post_commit_action {
                    PostCommitAction::SendWelcomes(action) => {
                        self.send_welcomes(action, intent.sequence_id).await?;
                    }
                }
            }
            db.set_group_intent_processed(intent.id)?
        }

        Ok(())
    }
}
