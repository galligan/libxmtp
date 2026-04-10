use super::{
    GroupError, HmacKey, MlsGroup, build_extensions_for_admin_lists_update,
    build_extensions_for_metadata_update, build_extensions_for_permissions_update,
    build_group_membership_extension,
    group_permissions::extract_group_permissions,
    intents::{
        CommitPendingProposalsIntentData, Installation, IntentError, PostCommitAction,
        ProposeGroupContextExtensionsIntentData, ProposeMemberUpdateIntentData,
        SendMessageIntentData, SendWelcomesAction, UpdateAdminListIntentData,
        UpdateGroupMembershipIntentData, UpdatePermissionIntentData,
    },
    summary::{MessageIdentifier, MessageIdentifierBuilder, ProcessSummary, SyncSummary},
    update_required_capabilities_for_proposals,
    validated_commit::{
        CommitValidationError, LibXMTPVersion, extract_group_membership, validate_proposal,
    },
};
use crate::{
    client::ClientError,
    context::XmtpSharedContext,
    groups::{
        group_membership::{GroupMembership, MembershipDiffWithKeyPackages},
        intents::{QueueIntent, ReaddInstallationsIntentData, UpdateMetadataIntentData},
        mls_ext::{CommitLogStorer, MlsGroupReload, WrapWelcomeError, wrap_welcome},
        mls_sync::{
            GroupMessageProcessingError::OpenMlsProcessMessage,
            update_group_membership::apply_readd_installations_intent,
        },
        validated_commit::{Inbox, MutableMetadataValidationInfo, ValidatedCommit},
    },
    identity::{IdentityError, parse_credential},
    identity_updates::{IdentityUpdates, load_identity_updates},
    intents::ProcessIntentError,
    messages::{decoded_message::MessageBody, enrichment::EnrichMessageError},
    mls_store::MlsStore,
    subscriptions::{LocalEvents, SyncWorkerEvent},
    traits::IntoWith,
    utils::{
        self,
        hash::sha256,
        id::{calculate_message_id, calculate_message_id_for_intent},
        time::hmac_epoch,
    },
};
use futures::future::try_join_all;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use openmls::prelude::BasicCredentialError;
use openmls::{
    credentials::BasicCredential,
    framing::ProtocolMessage,
    group::{
        CommitToPendingProposalsError, GroupContext, GroupEpoch, ProcessMessageError, StagedCommit,
        ValidationError,
    },
    key_packages::KeyPackage,
    messages::proposals::Proposal,
    prelude::{
        ExtensionType, Extensions, LeafNodeIndex, MlsGroup as OpenMlsGroup, ProcessedMessage,
        ProcessedMessageContent, ProposalType, Sender,
        tls_codec::{Error as TlsCodecError, Serialize},
    },
    treesync::LeafNodeParameters,
};
use openmls_traits::OpenMlsProvider;
use prost::Message;
use prost::bytes::Bytes;
use sha2::Sha256;
use std::{
    collections::{HashMap, HashSet},
    mem::{Discriminant, discriminant},
    ops::RangeInclusive,
    time::Duration,
};
use thiserror::Error;
use tracing::debug;
use update_group_membership::apply_update_group_membership_intent;
use xmtp_common::{
    Event, ExponentialBackoff, Retry, RetryableError, Strategy, log_event, retry_async,
    time::now_ns,
};
use xmtp_configuration::{
    GRPC_PAYLOAD_LIMIT, HMAC_SALT, MAX_GROUP_SIZE, MAX_GROUP_SYNC_RETRIES,
    MAX_INTENT_PUBLISH_ATTEMPTS, MAX_PAST_EPOCHS, PROPOSAL_SUPPORT_EXTENSION_ID,
    SYNC_BACKOFF_TOTAL_WAIT_MAX_SECS, SYNC_BACKOFF_WAIT_MS, SYNC_JITTER_MS,
    SYNC_UPDATE_INSTALLATIONS_INTERVAL_NS,
};
use xmtp_content_types::{CodecError, ContentCodec, group_updated::GroupUpdatedCodec};
use xmtp_db::message_deletion::{QueryMessageDeletion, StoredMessageDeletion};
use xmtp_db::{
    Fetch, MlsProviderExt, StorageError, StoreOrIgnore,
    group::{ConversationType, StoredGroup},
    group_intent::{ID, IntentKind, IntentState, StoredGroupIntent},
    group_message::{ContentType, DeliveryStatus, GroupMessageKind, StoredGroupMessage},
    remote_commit_log::CommitResult,
    sql_key_store,
    user_preferences::StoredUserPreferences,
};
use xmtp_db::{NotFound, group_intent::IntentKind::MetadataUpdate};
use xmtp_db::{TransactionalKeyStore, XmtpMlsStorageProvider, refresh_state::HasEntityKind};
use xmtp_db::{XmtpOpenMlsProvider, XmtpOpenMlsProviderRef, prelude::*};
use xmtp_db::{group::GroupMembershipState, group_message::Deletable};
use xmtp_db::{
    group_message::MsgQueryArgs,
    pending_remove::{PendingRemove, QueryPendingRemove},
};
use xmtp_id::{InboxId, InboxIdRef};
use xmtp_mls_common::group_metadata::extract_group_metadata;
use xmtp_mls_common::group_mutable_metadata::{MetadataField, extract_group_mutable_metadata};
use xmtp_proto::xmtp::mls::message_contents::content_types::DeleteMessage;
use xmtp_proto::xmtp::mls::{
    api::v1::{
        GroupMessageInput, WelcomeMessageInput, WelcomeMetadata,
        group_message_input::{V1 as GroupMessageInputV1, Version as GroupMessageInputVersion},
        welcome_message_input::{
            V1 as WelcomeMessageInputV1, Version as WelcomeMessageInputVersion,
            WelcomePointer as WelcomePointerInput,
        },
    },
    message_contents::{
        GroupUpdated, PlaintextEnvelope, WelcomePointer as WelcomePointerProto, group_updated,
        plaintext_envelope::{Content, V1, V2},
    },
};
use xmtp_proto::{
    GroupUpdateDeduper,
    types::{Cursor, GroupMessage},
};
use xmtp_proto::{ShortHex, xmtp::mls::message_contents::EncodedContent};
use zeroize::Zeroizing;

mod events;
mod helpers;
mod membership;
mod persistence;
mod processing;
mod publish;
mod receive;
mod removals;
pub mod update_group_membership;
mod welcomes;
pub(crate) use events::DeferredEvents;
pub(crate) use helpers::decode_staged_commit;
pub(super) use helpers::generate_commit_with_rollback;
use helpers::{
    extract_message_sender, handle_published_intent_send_failure,
};
use membership::calculate_membership_changes_with_keypackages;

#[derive(Debug, Error)]
pub enum GroupMessageProcessingError {
    #[error("intent already processed")]
    IntentAlreadyProcessed,
    #[error("message with cursor [{}] for group [{}] already processed", _0.cursor, xmtp_common::fmt::debug_hex(&_0.group_id)
    )]
    MessageAlreadyProcessed(MessageIdentifier),
    #[error("message identifier not found")]
    MessageIdentifierNotFound,
    #[error("welcome with cursor [{0}] already processed")]
    WelcomeAlreadyProcessed(u64),
    #[error("[{message_time_ns:?}] invalid sender with credential: {credential:?}")]
    InvalidSender {
        message_time_ns: u64,
        credential: Vec<u8>,
    },
    #[error("invalid payload")]
    InvalidPayload,
    #[error("storage error: {0}")]
    Storage(#[from] xmtp_db::StorageError),
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error("openmls process message error: {0}")]
    OpenMlsProcessMessage(
        #[from] openmls::prelude::ProcessMessageError<sql_key_store::SqlKeyStoreError>,
    ),
    #[error("merge staged commit: {0}")]
    MergeStagedCommit(#[from] openmls::group::MergeCommitError<sql_key_store::SqlKeyStoreError>),
    #[error("TLS Codec error: {0}")]
    TlsError(#[from] TlsCodecError),
    #[error("unsupported message type: {0:?}")]
    UnsupportedMessageType(Discriminant<ProtocolMessage>),
    #[error("commit validation")]
    CommitValidation(#[from] CommitValidationError),
    #[error("epoch increment not allowed")]
    EpochIncrementNotAllowed,
    #[error("clear pending commit error: {0}")]
    ClearPendingCommit(#[from] sql_key_store::SqlKeyStoreError),
    #[error("Serialization/Deserialization Error {0}")]
    Serde(#[from] serde_json::Error),
    #[error("intent is missing staged_commit field")]
    IntentMissingStagedCommit,
    #[error("encode proto: {0}")]
    EncodeProto(#[from] prost::EncodeError),
    #[error("proto decode error: {0}")]
    DecodeProto(#[from] prost::DecodeError),
    #[error(transparent)]
    Intent(#[from] IntentError),
    #[error(transparent)]
    Codec(#[from] CodecError),
    #[error("wrong credential type")]
    WrongCredentialType(#[from] BasicCredentialError),
    #[error(transparent)]
    ProcessIntent(#[from] ProcessIntentError),
    #[error(transparent)]
    AssociationDeserialization(#[from] xmtp_id::associations::DeserializationError),
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error("Group paused due to minimum protocol version requirement")]
    GroupPaused,
    #[error("Message epoch [{0}] is too old [{1}]")]
    OldEpoch(u64, u64),
    #[error("Message epoch [{0}] is greater than group epoch [{1}]")]
    FutureEpoch(u64, u64),
    #[error(transparent)]
    Db(#[from] xmtp_db::ConnectionError),
    #[error(transparent)]
    Builder(#[from] derive_builder::UninitializedFieldError),
    #[error(transparent)]
    Diesel(#[from] xmtp_db::diesel::result::Error),
    #[error(transparent)]
    EnrichMessage(#[from] EnrichMessageError),
    #[error("pre-commit proposal phase complete, re-queuing intent")]
    PreCommitProposalPhaseComplete,
}

impl RetryableError for GroupMessageProcessingError {
    fn is_retryable(&self) -> bool {
        match self {
            Self::Storage(err) => err.is_retryable(),
            Self::Diesel(err) => err.is_retryable(),
            Self::Identity(err) => err.is_retryable(),
            Self::OpenMlsProcessMessage(err) => err.is_retryable(),
            Self::MergeStagedCommit(err) => err.is_retryable(),
            Self::ProcessIntent(err) => err.is_retryable(),
            Self::CommitValidation(err) => err.is_retryable(),
            Self::ClearPendingCommit(err) => err.is_retryable(),
            Self::Client(err) => err.is_retryable(),
            Self::Db(e) => e.is_retryable(),
            Self::EnrichMessage(e) => e.is_retryable(),
            Self::IntentAlreadyProcessed
            | Self::MessageIdentifierNotFound
            | Self::WrongCredentialType(_)
            | Self::Codec(_)
            | Self::MessageAlreadyProcessed(_)
            | Self::WelcomeAlreadyProcessed(_)
            | Self::InvalidSender { .. }
            | Self::DecodeProto(_)
            | Self::InvalidPayload
            | Self::Intent(_)
            | Self::EpochIncrementNotAllowed
            | Self::EncodeProto(_)
            | Self::IntentMissingStagedCommit
            | Self::Serde(_)
            | Self::AssociationDeserialization(_)
            | Self::TlsError(_)
            | Self::UnsupportedMessageType(_)
            | Self::GroupPaused
            | Self::FutureEpoch(_, _)
            | Self::OldEpoch(_, _)
            | Self::PreCommitProposalPhaseComplete => false,
            Self::Builder(_) => false,
        }
    }
}

impl GroupMessageProcessingError {
    pub(crate) fn commit_result(&self) -> CommitResult {
        match self {
            GroupMessageProcessingError::OpenMlsProcessMessage(
                ProcessMessageError::ValidationError(ValidationError::WrongEpoch),
            ) => CommitResult::WrongEpoch,
            GroupMessageProcessingError::OldEpoch(_, _) => CommitResult::WrongEpoch,
            GroupMessageProcessingError::FutureEpoch(_, _) => CommitResult::WrongEpoch,
            GroupMessageProcessingError::CommitValidation(_) => CommitResult::Invalid,
            GroupMessageProcessingError::OpenMlsProcessMessage(_) => CommitResult::Undecryptable,
            _ => CommitResult::Unknown,
        }
    }
}

#[derive(Debug, Error)]
pub struct IntentResolutionError {
    processing_error: GroupMessageProcessingError,
    // The next intent state to transition to, if the error is non-retriable.
    // Should not be used for retryable errors.
    next_intent_state: IntentState,
}

impl std::fmt::Display for IntentResolutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "IntentValidationError: {}", self.processing_error)
    }
}

impl RetryableError for IntentResolutionError {
    fn is_retryable(&self) -> bool {
        self.processing_error.is_retryable()
    }
}

#[derive(Debug)]
pub(crate) struct PublishIntentData {
    staged_commit: Option<Vec<u8>>,
    post_commit_action: Option<Vec<u8>>,
    /// One or more payloads to publish. Most intents have a single payload (commit or message),
    /// but proposal intents may have multiple payloads (one per proposal).
    payloads_to_publish: Vec<Vec<u8>>,
    should_send_push_notification: bool,
    group_epoch: u64,
}

#[cfg(any(test, feature = "test-utils"))]
impl PublishIntentData {
    #[allow(dead_code)]
    pub fn post_commit_data(&self) -> Option<Vec<u8>> {
        self.post_commit_action.clone()
    }

    #[allow(dead_code)]
    pub fn staged_commit(&self) -> Option<Vec<u8>> {
        self.staged_commit.clone()
    }
}

impl<Context> MlsGroup<Context>
where
    Context: XmtpSharedContext,
{
    #[tracing::instrument]
    pub async fn sync(&self) -> Result<SyncSummary, GroupError> {
        let conn = self.context.db();

        let epoch = self.epoch().await?;
        tracing::info!(
            inbox_id = self.context.inbox_id(),
            installation_id = %self.context.installation_id(),
            group_id = self.group_id.short_hex(),
            "[{}] syncing group, epoch = {epoch}",
            self.context.inbox_id(),
        );

        // Also sync the "stitched DMs", if any...
        for other_dm in conn.other_dms(&self.group_id)? {
            let other_dm = Self::new_from_arc(
                self.context.clone(),
                other_dm.id,
                other_dm.dm_id.clone(),
                other_dm.conversation_type,
                other_dm.created_at_ns,
            );

            other_dm.sync_with_conn().await?;
            other_dm.maybe_update_installations(None).await?;
        }

        let sync_summary = self.sync_with_conn().await.map_err(GroupError::from)?;
        self.maybe_update_installations(None).await?;
        Ok(sync_summary)
    }

    fn handle_group_paused(&self) -> Result<(), GroupError> {
        // Check if group is paused and try to unpause if version requirements are met
        if let Some(required_min_version_str) =
            self.context.db().get_group_paused_version(&self.group_id)?
        {
            tracing::info!(
                "Group is paused until version: {}",
                required_min_version_str
            );
            let current_version_str = self.context.version_info().pkg_version();
            let current_version = LibXMTPVersion::parse(current_version_str)?;
            let required_min_version = LibXMTPVersion::parse(&required_min_version_str)?;

            if required_min_version <= current_version {
                tracing::info!(
                    "Unpausing group since version requirements are met. \
                     Group ID: {}",
                    hex::encode(&self.group_id),
                );
                self.context.db().unpause_group(&self.group_id)?;
            } else {
                tracing::warn!(
                    "Skipping sync for paused group since version requirements are not met. \
                    Group ID: {}, \
                    Required version: {}, \
                    Current version: {}",
                    hex::encode(&self.group_id),
                    required_min_version_str,
                    current_version_str
                );
                // Skip sync for paused groups
                return Err(GroupError::GroupPausedUntilUpdate(required_min_version_str));
            }
        }
        Ok(())
    }

    /// Sync from the network with the 'conn' (local database).
    /// must return a summary of all messages synced, whether they were
    /// successful or not.
    #[cfg_attr(any(test, feature = "test-utils"), tracing::instrument(fields(who = %self.context.inbox_id())))]
    #[cfg_attr(not(any(test, feature = "test-utils")), tracing::instrument(skip_all))]
    pub async fn sync_with_conn(&self) -> Result<SyncSummary, SyncSummary> {
        let _mutex = self.mutex.lock().await;
        let mut summary = SyncSummary::default();

        if !self.is_active().map_err(SyncSummary::other)? {
            log_event!(
                Event::GroupSyncGroupInactive,
                self.context.installation_id(),
                group_id = self.group_id
            );
            return Err(SyncSummary::other(GroupError::GroupInactive));
        }

        if let Err(e) = self.handle_group_paused() {
            if matches!(e, GroupError::GroupPausedUntilUpdate(_)) {
                // nothing synced
                return Ok(summary);
            } else {
                return Err(SyncSummary::other(e));
            }
        }

        // Even if publish fails, continue to receiving
        let result = self.publish_intents().await;
        if let Err(e) = result {
            tracing::error!("Sync: error publishing intents {e:?}",);
            summary.add_publish_err(e);
        }

        // Even if receiving fails, we continue to post_commit
        // Errors are collected in the summary.
        let result = self.receive().await;
        match result {
            Ok(s) => summary.add_process(s),
            Err(e) => {
                summary.add_other(e);
                // We don't return an error if receive fails, because it's possible this is caused
                // by malicious data sent over the network, or messages from before the user was
                // added to the group
            }
        }

        let result = self.post_commit().await;
        if let Err(e) = result {
            tracing::error!("post commit error {e:?}",);
            summary.add_post_commit_err(e);
        }

        if summary.is_errored() {
            Err(summary)
        } else {
            Ok(summary)
        }
    }

    #[cfg_attr(any(test, feature = "test-utils"), tracing::instrument(level = "info", fields(who = %self.context.inbox_id()), skip_all))]
    #[cfg_attr(
        not(any(test, feature = "test-utils")),
        tracing::instrument(level = "trace", skip_all)
    )]
    pub(crate) async fn sync_until_last_intent_resolved(&self) -> Result<SyncSummary, GroupError> {
        let intents = self.context.db().find_group_intents(
            self.group_id.clone(),
            Some(vec![IntentState::ToPublish, IntentState::Published]),
            None,
        )?;

        let Some(intent) = intents.last() else {
            return Ok(Default::default());
        };

        self.sync_until_intent_resolved(intent.id).await
    }

    /**
     * Sync the group and wait for the intent to be deleted
     * Group syncing may involve picking up messages unrelated to the intent, so simply checking for errors
     * does not give a clear signal as to whether the intent was successfully completed or not.
     *
     * This method will retry up to `xmtp_configuration::MAX_GROUP_SYNC_RETRIES` times.
     */
    #[cfg_attr(any(test, feature = "test-utils"), tracing::instrument(level = "info", fields(who = %self.context.inbox_id()), skip(self)))]
    #[cfg_attr(
        not(any(test, feature = "test-utils")),
        tracing::instrument(level = "trace", skip(self))
    )]
    pub(crate) async fn sync_until_intent_resolved(
        &self,
        intent_id: ID,
    ) -> Result<SyncSummary, GroupError> {
        log_event!(
            Event::GroupSyncStart,
            self.context.installation_id(),
            group_id = self.group_id
        );

        let result = self.sync_until_intent_resolved_inner(intent_id).await;
        let summary = match &result {
            Ok(summary) => Some(summary),
            Err(GroupError::Sync(summary)) => Some(&**summary),
            Err(GroupError::SyncFailedToWait(summary)) => Some(&**summary),
            _ => None,
        };

        log_event!(
            Event::GroupSyncFinished,
            self.context.installation_id(),
            group_id = self.group_id,
            summary = ?summary,
            success = result.is_ok()
        );

        result
    }

    #[cfg_attr(any(test, feature = "test-utils"), tracing::instrument(level = "info", fields(who = %self.context.inbox_id()), skip(self)))]
    #[cfg_attr(
        not(any(test, feature = "test-utils")),
        tracing::instrument(level = "trace", skip(self))
    )]
    async fn sync_until_intent_resolved_inner(
        &self,
        intent_id: ID,
    ) -> Result<SyncSummary, GroupError> {
        let mut summary = SyncSummary::default();
        let db = self.context.db();

        let time_spent = xmtp_common::time::Instant::now();
        let backoff = ExponentialBackoff::builder()
            .duration(Duration::from_millis(SYNC_BACKOFF_WAIT_MS.into()))
            .total_wait_max(Duration::from_secs(SYNC_BACKOFF_TOTAL_WAIT_MAX_SECS.into()))
            .max_jitter(Duration::from_millis(SYNC_JITTER_MS.into()))
            .build();

        // Return the last error to the caller if we fail to sync
        for attempt in 0..MAX_GROUP_SYNC_RETRIES {
            let wait_for = backoff
                .backoff(attempt + 1, time_spent)
                .unwrap_or(Duration::from_millis(50));

            log_event!(
                Event::GroupSyncAttempt,
                self.context.installation_id(),
                group_id = self.group_id,
                attempt,
                backoff = ?wait_for
            );

            match self.sync_with_conn().await {
                Ok(s) => summary.extend(s),
                Err(s) => {
                    tracing::error!("error syncing group {s}");
                    summary.extend(s);
                }
            }
            match Fetch::<StoredGroupIntent>::fetch(&db, &intent_id) {
                Ok(Some(StoredGroupIntent {
                    state: IntentState::Processed,
                    ..
                })) => {
                    // This is expected, we mark intents as processed on success.
                    return Ok(summary);
                }
                Ok(None) => {
                    // This is somewhat expected, we used to delete intents on success.
                    tracing::warn!(
                        "Intent was deleted when it should have been marked as processed.\
                         This is still okay, but unexpected. intent_id: {intent_id}",
                    );
                    return Ok(summary);
                }

                Ok(Some(StoredGroupIntent {
                    state: IntentState::Error,
                    kind,
                    ..
                })) => {
                    log_event!(
                        Event::GroupSyncIntentErrored,
                        self.context.installation_id(),
                        level = warn,
                        group_id = self.group_id, intent_id = intent_id,
                        summary = ?summary, intent_kind = ?kind
                    );
                    return Err(GroupError::from(summary));
                }
                Ok(Some(StoredGroupIntent { state, kind, .. })) => {
                    log_event!(
                        Event::GroupSyncIntentRetry,
                        self.context.installation_id(),
                        level = warn, group_id = self.group_id,
                        intent_id = intent_id, state = ?state, intent_kind = ?kind
                    );
                }
                Err(err) => {
                    tracing::error!("database error fetching intent {err:?}");
                    summary.add_other(GroupError::Storage(err));
                }
            };
            if attempt + 1 < MAX_GROUP_SYNC_RETRIES {
                xmtp_common::time::sleep(wait_for).await;
            }
        }
        Err(GroupError::SyncFailedToWait(Box::new(summary)))
    }

}

#[cfg(test)]
pub(crate) mod tests {

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
}
