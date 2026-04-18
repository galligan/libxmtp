//! Synchronization pipeline for reconciling local intents with remote MLS traffic.
//!
//! This module is the coordination surface for the refactored group sync flow:
//! `publish` prepares and sends local work, `receive` pulls remote envelopes,
//! `processing` validates and applies them, and `persistence` commits the
//! durable side effects that survive retries and restarts.

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
mod orchestration;
mod persistence;
mod processing;
mod publish;
mod receive;
mod removals;
mod resolution;
#[cfg(test)]
mod tests;
mod types;
pub mod update_group_membership;
mod welcomes;
pub(crate) use events::DeferredEvents;
pub(crate) use helpers::decode_staged_commit;
pub(super) use helpers::generate_commit_with_rollback;
use helpers::{extract_message_sender, handle_published_intent_send_failure};
use membership::calculate_membership_changes_with_keypackages;
pub(crate) use types::PublishIntentData;
pub use types::{GroupMessageProcessingError, IntentResolutionError};
