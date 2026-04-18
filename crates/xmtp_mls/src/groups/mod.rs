//! Group lifecycle surfaces layered on top of the OpenMLS state machine.
//!
//! `MlsGroup` is the long-lived facade that callers interact with. The surrounding modules split
//! responsibilities like creation, membership changes, message publishing, metadata updates, and
//! sync/replay so those concerns can evolve independently without changing the binding-facing
//! shape of the type.

pub mod commit_log;
pub mod commit_log_key;
mod creation;
mod error;
mod group_config;
pub mod group_membership;
pub mod group_permissions;
pub mod intents;
pub mod members;
mod membership_ops;
mod message_fields;
pub mod message_list;
mod message_ops;
mod message_settings;
mod metadata_ops;
pub(super) mod mls_ext;
pub(super) mod mls_sync;
pub mod oneshot;
mod proposal_ops;
pub mod send_message_opts;
mod state_ops;
pub(super) mod subscriptions;
pub mod summary;
#[cfg(test)]
mod tests;
pub mod validated_commit;
pub mod welcome_pointer;
pub mod welcome_sync;
mod welcomes;
pub(crate) use creation::validate_dm_group;
pub use group_config::{
    build_dm_mutable_metadata_extension_default, build_extensions_for_admin_lists_update,
    build_extensions_for_membership_update, build_extensions_for_metadata_update,
    build_extensions_for_permissions_update, build_group_membership_extension,
    build_mutable_metadata_extension_default, build_proposals_enabled_extension,
    build_starting_group_membership_extension, check_proposals_enabled,
    filter_inbox_ids_needing_updates, update_required_capabilities_for_proposals,
};
pub(crate) use group_config::{
    build_dm_protected_metadata_extension, build_group_config, build_mutable_permissions_extension,
    build_protected_metadata_extension,
};
pub(crate) use message_fields::QueryableContentFields;
pub use welcomes::*;
pub use xmtp_db::group_message::DeliveryStatus;
pub use xmtp_db::user_preferences::HmacKey;
pub use xmtp_mls_common::group::{DMMetadataOptions, GroupMetadataOptions};
pub use xmtp_proto::types::Cursor;

#[cfg(test)]
pub(crate) use self::group_permissions::PolicySet;
pub use self::group_permissions::PreconfiguredPolicies;
use crate::{GroupCommitLock, context::XmtpSharedContext};
pub use error::*;
use openmls::prelude::{GroupId, MlsGroup as OpenMlsGroup};
use std::sync::Arc;
use tokio::sync::Mutex;
use xmtp_db::prelude::*;
use xmtp_db::{NotFound, StorageError};
use xmtp_db::{
    XmtpMlsStorageProvider, group::ConversationType, group::StoredGroup,
    group_message::StoredGroupMessage,
};
use xmtp_proto::types::GlobalCursor;

const MAX_GROUP_DESCRIPTION_LENGTH: usize = 1000;
const MAX_GROUP_NAME_LENGTH: usize = 100;
const MAX_GROUP_IMAGE_URL_LENGTH: usize = 2048;
const MAX_APP_DATA_LENGTH: usize = 8192;

/// Binding-facing handle for one XMTP conversation.
///
/// `MlsGroup` deliberately keeps a small amount of durable identity plus the shared context needed
/// to load and mutate MLS state on demand. Most operations reacquire the stored OpenMLS group
/// under the appropriate lock instead of caching mutable state on the struct itself, which keeps
/// clones cheap and prevents bindings from observing stale in-memory state.
///
/// _NOTE:_ The Eq implementation compares [`GroupId`], so a dm group with the same identity will be
/// different. The Hash implementation hashes the [`GroupId`].
pub struct MlsGroup<Context> {
    pub group_id: Vec<u8>,
    pub dm_id: Option<String>,
    pub conversation_type: ConversationType,
    pub created_at_ns: i64,
    pub context: Context,
    mls_commit_lock: Arc<GroupCommitLock>,
    mutex: Arc<Mutex<()>>,
    stream_seed_cursor: Option<GlobalCursor>,
    stream_replay_after_ns: Option<i64>,
}

impl<C> std::hash::Hash for MlsGroup<C> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.group_id.hash(state);
    }
}

impl<C> PartialEq for MlsGroup<C> {
    fn eq(&self, other: &Self) -> bool {
        self.group_id == other.group_id
    }
}

impl<C> Eq for MlsGroup<C> {}

impl<Context> std::fmt::Debug for MlsGroup<Context>
where
    Context: XmtpSharedContext,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        let id = xmtp_common::fmt::truncate_hex(hex::encode(&self.group_id));
        let inbox_id = self.context.inbox_id();
        let installation = self.context.installation_id().to_string();
        let time = chrono::DateTime::from_timestamp_nanos(self.created_at_ns);
        write!(
            f,
            "Group {{ id: [{}], created: [{}], client: [{}], installation: [{}] }}",
            id,
            time.format("%H:%M:%S"),
            inbox_id,
            installation
        )
    }
}

pub struct ConversationListItem<Context> {
    pub group: MlsGroup<Context>,
    pub last_message: Option<StoredGroupMessage>,
    pub is_commit_log_forked: Option<bool>,
}

impl<Context: XmtpSharedContext> Clone for MlsGroup<Context> {
    fn clone(&self) -> Self {
        Self {
            group_id: self.group_id.clone(),
            dm_id: self.dm_id.clone(),
            conversation_type: self.conversation_type,
            created_at_ns: self.created_at_ns,
            context: self.context.clone(),
            mutex: self.mutex.clone(),
            mls_commit_lock: self.mls_commit_lock.clone(),
            stream_seed_cursor: self.stream_seed_cursor.clone(),
            stream_replay_after_ns: self.stream_replay_after_ns,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ConversationDebugInfo {
    pub epoch: u64,
    pub maybe_forked: bool,
    pub fork_details: String,
    pub is_commit_log_forked: Option<bool>,
    pub local_commit_log: String,
    pub remote_commit_log: String,
    pub cursor: Vec<Cursor>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum UpdateAdminListType {
    Add,
    Remove,
    AddSuper,
    RemoveSuper,
}

impl<Context: Clone> From<MlsGroup<&Context>> for MlsGroup<Context> {
    fn from(group: MlsGroup<&Context>) -> MlsGroup<Context> {
        MlsGroup::<Context> {
            context: group.context.clone(),
            group_id: group.group_id,
            dm_id: group.dm_id,
            created_at_ns: group.created_at_ns,
            mls_commit_lock: group.mls_commit_lock,
            mutex: group.mutex,
            conversation_type: group.conversation_type,
            stream_seed_cursor: group.stream_seed_cursor,
            stream_replay_after_ns: group.stream_replay_after_ns,
        }
    }
}

/// Represents a group, which can contain anywhere from 1 to MAX_GROUP_SIZE inboxes.
///
/// This is a wrapper around OpenMLS's `MlsGroup` that handles our application-level configuration
/// and validations.
impl<Context> MlsGroup<Context>
where
    Context: XmtpSharedContext,
{
    /// Creates a lightweight handle without checking that backing storage already exists.
    ///
    /// This is useful when higher-level callers already own the database row or are reconstructing
    /// a group from adjacent query results. Callers that need existence validation should prefer
    /// [`Self::new_cached`].
    pub fn new(
        context: Context,
        group_id: Vec<u8>,
        dm_id: Option<String>,
        conversation_type: ConversationType,
        created_at_ns: i64,
    ) -> Self {
        Self::new_from_arc(
            context.clone(),
            group_id,
            dm_id,
            conversation_type,
            created_at_ns,
        )
    }

    /// Creates a new handle after confirming the group exists in local storage.
    ///
    /// # Returns
    ///
    /// Returns the Group and the stored group information as a tuple.
    pub fn new_cached(
        context: Context,
        group_id: &[u8],
    ) -> Result<(Self, StoredGroup), StorageError> {
        let conn = context.db();
        if let Some(group) = conn.find_group(group_id)? {
            Ok((
                Self::new_from_arc(
                    context,
                    group_id.to_vec(),
                    group.dm_id.clone(),
                    group.conversation_type,
                    group.created_at_ns,
                ),
                group,
            ))
        } else {
            tracing::error!("group {} does not exist", hex::encode(group_id));
            Err(NotFound::GroupById(group_id.to_vec()).into())
        }
    }

    /// Internal constructor that reuses the context-scoped mutex registry.
    ///
    /// Every `MlsGroup` for the same `group_id` must share the same mutex so async callers serialize
    /// local OpenMLS mutations even when the binding layer creates multiple handles.
    pub(crate) fn new_from_arc(
        context: Context,
        group_id: Vec<u8>,
        dm_id: Option<String>,
        conversation_type: ConversationType,
        created_at_ns: i64,
    ) -> Self {
        let mut mutexes = context.mutexes().clone();
        Self {
            group_id: group_id.clone(),
            dm_id,
            conversation_type,
            created_at_ns,
            mutex: mutexes.get_mutex(group_id),
            context: context.clone(),
            mls_commit_lock: Arc::clone(context.mls_commit_lock()),
            stream_seed_cursor: None,
            stream_replay_after_ns: None,
        }
    }

    pub(crate) fn with_stream_seed_cursor(mut self, cursor: Option<GlobalCursor>) -> Self {
        self.stream_seed_cursor = cursor;
        self
    }

    pub(crate) fn stream_seed_cursor(&self) -> Option<GlobalCursor> {
        self.stream_seed_cursor.clone()
    }

    pub(crate) fn with_stream_replay_after_ns(mut self, replay_after_ns: Option<i64>) -> Self {
        self.stream_replay_after_ns = replay_after_ns;
        self
    }

    pub(crate) fn stream_replay_after_ns(&self) -> Option<i64> {
        self.stream_replay_after_ns
    }

    // Load the stored OpenMLS group from the OpenMLS provider's keystore
    #[tracing::instrument(level = "trace", skip_all)]
    pub(crate) fn load_mls_group_with_lock<F, R>(
        &self,
        storage: &impl XmtpMlsStorageProvider,
        operation: F,
    ) -> Result<R, GroupError>
    where
        F: Fn(OpenMlsGroup) -> Result<R, GroupError>,
    {
        // Get the group ID for locking
        let group_id = self.group_id.clone();

        // Acquire the lock synchronously using blocking_lock
        let _lock = self.mls_commit_lock.get_lock_sync(group_id.clone());
        // Load the MLS group
        let mls_group = OpenMlsGroup::load(storage, &GroupId::from_slice(&self.group_id))
            .map_err(|_| NotFound::MlsGroup)?
            .ok_or(NotFound::MlsGroup)?;

        // Perform the operation with the MLS group
        operation(mls_group)
    }

    // Load the stored OpenMLS group from the OpenMLS provider's keystore
    #[tracing::instrument(level = "trace", skip(operation))]
    pub(crate) async fn load_mls_group_with_lock_async<R, E>(
        &self,
        operation: impl AsyncFnOnce(OpenMlsGroup) -> Result<R, E>,
    ) -> Result<R, E>
    where
        E: From<crate::StorageError> + From<xmtp_db::sql_key_store::SqlKeyStoreError>,
    {
        let mls_storage = self.context.mls_storage();
        // Get the group ID for locking
        let group_id = self.group_id.clone();

        // Acquire the lock asynchronously
        let _lock = self.mls_commit_lock.get_lock_async(group_id.clone()).await;

        // Load the MLS group
        let mls_group = OpenMlsGroup::load(mls_storage, &GroupId::from_slice(&self.group_id))?
            .ok_or(StorageError::from(NotFound::GroupById(
                self.group_id.to_vec(),
            )))?;

        // Perform the operation with the MLS group
        operation(mls_group).await
    }
}
