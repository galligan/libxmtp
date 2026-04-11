//! Group lifecycle surfaces layered on top of the OpenMLS state machine.
//!
//! `MlsGroup` is the long-lived facade that callers interact with. The surrounding modules split
//! responsibilities like creation, membership changes, message publishing, metadata updates, and
//! sync/replay so those concerns can evolve independently without changing the binding-facing
//! shape of the type.

pub mod commit_log;
pub mod commit_log_key;
mod error;
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
pub(crate) use message_fields::QueryableContentFields;
pub use welcomes::*;
pub use xmtp_proto::types::Cursor;

pub use self::group_permissions::PreconfiguredPolicies;
use self::{
    group_membership::GroupMembership,
    group_permissions::PolicySet,
    group_permissions::{GroupMutablePermissions, extract_group_permissions},
};
use crate::groups::{
    intents::{
        AdminListActionType, PermissionUpdateType, UpdateAdminListIntentData,
        UpdatePermissionIntentData,
    },
    mls_ext::CommitLogStorer,
};
use crate::{GroupCommitLock, context::XmtpSharedContext};
pub use error::*;
use openmls::{
    credentials::CredentialType,
    extensions::{
        Extension, ExtensionType, Extensions, Metadata, RequiredCapabilitiesExtension,
        UnknownExtension,
    },
    group::{GroupContext, MlsGroupCreateConfig},
    messages::proposals::ProposalType,
    prelude::{Capabilities, GroupId, MlsGroup as OpenMlsGroup, WireFormatPolicy},
};
use std::sync::Arc;
use tokio::sync::Mutex;
use xmtp_common::time::now_ns;
use xmtp_configuration::{
    BROADCAST_PROPOSAL_SUPPORT, CIPHERSUITE, GROUP_MEMBERSHIP_EXTENSION_ID,
    GROUP_PERMISSIONS_EXTENSION_ID, MAX_PAST_EPOCHS, MUTABLE_METADATA_EXTENSION_ID,
    PROPOSAL_SUPPORT_EXTENSION_ID, WELCOME_POINTEE_ENCRYPTION_AEAD_TYPES_EXTENSION_ID,
    WELCOME_WRAPPER_ENCRYPTION_EXTENSION_ID,
};
use xmtp_cryptography::configuration::ED25519_KEY_LENGTH;
use xmtp_db::prelude::*;
use xmtp_db::user_preferences::HmacKey;
use xmtp_db::{NotFound, StorageError};
use xmtp_db::{Store, StoreOrIgnore};
use xmtp_db::{XmtpMlsStorageProvider, consent_record::ConsentState};
use xmtp_db::{
    group::{ConversationType, GroupMembershipState, StoredGroup},
    group_message::{DeliveryStatus, StoredGroupMessage},
};
use xmtp_id::{InboxId, InboxIdRef};
use xmtp_mls_common::{
    group::{DMMetadataOptions, GroupMetadataOptions},
    group_metadata::{DmMembers, GroupMetadata, extract_group_metadata},
    group_mutable_metadata::{GroupMutableMetadata, GroupMutableMetadataError},
};
use xmtp_proto::xmtp::mls::message_contents::OneshotMessage;

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
        }
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

    /// Check if all members in the group support the proposal-by-reference flow.
    ///
    /// This checks both:
    /// 1. Leaf node capabilities in the MLS group (via `check_extension_support`)
    /// 2. The latest published key packages for all member installations fetched
    ///    from the network, since leaf nodes may be stale (they aren't updated after
    ///    the first message is sent).
    ///
    /// Returns `true` if all members support proposals, `false` otherwise.
    pub async fn all_members_support_proposals(
        &self,
        mls_group: &OpenMlsGroup,
    ) -> Result<bool, GroupError> {
        let extension_type = ExtensionType::Unknown(PROPOSAL_SUPPORT_EXTENSION_ID);

        // Check leaf nodes in the group first (fast path).
        // If all leaf nodes advertise support, we're done — no network call needed.
        if mls_group.check_extension_support(&[extension_type]).is_ok() {
            return Ok(true);
        }

        // Leaf nodes can be stale (they aren't updated after the first message),
        // so fall back to checking the latest published key packages from the network.
        let installation_ids: Vec<Vec<u8>> = mls_group
            .members()
            .map(|member| member.signature_key)
            .filter(|id| id.as_slice() != self.context.installation_id().as_slice())
            .collect();

        if installation_ids.is_empty() {
            return Ok(true);
        }

        let store = crate::mls_store::MlsStore::new(self.context.clone());
        let key_packages = store
            .get_key_packages_for_installation_ids(installation_ids)
            .await?;

        for result in key_packages.values() {
            match result {
                Ok(verified_kp) => {
                    let capabilities = verified_kp.inner.leaf_node().capabilities();
                    if !capabilities.extensions().contains(&extension_type) {
                        return Ok(false);
                    }
                }
                Err(_) => {
                    return Ok(false);
                }
            }
        }

        Ok(true)
    }

    /// Check if the group has proposals enabled (proposal-by-reference flow).
    ///
    /// This checks if the group context contains the `PROPOSAL_SUPPORT_EXTENSION_ID`
    /// extension with a `ProposalSupport` proto.
    ///
    /// When proposals are enabled on a group:
    /// - Add/remove member operations MUST use proposals
    /// - All members being added MUST support the proposal extension
    /// - Direct commits for membership changes are not allowed
    pub fn proposals_enabled(&self, mls_group: &OpenMlsGroup) -> bool {
        check_proposals_enabled(mls_group.extensions())
    }

    /// Enable proposals on this group (proposal-by-reference flow).
    ///
    /// This sets the `PROPOSAL_SUPPORT_EXTENSION_ID` extension on the group context.
    /// Once enabled:
    /// - All add/remove member operations will use proposals
    /// - All members being added must support proposals
    /// - This cannot be disabled once set
    ///
    /// # Prerequisites
    ///
    /// Before calling this method, ensure all existing members support proposals
    /// by calling `all_members_support_proposals()`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Not all existing members support proposals
    /// - The group context extension update fails
    pub async fn enable_proposals(&self) -> Result<(), GroupError> {
        // Check support AND build extensions in a single lock acquisition to avoid
        // a race where membership changes between the check and the build.
        let new_extensions = self
            .load_mls_group_with_lock_async(async |mls_group| {
                if !self.all_members_support_proposals(&mls_group).await? {
                    return Err(GroupError::ProposalsNotSupported(
                        "Cannot enable proposals: not all members support the proposal extension"
                            .to_string(),
                    ));
                }
                let mut extensions: Extensions<GroupContext> = mls_group.extensions().clone();
                extensions.add_or_replace(build_proposals_enabled_extension())?;
                update_required_capabilities_for_proposals(&mut extensions, true)?;
                Ok(extensions)
            })
            .await?;

        // Queue and publish the GCE proposal
        use openmls::prelude::tls_codec::Serialize;
        let extensions_bytes = new_extensions.tls_serialize_detached()?;

        let intent_data = intents::ProposeGroupContextExtensionsIntentData::new(extensions_bytes);
        let proposal_intent = intents::QueueIntent::propose_group_context_extensions()
            .data(intent_data)
            .queue(self)?;

        self.sync_until_intent_resolved(proposal_intent.id).await?;

        // Re-verify after sync: incoming messages processed during sync may have
        // changed group membership (e.g. a member was added who doesn't support
        // proposals). Abort before committing if support no longer holds.
        let still_supported = self
            .load_mls_group_with_lock_async(async |mls_group| {
                self.all_members_support_proposals(&mls_group).await
            })
            .await?;

        if !still_supported {
            return Err(GroupError::ProposalsNotSupported(
                "Cannot enable proposals: group membership changed and not all members support the proposal extension"
                    .to_string(),
            ));
        }

        // Commit the pending proposals to apply the extension
        let commit_intent = intents::QueueIntent::commit_pending_proposals()
            .data(intents::CommitPendingProposalsIntentData::new())
            .queue(self)?;

        self.sync_until_intent_resolved(commit_intent.id).await?;

        let enabled = self
            .load_mls_group_with_lock_async(async |mls_group| {
                Ok::<bool, GroupError>(self.proposals_enabled(&mls_group))
            })
            .await?;

        if !enabled {
            return Err(GroupError::ProposalsNotSupported(
                "Failed to enable proposals: extension not applied".to_string(),
            ));
        }

        Ok(())
    }

    /// Validate that key packages support the proposal extension.
    ///
    /// This checks if all provided key packages have the `PROPOSAL_SUPPORT_EXTENSION_ID`
    /// in their capabilities, meaning the installations can receive standalone proposals.
    pub fn validate_key_packages_support_proposals(
        &self,
        key_packages: &[openmls::key_packages::KeyPackage],
    ) -> Result<(), GroupError> {
        let extension_type = ExtensionType::Unknown(PROPOSAL_SUPPORT_EXTENSION_ID);

        for kp in key_packages {
            let leaf_node = kp.leaf_node();
            let capabilities = leaf_node.capabilities();

            if !capabilities.extensions().contains(&extension_type) {
                return Err(GroupError::ProposalsNotSupported(
                    "Member does not support proposals: installation cannot receive standalone proposal messages".to_string(),
                ));
            }
        }

        Ok(())
    }

    // Create a new group and save it to the DB
    pub(crate) fn create_and_insert(
        context: Context,
        conversation_type: ConversationType,
        permissions_policy_set: PolicySet,
        opts: GroupMetadataOptions,
        oneshot_message: Option<OneshotMessage>,
    ) -> Result<Self, GroupError> {
        assert!(conversation_type != ConversationType::Dm);
        let stored_group = Self::insert(
            &context,
            None,
            GroupMembershipState::Allowed,
            conversation_type,
            permissions_policy_set,
            opts,
            oneshot_message,
        )?;
        let new_group = Self::new_from_arc(
            context.clone(),
            stored_group.id,
            stored_group.dm_id,
            conversation_type,
            stored_group.created_at_ns,
        );

        // Consent state defaults to allowed when the user creates the group
        if !conversation_type.is_virtual() {
            new_group.update_consent_state(ConsentState::Allowed)?;
        }

        Ok(new_group)
    }

    pub(crate) fn insert(
        context: &Context,
        existing_group_id: Option<&[u8]>,
        membership_state: GroupMembershipState,
        conversation_type: ConversationType,
        permissions_policy_set: PolicySet,
        opts: GroupMetadataOptions,
        oneshot_message: Option<OneshotMessage>,
    ) -> Result<StoredGroup, GroupError> {
        assert!(conversation_type != ConversationType::Dm);

        let creator_inbox_id = context.inbox_id();
        let protected_metadata = build_protected_metadata_extension(
            creator_inbox_id,
            conversation_type,
            oneshot_message,
        )?;
        let mutable_metadata =
            build_mutable_metadata_extension_default(creator_inbox_id, opts.clone())?;
        let group_membership = build_starting_group_membership_extension(creator_inbox_id, 0);
        let mutable_permissions = build_mutable_permissions_extension(permissions_policy_set)?;
        let group_config = build_group_config(
            protected_metadata,
            mutable_metadata,
            group_membership,
            mutable_permissions,
        )?;

        let provider = context.mls_provider();
        let mls_group = if let Some(existing_group_id) = existing_group_id {
            // TODO: For groups restored from backup, in order to support queries on metadata such as
            // the group title and description, a stubbed OpenMLS group is created, and later overwritten
            // when a welcome is received.
            OpenMlsGroup::from_backup_stub_logged(
                &provider,
                context.identity(),
                &group_config,
                GroupId::from_slice(existing_group_id),
            )?
        } else {
            OpenMlsGroup::from_creation_logged(&provider, context.identity(), &group_config)?
        };

        let group_id = mls_group.group_id().to_vec();
        // If not an existing group, the creator is a super admin and should publish the commit log
        // Otherwise, for existing groups, we'll never publish the commit log until we receive a welcome message
        let should_publish_commit_log = existing_group_id.is_none();

        let stored_group = StoredGroup::builder()
            .id(group_id.clone())
            .created_at_ns(now_ns())
            .membership_state(membership_state)
            .conversation_type(conversation_type)
            .added_by_inbox_id(context.inbox_id().to_string())
            .message_disappear_from_ns(
                opts.message_disappearing_settings
                    .as_ref()
                    .map(|m| m.from_ns),
            )
            .message_disappear_in_ns(opts.message_disappearing_settings.as_ref().map(|m| m.in_ns))
            .should_publish_commit_log(should_publish_commit_log)
            .build()?;

        stored_group.store_or_ignore(&context.db())?;

        Ok(stored_group)
    }

    // Create a new DM and save it to the DB
    pub(crate) fn create_dm_and_insert(
        context: &Context,
        membership_state: GroupMembershipState,
        dm_target_inbox_id: InboxId,
        opts: DMMetadataOptions,
        existing_group_id: Option<&[u8]>,
    ) -> Result<Self, GroupError> {
        let provider = context.mls_provider();
        let protected_metadata =
            build_dm_protected_metadata_extension(context.inbox_id(), dm_target_inbox_id.clone())?;
        let mutable_metadata = build_dm_mutable_metadata_extension_default(
            context.inbox_id(),
            &dm_target_inbox_id,
            opts.clone(),
        )?;
        let group_membership = build_starting_group_membership_extension(context.inbox_id(), 0);
        let mutable_permissions = PolicySet::new_dm();
        let mutable_permission_extension =
            build_mutable_permissions_extension(mutable_permissions)?;
        let group_config = build_group_config(
            protected_metadata,
            mutable_metadata,
            group_membership,
            mutable_permission_extension,
        )?;

        let mls_group = if let Some(group_id) = existing_group_id {
            OpenMlsGroup::from_backup_stub_logged(
                &provider,
                context.identity(),
                &group_config,
                GroupId::from_slice(group_id),
            )?
        } else {
            OpenMlsGroup::from_creation_logged(&provider, context.identity(), &group_config)?
        };

        let group_id = mls_group.group_id().to_vec();
        let stored_group = StoredGroup::builder()
            .id(group_id.clone())
            .created_at_ns(now_ns())
            .membership_state(membership_state)
            .added_by_inbox_id(context.inbox_id().to_string())
            .message_disappear_from_ns(
                opts.message_disappearing_settings
                    .as_ref()
                    .map(|m| m.from_ns),
            )
            .message_disappear_in_ns(opts.message_disappearing_settings.as_ref().map(|m| m.in_ns))
            .dm_id(Some(
                DmMembers {
                    member_one_inbox_id: dm_target_inbox_id,
                    member_two_inbox_id: context.identity().inbox_id().to_string(),
                }
                .to_string(),
            ))
            .build()?;

        stored_group.store(&context.db())?;
        let new_group = Self::new_from_arc(
            context.clone(),
            group_id.clone(),
            stored_group.dm_id,
            ConversationType::Dm,
            stored_group.created_at_ns,
        );
        // Consent state defaults to allowed when the user creates the group
        new_group.update_consent_state(ConsentState::Allowed)?;
        Ok(new_group)
    }

    // Super admin status is only criteria for whether to publish the commit log for now
    fn check_should_publish_commit_log(
        inbox_id: String,
        mutable_metadata: Option<GroupMutableMetadata>,
    ) -> bool {
        mutable_metadata
            .as_ref()
            .map(|metadata| metadata.is_super_admin(&inbox_id))
            .unwrap_or(false) // Default to false if no mutable metadata
    }

    /// Used for testing that dm group validation works as expected.
    ///
    /// See the `test_validate_dm_group` test function for more details.
    #[cfg(test)]
    pub fn create_test_dm_group(
        context: Context,
        dm_target_inbox_id: InboxId,
        custom_protected_metadata: Option<Extension>,
        custom_mutable_metadata: Option<Extension>,
        custom_group_membership: Option<Extension>,
        custom_mutable_permissions: Option<PolicySet>,
        opts: Option<DMMetadataOptions>,
    ) -> Result<Self, GroupError> {
        let provider = context.mls_provider();

        let protected_metadata = custom_protected_metadata.unwrap_or_else(|| {
            build_dm_protected_metadata_extension(context.inbox_id(), dm_target_inbox_id.clone())
                .unwrap()
        });
        let mutable_metadata = custom_mutable_metadata.unwrap_or_else(|| {
            build_dm_mutable_metadata_extension_default(
                context.inbox_id(),
                &dm_target_inbox_id,
                opts.unwrap_or_default(),
            )
            .unwrap()
        });
        let group_membership = custom_group_membership
            .unwrap_or_else(|| build_starting_group_membership_extension(context.inbox_id(), 0));
        let mutable_permissions = custom_mutable_permissions.unwrap_or_else(PolicySet::new_dm);
        let mutable_permission_extension =
            build_mutable_permissions_extension(mutable_permissions)?;

        let group_config = build_group_config(
            protected_metadata,
            mutable_metadata,
            group_membership,
            mutable_permission_extension,
        )?;

        let mls_group =
            OpenMlsGroup::from_creation_logged(&provider, context.identity(), &group_config)?;
        let group_id = mls_group.group_id().to_vec();
        let stored_group = StoredGroup::builder()
            .id(group_id.clone())
            .created_at_ns(now_ns())
            .membership_state(GroupMembershipState::Allowed)
            .added_by_inbox_id(context.inbox_id().to_string())
            .dm_id(Some(
                DmMembers {
                    member_one_inbox_id: context.inbox_id().to_string(),
                    member_two_inbox_id: dm_target_inbox_id,
                }
                .to_string(),
            ))
            .build()?;

        stored_group.store(&context.db())?;
        Ok(Self::new_from_arc(
            context,
            group_id,
            stored_group.dm_id.clone(),
            ConversationType::Dm,
            stored_group.created_at_ns,
        ))
    }
}

pub(crate) fn build_protected_metadata_extension(
    creator_inbox_id: &str,
    conversation_type: ConversationType,
    oneshot_message: Option<OneshotMessage>,
) -> Result<Extension, MetadataPermissionsError> {
    assert!(conversation_type != ConversationType::Dm);
    let metadata = GroupMetadata::new(
        conversation_type,
        creator_inbox_id.to_string(),
        None,
        oneshot_message,
    );
    let protected_metadata = Metadata::new(metadata.try_into()?);

    Ok(Extension::ImmutableMetadata(protected_metadata))
}

fn build_dm_protected_metadata_extension(
    creator_inbox_id: &str,
    dm_inbox_id: InboxId,
) -> Result<Extension, GroupError> {
    let dm_members = Some(DmMembers {
        member_one_inbox_id: creator_inbox_id.to_string(),
        member_two_inbox_id: dm_inbox_id,
    });

    let metadata = GroupMetadata::new(
        ConversationType::Dm,
        creator_inbox_id.to_string(),
        dm_members,
        None,
    );
    let protected_metadata = Metadata::new(
        metadata
            .try_into()
            .map_err(MetadataPermissionsError::from)?,
    );

    Ok(Extension::ImmutableMetadata(protected_metadata))
}

pub(crate) fn build_mutable_permissions_extension(
    policies: PolicySet,
) -> Result<Extension, MetadataPermissionsError> {
    let permissions: Vec<u8> = GroupMutablePermissions::new(policies).try_into()?;
    let unknown_gc_extension = UnknownExtension(permissions);

    Ok(Extension::Unknown(
        GROUP_PERMISSIONS_EXTENSION_ID,
        unknown_gc_extension,
    ))
}

pub fn build_mutable_metadata_extension_default(
    creator_inbox_id: &str,
    opts: GroupMetadataOptions,
) -> Result<Extension, GroupError> {
    let mut commit_log_signer = None;
    if xmtp_configuration::ENABLE_COMMIT_LOG {
        // Optional TODO(rich): Plumb in provider and use traits in commit_log_key.rs to generate and store secret
        commit_log_signer = Some(xmtp_cryptography::rand::rand_secret::<ED25519_KEY_LENGTH>());
    }
    let mutable_metadata: Vec<u8> =
        GroupMutableMetadata::new_default(creator_inbox_id.to_string(), commit_log_signer, opts)
            .try_into()
            .map_err(MetadataPermissionsError::from)?;
    let unknown_gc_extension = UnknownExtension(mutable_metadata);

    Ok(Extension::Unknown(
        MUTABLE_METADATA_EXTENSION_ID,
        unknown_gc_extension,
    ))
}

pub fn build_dm_mutable_metadata_extension_default(
    creator_inbox_id: &str,
    dm_target_inbox_id: &str,
    opts: DMMetadataOptions,
) -> Result<Extension, MetadataPermissionsError> {
    let mut commit_log_signer = None;
    if xmtp_configuration::ENABLE_COMMIT_LOG {
        commit_log_signer = Some(xmtp_cryptography::rand::rand_secret::<ED25519_KEY_LENGTH>());
    }
    let mutable_metadata: Vec<u8> = GroupMutableMetadata::new_dm_default(
        creator_inbox_id.to_string(),
        dm_target_inbox_id,
        commit_log_signer,
        opts,
    )
    .try_into()?;
    let unknown_gc_extension = UnknownExtension(mutable_metadata);

    Ok(Extension::Unknown(
        MUTABLE_METADATA_EXTENSION_ID,
        unknown_gc_extension,
    ))
}

#[tracing::instrument(level = "trace", skip_all)]
pub fn build_extensions_for_metadata_update(
    group: &OpenMlsGroup,
    field_name: String,
    field_value: String,
) -> Result<Extensions<GroupContext>, MetadataPermissionsError> {
    let existing_metadata: GroupMutableMetadata = group.try_into()?;
    let mut attributes = existing_metadata.attributes.clone();
    attributes.insert(field_name, field_value);
    let new_mutable_metadata: Vec<u8> = GroupMutableMetadata::new(
        attributes,
        existing_metadata.admin_list,
        existing_metadata.super_admin_list,
    )
    .try_into()?;
    let unknown_gc_extension = UnknownExtension(new_mutable_metadata);
    let extension = Extension::Unknown(MUTABLE_METADATA_EXTENSION_ID, unknown_gc_extension);
    let mut extensions = group.extensions().clone();
    extensions.add_or_replace(extension)?;
    Ok(extensions)
}

#[tracing::instrument(level = "trace", skip_all)]
pub fn build_extensions_for_permissions_update(
    group: &OpenMlsGroup,
    update_permissions_intent: UpdatePermissionIntentData,
) -> Result<Extensions<GroupContext>, MetadataPermissionsError> {
    let existing_permissions: GroupMutablePermissions = group.try_into()?;
    let existing_policy_set = existing_permissions.policies.clone();
    let new_policy_set = match update_permissions_intent.update_type {
        PermissionUpdateType::AddMember => PolicySet::new(
            update_permissions_intent.policy_option.into(),
            existing_policy_set.remove_member_policy,
            existing_policy_set.update_metadata_policy,
            existing_policy_set.add_admin_policy,
            existing_policy_set.remove_admin_policy,
            existing_policy_set.update_permissions_policy,
        ),
        PermissionUpdateType::RemoveMember => PolicySet::new(
            existing_policy_set.add_member_policy,
            update_permissions_intent.policy_option.into(),
            existing_policy_set.update_metadata_policy,
            existing_policy_set.add_admin_policy,
            existing_policy_set.remove_admin_policy,
            existing_policy_set.update_permissions_policy,
        ),
        PermissionUpdateType::AddAdmin => PolicySet::new(
            existing_policy_set.add_member_policy,
            existing_policy_set.remove_member_policy,
            existing_policy_set.update_metadata_policy,
            update_permissions_intent.policy_option.into(),
            existing_policy_set.remove_admin_policy,
            existing_policy_set.update_permissions_policy,
        ),
        PermissionUpdateType::RemoveAdmin => PolicySet::new(
            existing_policy_set.add_member_policy,
            existing_policy_set.remove_member_policy,
            existing_policy_set.update_metadata_policy,
            existing_policy_set.add_admin_policy,
            update_permissions_intent.policy_option.into(),
            existing_policy_set.update_permissions_policy,
        ),
        PermissionUpdateType::UpdateMetadata => {
            let mut metadata_policy = existing_policy_set.update_metadata_policy.clone();
            metadata_policy.insert(
                update_permissions_intent
                    .metadata_field_name
                    .ok_or(GroupMutableMetadataError::MissingMetadataField)?,
                update_permissions_intent.policy_option.into(),
            );
            PolicySet::new(
                existing_policy_set.add_member_policy,
                existing_policy_set.remove_member_policy,
                metadata_policy,
                existing_policy_set.add_admin_policy,
                existing_policy_set.remove_admin_policy,
                existing_policy_set.update_permissions_policy,
            )
        }
    };
    let new_group_permissions: Vec<u8> = GroupMutablePermissions::new(new_policy_set).try_into()?;
    let unknown_gc_extension = UnknownExtension(new_group_permissions);
    let extension = Extension::Unknown(GROUP_PERMISSIONS_EXTENSION_ID, unknown_gc_extension);
    let mut extensions = group.extensions().clone();
    extensions.add_or_replace(extension)?;
    Ok(extensions)
}

#[tracing::instrument(level = "trace", skip_all)]
pub fn build_extensions_for_admin_lists_update(
    group: &OpenMlsGroup,
    admin_lists_update: UpdateAdminListIntentData,
) -> Result<Extensions<GroupContext>, MetadataPermissionsError> {
    let existing_metadata: GroupMutableMetadata = group.try_into()?;
    let attributes = existing_metadata.attributes.clone();
    let mut admin_list = existing_metadata.admin_list;
    let mut super_admin_list = existing_metadata.super_admin_list;
    match admin_lists_update.action_type {
        AdminListActionType::Add => {
            if !admin_list.contains(&admin_lists_update.inbox_id) {
                admin_list.push(admin_lists_update.inbox_id);
            }
        }
        AdminListActionType::Remove => admin_list.retain(|x| x != &admin_lists_update.inbox_id),
        AdminListActionType::AddSuper => {
            if !super_admin_list.contains(&admin_lists_update.inbox_id) {
                super_admin_list.push(admin_lists_update.inbox_id);
            }
        }
        AdminListActionType::RemoveSuper => {
            super_admin_list.retain(|x| x != &admin_lists_update.inbox_id)
        }
    }
    let new_mutable_metadata: Vec<u8> =
        GroupMutableMetadata::new(attributes, admin_list, super_admin_list).try_into()?;
    let unknown_gc_extension = UnknownExtension(new_mutable_metadata);
    let extension = Extension::Unknown(MUTABLE_METADATA_EXTENSION_ID, unknown_gc_extension);
    let mut extensions = group.extensions().clone();
    extensions.add_or_replace(extension)?;
    Ok(extensions)
}

pub fn build_starting_group_membership_extension(inbox_id: &str, sequence_id: u64) -> Extension {
    let mut group_membership = GroupMembership::new();
    group_membership.add(inbox_id.to_string(), sequence_id);
    build_group_membership_extension(&group_membership)
}

pub fn build_group_membership_extension(group_membership: &GroupMembership) -> Extension {
    let unknown_gc_extension = UnknownExtension(group_membership.into());

    Extension::Unknown(GROUP_MEMBERSHIP_EXTENSION_ID, unknown_gc_extension)
}

/// Check if the given extensions contain a valid proposal support extension.
///
/// Returns `true` if the extensions contain a `PROPOSAL_SUPPORT_EXTENSION_ID` extension
/// with a `ProposalSupport` proto where `version > 0`.
pub fn check_proposals_enabled(extensions: &Extensions<GroupContext>) -> bool {
    use prost::Message;
    use xmtp_proto::xmtp::mls::message_contents::ProposalSupport;
    for extension in extensions.iter() {
        if let Extension::Unknown(PROPOSAL_SUPPORT_EXTENSION_ID, UnknownExtension(data)) = extension
        {
            if let Ok(ps) = ProposalSupport::decode(data.as_slice()) {
                return ps.version > 0;
            } else {
                return false;
            }
        }
    }
    false
}

/// Build an extension that enables proposals on the group context.
///
/// This extension uses `PROPOSAL_SUPPORT_EXTENSION_ID` with a `ProposalSupport` proto
/// to indicate that the group uses proposal-by-reference flow exclusively.
pub fn build_proposals_enabled_extension() -> Extension {
    use prost::Message;
    use xmtp_proto::xmtp::mls::message_contents::ProposalSupport;
    let data = ProposalSupport { version: 1 }.encode_to_vec();
    Extension::Unknown(PROPOSAL_SUPPORT_EXTENSION_ID, UnknownExtension(data))
}

/// Update the `RequiredCapabilities` extension to add or remove the `PROPOSAL_SUPPORT_EXTENSION_ID`.
/// Per MLS RFC 9420 Section 7.2, unknown extensions in the group context MUST be listed
/// in the required capabilities, so this must be called whenever the proposal support
/// extension is added to or removed from the group context.
pub fn update_required_capabilities_for_proposals(
    extensions: &mut Extensions<GroupContext>,
    add: bool,
) -> Result<(), GroupError> {
    let proposal_ext_type = ExtensionType::Unknown(PROPOSAL_SUPPORT_EXTENSION_ID);

    if let Some(required_caps) = extensions.required_capabilities() {
        let mut ext_types: Vec<ExtensionType> = required_caps.extension_types().to_vec();
        let has_it = ext_types.contains(&proposal_ext_type);

        if add && !has_it {
            ext_types.push(proposal_ext_type);
        } else if !add && has_it {
            ext_types.retain(|t| *t != proposal_ext_type);
        } else {
            return Ok(()); // already in desired state
        }

        let new_required = Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &ext_types,
            required_caps.proposal_types(),
            required_caps.credential_types(),
        ));
        extensions.add_or_replace(new_required)?;
    }

    Ok(())
}

/// Build extensions with updated group membership for a GroupContextExtensions proposal.
/// This is used when proposing to add or remove members to include the membership update
/// alongside the Add/Remove proposals.
#[tracing::instrument(level = "trace", skip_all)]
pub fn build_extensions_for_membership_update(
    group: &OpenMlsGroup,
    new_membership: &GroupMembership,
) -> Result<Extensions<GroupContext>, GroupError> {
    let mut extensions: Extensions<GroupContext> = group.extensions().clone();
    extensions.add_or_replace(build_group_membership_extension(new_membership))?;
    Ok(extensions)
}

pub(crate) fn build_group_config(
    protected_metadata_extension: Extension,
    mutable_metadata_extension: Extension,
    group_membership_extension: Extension,
    mutable_permission_extension: Extension,
) -> Result<MlsGroupCreateConfig, GroupError> {
    // Extensions that all group members MUST support (enforced by RequiredCapabilities)
    let required_extension_types = &[
        ExtensionType::Unknown(GROUP_MEMBERSHIP_EXTENSION_ID),
        ExtensionType::Unknown(MUTABLE_METADATA_EXTENSION_ID),
        ExtensionType::Unknown(GROUP_PERMISSIONS_EXTENSION_ID),
        ExtensionType::ImmutableMetadata,
        ExtensionType::LastResort,
        ExtensionType::ApplicationId,
    ];

    // Extensions the creator's leaf node advertises support for (superset of required).
    // Optional extensions like PROPOSAL_SUPPORT are listed here so the group can use
    // them, but are NOT in required_extension_types so members without support can join.
    let mut creator_capability_extensions = required_extension_types.to_vec();
    creator_capability_extensions.push(ExtensionType::Unknown(
        WELCOME_WRAPPER_ENCRYPTION_EXTENSION_ID,
    ));
    creator_capability_extensions.push(ExtensionType::Unknown(
        WELCOME_POINTEE_ENCRYPTION_AEAD_TYPES_EXTENSION_ID,
    ));
    if BROADCAST_PROPOSAL_SUPPORT {
        creator_capability_extensions.push(ExtensionType::Unknown(PROPOSAL_SUPPORT_EXTENSION_ID));
    }

    let required_proposal_types = &[ProposalType::GroupContextExtensions];

    let capabilities = Capabilities::new(
        None,
        None,
        Some(&creator_capability_extensions),
        Some(required_proposal_types),
        None,
    );
    let credentials = &[CredentialType::Basic];

    let required_capabilities =
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            required_extension_types,
            required_proposal_types,
            credentials,
        ));

    let extensions = Extensions::from_vec(vec![
        protected_metadata_extension,
        mutable_metadata_extension,
        group_membership_extension,
        mutable_permission_extension,
        required_capabilities,
    ])?;

    Ok(MlsGroupCreateConfig::builder()
        .with_group_context_extensions(extensions)
        .capabilities(capabilities)
        .ciphersuite(CIPHERSUITE)
        .wire_format_policy(WireFormatPolicy::default())
        .max_past_epochs(MAX_PAST_EPOCHS)
        .use_ratchet_tree_extension(true)
        .build())
}

pub fn filter_inbox_ids_needing_updates<'a>(
    conn: &impl DbQuery,
    filters: &[(&'a str, i64)],
) -> Result<Vec<&'a str>, xmtp_db::ConnectionError> {
    let existing_sequence_ids =
        conn.get_latest_sequence_id(&filters.iter().map(|f| f.0).collect::<Vec<&str>>())?;

    let needs_update = filters
        .iter()
        .filter_map(|&(inbox_id, seq)| {
            let existing_sequence_id = existing_sequence_ids.get(inbox_id);
            if existing_sequence_id.is_some_and(|&s| s >= seq) {
                return None;
            }

            Some(inbox_id)
        })
        .collect();
    Ok(needs_update)
}

pub(crate) trait DmValidationContext {
    fn inbox_id(&self) -> InboxIdRef<'_>;
}

impl<Context> DmValidationContext for Context
where
    Context: XmtpSharedContext,
{
    fn inbox_id(&self) -> InboxIdRef<'_> {
        XmtpSharedContext::inbox_id(self)
    }
}

fn validate_dm_group(
    context: impl DmValidationContext,
    mls_group: &OpenMlsGroup,
    added_by_inbox: &str,
) -> Result<(), MetadataPermissionsError> {
    // Validate dm specific immutable metadata
    let metadata = extract_group_metadata(mls_group.extensions())?;

    // 1) Check if the conversation type is DM
    if metadata.conversation_type != ConversationType::Dm {
        return Err(DmValidationError::InvalidConversationType.into());
    }

    // 2) If `dm_members` is not set, return an error immediately
    let dm_members = match &metadata.dm_members {
        Some(dm) => dm,
        None => {
            return Err(DmValidationError::MustHaveMembersSet.into());
        }
    };

    // 3) If the inbox that added this group is our inbox, make sure that
    //    one of the `dm_members` is our inbox id
    let inbox_id = context.inbox_id();
    if added_by_inbox == inbox_id {
        if !(dm_members.member_one_inbox_id == inbox_id
            || dm_members.member_two_inbox_id == inbox_id)
        {
            return Err(DmValidationError::OurInboxMustBeMember.into());
        }
        return Ok(());
    }

    // 4) Otherwise, make sure one of the `dm_members` is ours, and the other is `added_by_inbox`
    let is_expected_pair = (dm_members.member_one_inbox_id == added_by_inbox
        && dm_members.member_two_inbox_id == inbox_id)
        || (dm_members.member_one_inbox_id == inbox_id
            && dm_members.member_two_inbox_id == added_by_inbox);

    if !is_expected_pair {
        return Err(DmValidationError::ExpectedInboxesDoNotMatch.into());
    }

    // Validate mutable metadata
    let mutable_metadata: GroupMutableMetadata = mls_group.try_into()?;

    // Check if the admin list and super admin list are empty
    if !mutable_metadata.admin_list.is_empty() || !mutable_metadata.super_admin_list.is_empty() {
        return Err(DmValidationError::MustHaveEmptyAdminAndSuperAdmin.into());
    }

    // Validate permissions so no one adds us to a dm that they can unexpectedly add another member to
    // Note: we don't validate mutable metadata permissions, because they don't affect group membership
    let permissions = extract_group_permissions(mls_group)?;
    let expected_permissions = GroupMutablePermissions::new(PolicySet::new_dm());

    if permissions.policies.add_member_policy != expected_permissions.policies.add_member_policy
        && permissions.policies.remove_member_policy
            != expected_permissions.policies.remove_member_policy
        && permissions.policies.add_admin_policy != expected_permissions.policies.add_admin_policy
        && permissions.policies.remove_admin_policy
            != expected_permissions.policies.remove_admin_policy
        && permissions.policies.update_permissions_policy
            != expected_permissions.policies.update_permissions_policy
    {
        return Err(DmValidationError::InvalidPermissions.into());
    }

    Ok(())
}
