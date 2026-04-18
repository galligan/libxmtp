use super::{
    ConversationDebugInfo, GroupError, MetadataPermissionsError, MlsGroup,
    group_permissions::{GroupMutablePermissions, extract_group_permissions},
};
use crate::{client::ClientError, context::XmtpSharedContext};
use xmtp_configuration::Originators;
use xmtp_db::{
    NotFound,
    group::{ConversationType, GroupMembershipState},
    local_commit_log::LocalCommitLog,
    pending_remove::QueryPendingRemove,
    prelude::*,
    refresh_state::EntityKind,
    remote_commit_log::{RemoteCommitLog, RemoteCommitLogOrder},
};
use xmtp_mls_common::{
    group_metadata::{GroupMetadata, extract_group_metadata},
    group_mutable_metadata::GroupMutableMetadata,
};
use xmtp_proto::types::Cursor;

impl<Context> MlsGroup<Context>
where
    Context: XmtpSharedContext,
{
    /// Load the group reference stored in the local database
    pub fn load(&self) -> Result<xmtp_db::group::StoredGroup, xmtp_db::StorageError> {
        let conn = self.context.db();
        if let Some(group) = conn.find_group(&self.group_id)? {
            Ok(group)
        } else {
            tracing::error!("group {} does not exist", hex::encode(&self.group_id));
            Err(NotFound::GroupById(self.group_id.to_vec()).into())
        }
    }

    pub fn pending_remove_list(&self) -> Result<Vec<String>, GroupError> {
        self.context
            .db()
            .get_pending_remove_users(&self.group_id)
            .map_err(Into::into)
    }

    /// Checks if the given inbox ID is the pending-remove list of the group at the most recently synced epoch.
    pub fn is_in_pending_remove(&self, inbox_id: &str) -> Result<bool, GroupError> {
        self.context
            .db()
            .get_user_pending_remove_status(&self.group_id, inbox_id)
            .map_err(Into::into)
    }

    /// Retrieves the conversation type of the group from the group's metadata extension.
    pub async fn conversation_type(&self) -> Result<ConversationType, GroupError> {
        let conversation_type = self.context.db().get_conversation_type(&self.group_id)?;
        Ok(conversation_type)
    }

    /// Get the current epoch number of the group.
    pub async fn epoch(&self) -> Result<u64, GroupError> {
        self.load_mls_group_with_lock_async(async |mls_group| Ok(mls_group.epoch().as_u64()))
            .await
    }

    /// Get the encryption state of the current epoch. Should match for all installations
    /// in the same epoch.
    pub(crate) async fn epoch_authenticator(&self) -> Result<Vec<u8>, GroupError> {
        self.load_mls_group_with_lock_async(async |mls_group| {
            Ok(mls_group.epoch_authenticator().as_slice().to_vec())
        })
        .await
    }

    pub async fn cursor(&self) -> Result<[Cursor; 2], GroupError> {
        let db = self.context.db();
        let msgs = db.get_last_cursor_for_originator(
            &self.group_id,
            EntityKind::ApplicationMessage,
            Originators::APPLICATION_MESSAGES,
        )?;
        let commits = db.get_last_cursor_for_originator(
            &self.group_id,
            EntityKind::CommitMessage,
            Originators::MLS_COMMITS,
        )?;
        Ok([msgs, commits])
    }

    pub async fn local_commit_log(&self) -> Result<Vec<LocalCommitLog>, GroupError> {
        Ok(self.context.db().get_group_logs(&self.group_id)?)
    }

    pub async fn remote_commit_log(&self) -> Result<Vec<RemoteCommitLog>, GroupError> {
        Ok(self.context.db().get_remote_commit_log_after_cursor(
            &self.group_id,
            0,
            RemoteCommitLogOrder::AscendingByRowid,
        )?)
    }

    pub async fn debug_info(&self) -> Result<ConversationDebugInfo, GroupError> {
        let epoch = self.epoch().await?;
        let cursor = self.cursor().await?;
        let commit_log = self.local_commit_log().await?;
        let remote_commit_log = self.remote_commit_log().await?;
        let db = self.context.db();

        let stored_group = match db.find_group(&self.group_id)? {
            Some(group) => group,
            None => {
                return Err(GroupError::NotFound(NotFound::GroupById(
                    self.group_id.clone(),
                )));
            }
        };

        Ok(ConversationDebugInfo {
            epoch,
            maybe_forked: stored_group.maybe_forked,
            fork_details: stored_group.fork_details,
            is_commit_log_forked: stored_group.is_commit_log_forked,
            local_commit_log: format!("{:?}", commit_log),
            remote_commit_log: format!("{:?}", remote_commit_log),
            cursor: cursor.to_vec(),
        })
    }

    /// Checks if the current user is active in the group.
    ///
    /// If the current user has been kicked out of the group, `is_active` will return `false`
    #[tracing::instrument(skip_all, level = "trace")]
    pub fn is_active(&self) -> Result<bool, GroupError> {
        // Restored groups that are not yet added are inactive
        let Some(stored_group) = self.context.db().find_group(&self.group_id)? else {
            return Err(GroupError::NotFound(NotFound::GroupById(
                self.group_id.clone(),
            )));
        };
        if matches!(
            stored_group.membership_state,
            GroupMembershipState::Restored
        ) {
            return Ok(false);
        }

        self.load_mls_group_with_lock(self.context.mls_storage(), |mls_group| {
            Ok(mls_group.is_active())
        })
    }

    /// Returns the membership state of the current user in this group.
    #[tracing::instrument(skip_all, level = "trace")]
    pub fn membership_state(&self) -> Result<GroupMembershipState, GroupError> {
        let stored_group = self
            .context
            .db()
            .find_group(&self.group_id)?
            .ok_or_else(|| GroupError::NotFound(NotFound::GroupById(self.group_id.clone())))?;
        Ok(stored_group.membership_state)
    }

    /// Get the `GroupMetadata` of the group.
    pub async fn metadata(&self) -> Result<GroupMetadata, GroupError> {
        self.load_mls_group_with_lock_async(async |mls_group| {
            extract_group_metadata(mls_group.extensions())
                .map_err(MetadataPermissionsError::from)
                .map_err(Into::into)
        })
        .await
    }

    /// Get the `GroupMutableMetadata` of the group.
    pub fn mutable_metadata(&self) -> Result<GroupMutableMetadata, GroupError> {
        self.load_mls_group_with_lock(self.context.mls_storage(), |mls_group| {
            GroupMutableMetadata::try_from(&mls_group)
                .map_err(MetadataPermissionsError::from)
                .map_err(GroupError::from)
        })
    }

    pub fn permissions(&self) -> Result<GroupMutablePermissions, GroupError> {
        self.load_mls_group_with_lock(self.context.mls_storage(), |mls_group| {
            Ok(extract_group_permissions(&mls_group).map_err(MetadataPermissionsError::from)?)
        })
    }

    /// Find all the duplicate dms for this group
    pub fn find_duplicate_dms(&self) -> Result<Vec<MlsGroup<Context>>, ClientError> {
        let duplicates = self.context.db().other_dms(&self.group_id)?;

        let mls_groups = duplicates
            .into_iter()
            .map(|g| {
                MlsGroup::new(
                    self.context.clone(),
                    g.id,
                    g.dm_id,
                    g.conversation_type,
                    g.created_at_ns,
                )
            })
            .collect();

        Ok(mls_groups)
    }
}
