use super::{
    GroupError, MetadataPermissionsError, MlsGroup, UpdateAdminListType,
    intents::{
        AdminListActionType, PermissionPolicyOption, PermissionUpdateType,
        UpdateAdminListIntentData, UpdateMetadataIntentData, UpdatePermissionIntentData,
    },
};
use crate::context::XmtpSharedContext;
use xmtp_cryptography::Secret;
use xmtp_db::{
    DbQuery, NotFound,
    consent_record::{ConsentState, StoredConsentRecord},
    group::{ConversationType, DmIdExt},
    prelude::{QueryConsentRecord, QueryGroup, QueryGroupVersion},
};
use xmtp_mls_common::group_mutable_metadata::{
    GroupMutableMetadata, GroupMutableMetadataError, MetadataField,
};

impl<Context> MlsGroup<Context>
where
    Context: XmtpSharedContext,
{
    /// Updates the name of the group. Will error if the user does not have the appropriate permissions
    /// to perform these updates.
    #[cfg_attr(any(test, feature = "test-utils"), tracing::instrument(level = "info", fields(who = %self.context.inbox_id()), skip(self)))]
    #[cfg_attr(
        not(any(test, feature = "test-utils")),
        tracing::instrument(level = "trace", skip(self))
    )]
    pub async fn update_group_name(&self, group_name: String) -> Result<(), GroupError> {
        self.ensure_not_paused().await?;

        if group_name.len() > super::MAX_GROUP_NAME_LENGTH {
            return Err(GroupError::TooManyCharacters {
                length: super::MAX_GROUP_NAME_LENGTH,
            });
        }
        if self.metadata().await?.conversation_type == ConversationType::Dm {
            return Err(MetadataPermissionsError::DmGroupMetadataForbidden.into());
        }
        let intent_data: Vec<u8> =
            UpdateMetadataIntentData::new_update_group_name(group_name).into();
        let intent = super::intents::QueueIntent::metadata_update()
            .data(intent_data)
            .queue(self)?;

        let _ = self.sync_until_intent_resolved(intent.id).await?;
        Ok(())
    }

    #[cfg_attr(any(test, feature = "test-utils"), tracing::instrument(level = "info", fields(who = %self.context.inbox_id()), skip(self)))]
    #[cfg_attr(
        not(any(test, feature = "test-utils")),
        tracing::instrument(level = "trace", skip(self))
    )]
    pub async fn update_app_data(&self, app_data: String) -> Result<(), GroupError> {
        self.ensure_not_paused().await?;

        if app_data.len() > super::MAX_APP_DATA_LENGTH {
            return Err(GroupError::TooManyCharacters {
                length: super::MAX_APP_DATA_LENGTH,
            });
        }
        if self.metadata().await?.conversation_type == ConversationType::Dm {
            return Err(MetadataPermissionsError::DmGroupMetadataForbidden.into());
        }
        let intent_data: Vec<u8> = UpdateMetadataIntentData::new_update_app_data(app_data).into();
        let intent = super::intents::QueueIntent::metadata_update()
            .data(intent_data)
            .queue(self)?;

        let _ = self.sync_until_intent_resolved(intent.id).await?;
        Ok(())
    }

    /// Updates min version of the group to match this client's version.
    /// Not publicly exposed because:
    /// - Setting the min version to pre-release versions may not behave as expected
    /// - When the version is not explicitly specified, unexpected behavior may arise,
    ///   for example if the code is left in across multiple version bumps.
    #[cfg_attr(any(test, feature = "test-utils"), tracing::instrument(level = "info", fields(who = %self.context.inbox_id()), skip(self)))]
    #[cfg_attr(
        not(any(test, feature = "test-utils")),
        tracing::instrument(level = "trace", skip(self))
    )]
    #[allow(dead_code)]
    pub(crate) async fn update_group_min_version_to_match_self(&self) -> Result<(), GroupError> {
        let version = self.context.version_info().pkg_version();
        self.update_group_min_version(version).await
    }

    /// Updates min version of the group to match the given version.
    ///
    /// # Arguments
    /// * `version` - The libxmtp version to update the group min version to.
    ///   This is a semver-formatted string matching the Cargo.toml in the
    ///   libxmtp dependency, and does not match mobile or web release versions.
    ///   Do NOT include pre-release metadata like "1.0.0-alpha",
    ///   "1.0.0-beta", etc, as the version comparison may not match what
    ///   is expected. For historical reasons, "1.0.0-alpha" is considered to be
    ///   > "1.0.0", so it is better to just specify "1.0.0".
    ///
    /// # Returns
    /// A `Result` indicating success or failure of the operation.
    pub async fn update_group_min_version(&self, version: &str) -> Result<(), GroupError> {
        self.ensure_not_paused().await?;
        tracing::info!("updating group min version to match self: {}", version);
        let intent_data: Vec<u8> =
            UpdateMetadataIntentData::new_update_group_min_version_to_match_self(
                version.to_string(),
            )
            .into();
        let intent = super::intents::QueueIntent::metadata_update()
            .data(intent_data)
            .queue(self)?;

        let _ = self.sync_until_intent_resolved(intent.id).await?;
        Ok(())
    }

    /// Updates the commit log signer of the group. Will error if the user does not have the appropriate permissions
    /// to perform these updates.
    pub async fn update_commit_log_signer(
        &self,
        commit_log_signer: Secret,
    ) -> Result<(), GroupError> {
        self.ensure_not_paused().await?;

        if self.metadata().await?.conversation_type == ConversationType::Dm {
            return Err(MetadataPermissionsError::DmGroupMetadataForbidden.into());
        }
        let intent_data: Vec<u8> =
            UpdateMetadataIntentData::new_update_commit_log_signer(commit_log_signer).into();
        let intent = super::intents::QueueIntent::metadata_update()
            .data(intent_data)
            .queue(self)?;

        let _ = self.sync_until_intent_resolved(intent.id).await?;
        Ok(())
    }

    pub(crate) fn min_protocol_version_from_extensions(
        mutable_metadata: &GroupMutableMetadata,
    ) -> Option<String> {
        mutable_metadata
            .attributes
            .get(&MetadataField::MinimumSupportedProtocolVersion.to_string())
            .map(|v| v.to_string())
    }

    /// Updates the permission policy of the group. This requires super admin permissions.
    #[cfg_attr(any(test, feature = "test-utils"), tracing::instrument(level = "info", fields(who = %self.context.inbox_id()), skip(self)))]
    #[cfg_attr(
        not(any(test, feature = "test-utils")),
        tracing::instrument(level = "trace", skip(self))
    )]
    pub async fn update_permission_policy(
        &self,
        permission_update_type: PermissionUpdateType,
        permission_policy: PermissionPolicyOption,
        metadata_field: Option<MetadataField>,
    ) -> Result<(), GroupError> {
        self.ensure_not_paused().await?;

        if self.metadata().await?.conversation_type == ConversationType::Dm {
            return Err(MetadataPermissionsError::DmGroupMetadataForbidden.into());
        }
        if permission_update_type == PermissionUpdateType::UpdateMetadata
            && metadata_field.is_none()
        {
            return Err(MetadataPermissionsError::InvalidPermissionUpdate.into());
        }

        let intent_data: Vec<u8> = UpdatePermissionIntentData::new(
            permission_update_type,
            permission_policy,
            metadata_field.as_ref().map(|field| field.to_string()),
        )
        .into();

        let intent = super::intents::QueueIntent::update_permission()
            .data(intent_data)
            .queue(self)?;

        let _ = self.sync_until_intent_resolved(intent.id).await?;
        Ok(())
    }

    /// Retrieves the group name from the group's mutable metadata extension.
    pub fn group_name(&self) -> Result<String, GroupError> {
        let mutable_metadata = self.mutable_metadata()?;
        self.required_attribute(&mutable_metadata, MetadataField::GroupName)
    }

    /// Retrieves the app_data field from the group's mutable metadata extension
    pub fn app_data(&self) -> Result<String, GroupError> {
        let mutable_metadata = self.mutable_metadata()?;
        self.required_attribute(&mutable_metadata, MetadataField::AppData)
    }

    /// Updates the description of the group.
    #[cfg_attr(any(test, feature = "test-utils"), tracing::instrument(level = "info", fields(who = %self.context.inbox_id()), skip(self)))]
    #[cfg_attr(
        not(any(test, feature = "test-utils")),
        tracing::instrument(level = "trace", skip(self))
    )]
    pub async fn update_group_description(
        &self,
        group_description: String,
    ) -> Result<(), GroupError> {
        self.ensure_not_paused().await?;

        if group_description.len() > super::MAX_GROUP_DESCRIPTION_LENGTH {
            return Err(GroupError::TooManyCharacters {
                length: super::MAX_GROUP_DESCRIPTION_LENGTH,
            });
        }

        if self.metadata().await?.conversation_type == ConversationType::Dm {
            return Err(MetadataPermissionsError::DmGroupMetadataForbidden.into());
        }
        let intent_data: Vec<u8> =
            UpdateMetadataIntentData::new_update_group_description(group_description).into();
        let intent = super::intents::QueueIntent::metadata_update()
            .data(intent_data)
            .queue(self)?;

        let _ = self.sync_until_intent_resolved(intent.id).await?;
        Ok(())
    }

    pub fn group_description(&self) -> Result<String, GroupError> {
        let mutable_metadata = self.mutable_metadata()?;
        self.required_attribute(&mutable_metadata, MetadataField::Description)
    }

    /// Updates the image URL (square) of the group.
    #[cfg_attr(any(test, feature = "test-utils"), tracing::instrument(level = "info", fields(who = %self.context.inbox_id()), skip(self)))]
    #[cfg_attr(
        not(any(test, feature = "test-utils")),
        tracing::instrument(level = "trace", skip(self))
    )]
    pub async fn update_group_image_url_square(
        &self,
        group_image_url_square: String,
    ) -> Result<(), GroupError> {
        self.ensure_not_paused().await?;

        if group_image_url_square.len() > super::MAX_GROUP_IMAGE_URL_LENGTH {
            return Err(GroupError::TooManyCharacters {
                length: super::MAX_GROUP_IMAGE_URL_LENGTH,
            });
        }

        if self.metadata().await?.conversation_type == ConversationType::Dm {
            return Err(MetadataPermissionsError::DmGroupMetadataForbidden.into());
        }
        let intent_data: Vec<u8> =
            UpdateMetadataIntentData::new_update_group_image_url_square(group_image_url_square)
                .into();
        let intent = super::intents::QueueIntent::metadata_update()
            .data(intent_data)
            .queue(self)?;

        let _ = self.sync_until_intent_resolved(intent.id).await?;
        Ok(())
    }

    /// Retrieves the image URL (square) of the group from the group's mutable metadata extension.
    pub fn group_image_url_square(&self) -> Result<String, GroupError> {
        let mutable_metadata = self.mutable_metadata()?;
        self.required_attribute(&mutable_metadata, MetadataField::GroupImageUrlSquare)
    }

    /// If group is not paused, will return None, otherwise will return the version that the group is paused for
    pub fn paused_for_version(&self) -> Result<Option<String>, GroupError> {
        let paused_for_version = self.context.db().get_group_paused_version(&self.group_id)?;
        Ok(paused_for_version)
    }

    /// Retrieves the admin list of the group from the group's mutable metadata extension.
    pub fn admin_list(&self) -> Result<Vec<String>, GroupError> {
        let mutable_metadata = self.mutable_metadata()?;
        Ok(mutable_metadata.admin_list)
    }

    /// Retrieves the super admin list of the group from the group's mutable metadata extension.
    pub fn super_admin_list(&self) -> Result<Vec<String>, GroupError> {
        let mutable_metadata = self.mutable_metadata()?;
        Ok(mutable_metadata.super_admin_list)
    }

    /// Checks if the given inbox ID is an admin of the group at the most recently synced epoch.
    pub fn is_admin(&self, inbox_id: String) -> Result<bool, GroupError> {
        let mutable_metadata = self.mutable_metadata()?;
        Ok(mutable_metadata.admin_list.contains(&inbox_id))
    }

    /// Checks if the given inbox ID is a super admin of the group at the most recently synced epoch.
    pub fn is_super_admin(&self, inbox_id: String) -> Result<bool, GroupError> {
        let mutable_metadata = self.mutable_metadata()?;
        Ok(mutable_metadata.super_admin_list.contains(&inbox_id))
    }

    /// Checks if the given inbox ID is a super admin of the group at the most recently synced epoch
    pub fn is_super_admin_without_lock(
        &self,
        mls_group: &openmls::group::MlsGroup,
        inbox_id: String,
    ) -> Result<bool, GroupMutableMetadataError> {
        let mutable_metadata = GroupMutableMetadata::try_from(mls_group)?;
        Ok(mutable_metadata.super_admin_list.contains(&inbox_id))
    }

    /// Updates the admin list of the group and syncs the changes to the network.
    #[cfg_attr(any(test, feature = "test-utils"), tracing::instrument(level = "info", fields(who = %self.context.inbox_id()), skip(self)))]
    #[cfg_attr(
        not(any(test, feature = "test-utils")),
        tracing::instrument(level = "trace", skip(self))
    )]
    pub async fn update_admin_list(
        &self,
        action_type: UpdateAdminListType,
        inbox_id: String,
    ) -> Result<(), GroupError> {
        if self.metadata().await?.conversation_type == ConversationType::Dm {
            return Err(MetadataPermissionsError::DmGroupMetadataForbidden.into());
        }
        let intent_action_type = match action_type {
            UpdateAdminListType::Add => AdminListActionType::Add,
            UpdateAdminListType::Remove => AdminListActionType::Remove,
            UpdateAdminListType::AddSuper => AdminListActionType::AddSuper,
            UpdateAdminListType::RemoveSuper => AdminListActionType::RemoveSuper,
        };
        let intent_data: Vec<u8> =
            UpdateAdminListIntentData::new(intent_action_type, inbox_id).into();
        let intent = super::intents::QueueIntent::update_admin_list()
            .data(intent_data)
            .queue(self)?;

        let _ = self.sync_until_intent_resolved(intent.id).await?;
        Ok(())
    }

    /// Find the `inbox_id` of the group member who added the member to the group
    pub fn added_by_inbox_id(&self) -> Result<String, GroupError> {
        let conn = self.context.db();
        let group = conn
            .find_group(&self.group_id)?
            .ok_or_else(|| NotFound::GroupById(self.group_id.clone()))?;
        Ok(group.added_by_inbox_id)
    }

    /// Find the `consent_state` of the group
    pub fn consent_state(&self) -> Result<ConsentState, GroupError> {
        let conn = self.context.db();
        let stored_group = conn
            .find_group(&self.group_id)?
            .ok_or_else(|| NotFound::GroupById(self.group_id.clone()))?;
        let record = conn.get_consent_record(
            hex::encode(self.group_id.clone()),
            xmtp_db::consent_record::ConsentType::ConversationId,
        )?;

        match record {
            Some(rec) => Ok(rec.state),
            None if stored_group.conversation_type == ConversationType::Dm => Ok(stored_group
                .dm_id
                .map(|dm_id| {
                    conn.get_consent_record(
                        dm_id.other_inbox_id(self.context.inbox_id()),
                        xmtp_db::consent_record::ConsentType::InboxId,
                    )
                })
                .transpose()?
                .flatten()
                .map(|record| record.state)
                .unwrap_or(ConsentState::Unknown)),
            None => Ok(ConsentState::Unknown),
        }
    }

    // Returns new consent records. Does not broadcast changes.
    pub fn quietly_update_consent_state(
        &self,
        state: ConsentState,
        db: &impl DbQuery,
    ) -> Result<Vec<StoredConsentRecord>, GroupError> {
        let consent_record = StoredConsentRecord::new(
            xmtp_db::consent_record::ConsentType::ConversationId,
            state,
            hex::encode(self.group_id.clone()),
        );

        Ok(db.insert_or_replace_consent_records(std::slice::from_ref(&consent_record))?)
    }

    #[tracing::instrument(skip_all, level = "trace")]
    pub fn update_consent_state(&self, state: ConsentState) -> Result<(), GroupError> {
        let db = self.context.db();
        let mut changed_records = self.quietly_update_consent_state(state, &db)?;

        if let Some(dm_id) = db
            .find_group(&self.group_id)?
            .and_then(|group| {
                (group.conversation_type == ConversationType::Dm)
                    .then_some(group.dm_id)
                    .flatten()
            })
        {
            let inbox_consent = StoredConsentRecord::new(
                xmtp_db::consent_record::ConsentType::InboxId,
                state,
                dm_id.other_inbox_id(self.context.inbox_id()),
            );
            changed_records.extend(
                db.insert_or_replace_consent_records(std::slice::from_ref(&inbox_consent))?,
            );
        }

        let new_records: Vec<crate::worker::device_sync::preference_sync::PreferenceUpdate> =
            changed_records
                .into_iter()
                .map(crate::worker::device_sync::preference_sync::PreferenceUpdate::Consent)
                .collect();

        if !new_records.is_empty() {
            // Dispatch an update event so it can be synced across devices
            let _ = self.context.worker_events().send(
                crate::subscriptions::SyncWorkerEvent::SyncPreferences(new_records.clone()),
            );
            // Broadcast the changes
            let _ = self.context.local_events().send(
                crate::subscriptions::LocalEvents::PreferencesChanged(
                    crate::subscriptions::preference_updates_event(&self.context, new_records),
                ),
            );
        }

        Ok(())
    }

    fn required_attribute(
        &self,
        mutable_metadata: &GroupMutableMetadata,
        field: MetadataField,
    ) -> Result<String, GroupError> {
        mutable_metadata
            .attributes
            .get(&field.to_string())
            .cloned()
            .ok_or_else(|| {
                MetadataPermissionsError::from(GroupMutableMetadataError::MissingExtension).into()
            })
    }
}
