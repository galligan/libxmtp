use super::{GroupError, MlsGroup};
use crate::context::XmtpSharedContext;
use crate::groups::intents::{QueueIntent, UpdateMetadataIntentData};
use xmtp_db::Fetch;
use xmtp_db::group::StoredGroup;
use xmtp_mls_common::group_metadata::GroupMetadataError;
use xmtp_mls_common::group_mutable_metadata::{
    GroupMutableMetadata, MessageDisappearingSettings, MetadataField,
};

impl<Context> MlsGroup<Context>
where
    Context: XmtpSharedContext,
{
    pub async fn update_conversation_message_disappearing_settings(
        &self,
        settings: MessageDisappearingSettings,
    ) -> Result<(), GroupError> {
        self.ensure_not_paused().await?;

        self.update_conversation_message_disappear_from_ns(settings.from_ns)
            .await?;
        self.update_conversation_message_disappear_in_ns(settings.in_ns)
            .await
    }

    pub async fn remove_conversation_message_disappearing_settings(
        &self,
    ) -> Result<(), GroupError> {
        self.ensure_not_paused().await?;

        self.update_conversation_message_disappearing_settings(
            MessageDisappearingSettings::default(),
        )
        .await
    }

    #[cfg_attr(any(test, feature = "test-utils"), tracing::instrument(level = "info", fields(who = %self.context.inbox_id()), skip(self)))]
    #[cfg_attr(
        not(any(test, feature = "test-utils")),
        tracing::instrument(level = "trace", skip(self))
    )]
    pub(super) async fn update_conversation_message_disappear_from_ns(
        &self,
        expire_from_ms: i64,
    ) -> Result<(), GroupError> {
        self.ensure_not_paused().await?;

        let intent_data: Vec<u8> =
            UpdateMetadataIntentData::new_update_conversation_message_disappear_from_ns(
                expire_from_ms,
            )
            .into();
        let intent = QueueIntent::metadata_update()
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
    pub(super) async fn update_conversation_message_disappear_in_ns(
        &self,
        expire_in_ms: i64,
    ) -> Result<(), GroupError> {
        self.ensure_not_paused().await?;

        let intent_data: Vec<u8> =
            UpdateMetadataIntentData::new_update_conversation_message_disappear_in_ns(expire_in_ms)
                .into();
        let intent = QueueIntent::metadata_update()
            .data(intent_data)
            .queue(self)?;
        let _ = self.sync_until_intent_resolved(intent.id).await?;
        Ok(())
    }

    pub fn conversation_message_disappearing_settings(
        &self,
    ) -> Result<MessageDisappearingSettings, GroupError> {
        let metadata = self.mutable_metadata()?;
        Self::conversation_message_disappearing_settings_from_extensions(&metadata)
    }

    pub fn conversation_message_disappearing_settings_from_extensions(
        mutable_metadata: &GroupMutableMetadata,
    ) -> Result<MessageDisappearingSettings, GroupError> {
        let disappear_from_ns = mutable_metadata
            .attributes
            .get(&MetadataField::MessageDisappearFromNS.to_string());
        let disappear_in_ns = mutable_metadata
            .attributes
            .get(&MetadataField::MessageDisappearInNS.to_string());

        if let (Some(Ok(message_disappear_from_ns)), Some(Ok(message_disappear_in_ns))) = (
            disappear_from_ns.map(|s| s.parse::<i64>()),
            disappear_in_ns.map(|s| s.parse::<i64>()),
        ) {
            Ok(MessageDisappearingSettings::new(
                message_disappear_from_ns,
                message_disappear_in_ns,
            ))
        } else {
            Err(GroupError::MetadataPermissionsError(
                GroupMetadataError::MissingExtension.into(),
            ))
        }
    }

    /// Fetches the message disappearing settings for a given group ID.
    ///
    /// Returns `Some(MessageDisappearingSettings)` if the group exists and has valid settings,
    /// `None` if the group or settings are missing, or `Err(ClientError)` on a database error.
    pub fn disappearing_settings(&self) -> Result<Option<MessageDisappearingSettings>, GroupError> {
        let conn = self.context.db();
        let stored_group: Option<StoredGroup> = conn.fetch(&self.group_id)?;

        let settings = stored_group.and_then(|group| {
            let from_ns = group.message_disappear_from_ns?;
            let in_ns = group.message_disappear_in_ns?;

            Some(MessageDisappearingSettings { from_ns, in_ns })
        });

        Ok(settings)
    }
}
