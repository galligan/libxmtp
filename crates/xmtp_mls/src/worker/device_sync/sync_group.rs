use super::{DeviceSyncClient, DeviceSyncError, worker::SyncMetric};
use crate::{
    client::ClientError,
    context::XmtpSharedContext,
    groups::{
        GroupError, MlsGroup, PreconfiguredPolicies, intents::QueueIntent, send_message_opts,
    },
    subscriptions::SyncWorkerEvent,
};
use futures::{StreamExt, TryStreamExt, stream};
use owo_colors::OwoColorize;
use prost::Message;
use std::collections::{HashMap, HashSet};
use tracing::instrument;
use xmtp_common::{NS_IN_DAY, time::now_ns};
use xmtp_content_types::encoded_content_to_bytes;
use xmtp_db::{
    consent_record::ConsentState, group::ConversationType, group::GroupQueryArgs, prelude::*,
};
use xmtp_mls_common::group::GroupMetadataOptions;
use xmtp_proto::xmtp::{
    device_sync::content::{
        DeviceSyncContent as DeviceSyncContentProto, device_sync_content::Content as ContentProto,
    },
    mls::message_contents::{
        ContentTypeId, EncodedContent, PlaintextEnvelope,
        plaintext_envelope::{Content, V1},
    },
};

impl<Context> DeviceSyncClient<Context>
where
    Context: XmtpSharedContext,
{
    #[cfg_attr(any(test, feature = "test-utils"), tracing::instrument(level = "info", fields(who = self.context.inbox_id()), skip(self)))]
    #[cfg_attr(
        not(any(test, feature = "test-utils")),
        tracing::instrument(level = "trace", skip(self))
    )]
    pub(super) async fn send_device_sync_message(
        &self,
        content: ContentProto,
    ) -> Result<Vec<u8>, ClientError> {
        let content = DeviceSyncContentProto {
            content: Some(content),
        };

        let sync_group = self.get_sync_group().await?;

        let msg = format!(
            "[{}] Sending sync message to group {:?}",
            self.context.installation_id(),
            xmtp_common::fmt::debug_hex(&sync_group.group_id)
        );
        tracing::info!("{}", msg.yellow());

        let mut content_bytes = vec![];
        content
            .encode(&mut content_bytes)
            .map_err(|err| ClientError::Generic(err.to_string()))?;

        let encoded_content = EncodedContent {
            r#type: Some(ContentTypeId {
                authority_id: "xmtp.org".to_string(),
                type_id: "application/x-protobuf".to_string(),
                version_major: 1,
                version_minor: 0,
            }),
            parameters: HashMap::new(),
            fallback: None,
            compression: None,
            content: content_bytes,
        };
        let content_bytes = encoded_content_to_bytes(encoded_content);

        let message_id = sync_group.prepare_message(
            &content_bytes,
            send_message_opts::SendMessageOpts { should_push: false },
            |now| PlaintextEnvelope {
                content: Some(Content::V1(V1 {
                    content: content_bytes.clone(),
                    idempotency_key: now.to_string(),
                })),
            },
        )?;

        sync_group.sync_until_last_intent_resolved().await?;

        let _ = self
            .context
            .worker_events()
            .send(SyncWorkerEvent::NewSyncGroupMsg);

        Ok(message_id)
    }

    #[instrument(level = "trace", skip_all)]
    pub async fn get_sync_group(&self) -> Result<MlsGroup<Context>, GroupError> {
        let db = self.context.db();
        let sync_group = match db.primary_sync_group()? {
            Some(sync_group) => self.mls_store.group(&sync_group.id)?,
            None => {
                let sync_group = MlsGroup::create_and_insert(
                    self.context.clone(),
                    ConversationType::Sync,
                    PreconfiguredPolicies::default().to_policy_set(),
                    GroupMetadataOptions::default(),
                    None,
                )?;
                tracing::info!(
                    "[{}] Creating sync group: {}",
                    hex::encode(self.context.installation_id()),
                    hex::encode(&sync_group.group_id)
                );
                sync_group.add_missing_installations().await?;
                sync_group.sync_with_conn().await?;

                self.metrics.increment_metric(SyncMetric::SyncGroupCreated);

                sync_group
            }
        };

        Ok(sync_group)
    }

    #[cfg_attr(
        any(test, feature = "test-utils"),
        tracing::instrument(level = "info", skip_all)
    )]
    pub async fn add_new_installation_to_groups(&self) -> Result<(), DeviceSyncError> {
        let groups = self.mls_store.find_groups(GroupQueryArgs {
            last_activity_after_ns: Some(now_ns() - NS_IN_DAY * 90),
            consent_states: Some(vec![ConsentState::Allowed, ConsentState::Unknown]),
            ..Default::default()
        })?;

        let groups = HashSet::from_iter(groups);
        let intents = QueueIntent::update_group_membership()
            .queue_for_each(groups, move |group| async move {
                let intent = group.get_membership_update_intent(&[], &[]).await?;
                let intent: Vec<u8> = intent.into();
                Ok::<_, GroupError>(intent)
            })
            .await?;

        let context = &self.context;
        stream::iter(intents)
            .map(Ok::<_, GroupError>)
            .try_for_each_concurrent(10, |intent| async move {
                let (group, _) = MlsGroup::new_cached(context, &intent.group_id)?;
                group.sync_until_intent_resolved(intent.id).await?;
                Ok(())
            })
            .await?;

        Ok(())
    }
}
