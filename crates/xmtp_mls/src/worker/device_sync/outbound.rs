use super::{
    ArchiveOptions, BackupElementSelection, DeviceSyncClient, DeviceSyncError, worker::SyncMetric,
};
use crate::{context::XmtpSharedContext, groups::GroupError};
use xmtp_archive::exporter::ArchiveExporter;
use xmtp_common::Event;
use xmtp_macro::log_event;
use xmtp_proto::xmtp::device_sync::content::{
    DeviceSyncKeyType, DeviceSyncReply as DeviceSyncReplyProto,
    DeviceSyncRequest as DeviceSyncRequestProto, device_sync_content::Content as ContentProto,
    device_sync_key_type::Key,
};

const ENC_KEY_SIZE: usize = xmtp_archive::ENC_KEY_SIZE;

impl<Context> DeviceSyncClient<Context>
where
    Context: XmtpSharedContext,
{
    pub(crate) async fn send_archive(
        &self,
        options: &ArchiveOptions,
        sync_group_id: &Vec<u8>,
        pin: &str,
        server_url: &str,
    ) -> Result<(), DeviceSyncError>
    where
        Context::Db: 'static,
    {
        log_event!(
            Event::DeviceSyncArchiveUploadStart,
            self.context.installation_id(),
            group_id = sync_group_id,
            server_url
        );

        let key = xmtp_common::rand_vec::<ENC_KEY_SIZE>();

        tracing::info!("Building the exporter.");
        let db = self.context.db();
        let exporter = ArchiveExporter::new(options.clone(), db, &key);
        let metadata = exporter.metadata().clone();

        tracing::info!("Uploading the archive.");
        let url = format!("{server_url}/upload");
        let response = exporter.post_to_url(&url).await?;

        let reply = DeviceSyncReplyProto {
            encryption_key: Some(DeviceSyncKeyType {
                key: Some(Key::Aes256Gcm(key)),
            }),
            request_id: pin.to_string(),
            url: format!("{server_url}/files/{response}"),
            metadata: Some(metadata),
            ..Default::default()
        };

        tracing::info!("Sending sync request reply message.");
        self.send_device_sync_message(ContentProto::Reply(reply))
            .await?;

        if options.elements.contains(&BackupElementSelection::Consent) {
            self.metrics
                .increment_metric(SyncMetric::ConsentPayloadSent);
        }
        if options.elements.contains(&BackupElementSelection::Messages) {
            self.metrics
                .increment_metric(SyncMetric::MessagesPayloadSent);
        }
        self.metrics.increment_metric(SyncMetric::PayloadSent);

        log_event!(
            Event::DeviceSyncArchiveUploadComplete,
            self.context.installation_id(),
            group_id = sync_group_id,
        );

        Ok(())
    }

    pub async fn send_sync_request(
        &self,
        options: ArchiveOptions,
        server_url: impl ToString,
    ) -> Result<(), crate::client::ClientError> {
        let sync_group = self.get_sync_group().await?;
        sync_group
            .sync_with_conn()
            .await
            .map_err(GroupError::from)?;

        let request = DeviceSyncRequestProto {
            pin: xmtp_common::rand_string::<5>(),
            options: Some(options.into()),
            server_url: server_url.to_string(),
            #[allow(deprecated)]
            deprecated_kind: 0,
        };

        self.send_device_sync_message(ContentProto::Request(request))
            .await?;

        self.metrics.increment_metric(SyncMetric::RequestSent);
        log_event!(
            Event::DeviceSyncSentSyncRequest,
            self.context.installation_id(),
            group_id = sync_group.group_id
        );

        Ok(())
    }

    pub async fn send_sync_archive(
        &self,
        options: &ArchiveOptions,
        server_url: &str,
        pin: &str,
    ) -> Result<(), crate::client::ClientError>
    where
        Context::Db: 'static,
    {
        let sync_group = self.get_sync_group().await?;
        sync_group
            .sync_with_conn()
            .await
            .map_err(GroupError::from)?;

        self.send_archive(options, &sync_group.group_id, pin, server_url)
            .await
            .map_err(|e| GroupError::DeviceSync(Box::new(e)))?;

        Ok(())
    }
}
