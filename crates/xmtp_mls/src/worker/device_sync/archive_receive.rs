use super::{
    AvailableArchive, DeviceSyncClient, DeviceSyncError, IterWithContent,
    archive::insert_importer,
    catalog::{find_requested_archive_reply, list_available_archives_from_db},
};
use crate::context::XmtpSharedContext;
use futures::StreamExt;
use tokio_util::compat::TokioAsyncReadCompatExt;
use xmtp_archive::ArchiveImporter;
use xmtp_common::Event;
use xmtp_db::group_message::{MsgQueryArgs, StoredGroupMessage};
use xmtp_macro::log_event;
use xmtp_proto::{
    ConversionError,
    xmtp::device_sync::{
        BackupElementSelection as BackupElementSelectionProto,
        content::{
            DeviceSyncKeyType, DeviceSyncReply as DeviceSyncReplyProto,
            DeviceSyncRequest as DeviceSyncRequestProto,
            device_sync_content::Content as ContentProto, device_sync_key_type::Key,
        },
    },
};

impl<Context> DeviceSyncClient<Context>
where
    Context: XmtpSharedContext,
{
    pub(in crate::worker::device_sync) async fn is_reply_requested_by_installation(
        &self,
        reply: &DeviceSyncReplyProto,
    ) -> Result<bool, DeviceSyncError> {
        let sync_group = self.get_sync_group().await?;
        let messages = sync_group.find_messages(&MsgQueryArgs::default())?;

        for (msg, content) in messages.iter_with_content() {
            if let ContentProto::Request(DeviceSyncRequestProto { pin, .. }) = content
                && *pin == reply.request_id
                && msg.sender_installation_id == self.installation_id()
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Processes sync archive with a matching pin. If no pin is provided, will process latest archive.
    pub async fn process_archive_with_pin(&self, pin: Option<&str>) -> Result<(), DeviceSyncError>
    where
        Context::Db: 'static,
    {
        let conn = self.context.db();
        if let Some((msg, reply)) = find_requested_archive_reply(&conn, pin)? {
            return self.process_archive(&msg, reply).await;
        }

        Err(DeviceSyncError::MissingPayload(pin.map(str::to_string)))
    }

    pub fn list_available_archives(
        &self,
        days_cutoff: i64,
    ) -> Result<Vec<AvailableArchive>, DeviceSyncError> {
        list_available_archives_from_db(&self.context.db(), days_cutoff)
    }

    pub(in crate::worker::device_sync) async fn process_archive(
        &self,
        msg: &StoredGroupMessage,
        reply: DeviceSyncReplyProto,
    ) -> Result<(), DeviceSyncError> {
        log_event!(
            Event::DeviceSyncArchiveProcessingStart,
            self.context.installation_id(),
            msg_id = #msg.id,
            group_id = msg.group_id
        );
        if reply.kind() != BackupElementSelectionProto::Unspecified {
            log_event!(Event::DeviceSyncV1Archive, self.context.installation_id());
            return Ok(());
        }

        self.welcome_service.sync_welcomes().await?;

        log_event!(
            Event::DeviceSyncArchiveDownloading,
            self.context.installation_id()
        );
        let response = reqwest::Client::new().get(reply.url).send().await?;
        if let Err(err) = response.error_for_status_ref() {
            log_event!(
                Event::DeviceSyncPayloadDownloadFailure,
                self.context.installation_id(),
                status = %response.status(),
                err = %err
            );
            return Err(DeviceSyncError::Reqwest(err));
        }

        log_event!(
            Event::DeviceSyncArchiveImportStart,
            self.context.installation_id()
        );

        let stream = response
            .bytes_stream()
            .map(|result| result.map_err(std::io::Error::other));
        let tokio_reader = tokio_util::io::StreamReader::new(stream);
        let reader = tokio_reader.compat();

        let Some(DeviceSyncKeyType {
            key: Some(Key::Aes256Gcm(key)),
        }) = reply.encryption_key
        else {
            return Err(ConversionError::Unspecified("encryption_key"))?;
        };

        let mut importer = ArchiveImporter::load(Box::pin(reader), &key).await?;

        tracing::info!("Importing the sync payload.");
        insert_importer(&mut importer, &self.context).await?;

        log_event!(
            Event::DeviceSyncArchiveImportSuccess,
            self.context.installation_id()
        );
        Ok(())
    }
}
