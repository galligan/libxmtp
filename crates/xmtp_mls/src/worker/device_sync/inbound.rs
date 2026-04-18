use super::{
    DeviceSyncClient, DeviceSyncError, IterWithContent, preference_sync::store_preference_updates,
    worker::SyncMetric,
};
use crate::{
    context::XmtpSharedContext, subscriptions::LocalEvents, worker::metrics::WorkerMetrics,
};
use xmtp_common::Event;
use xmtp_db::group_message::StoredGroupMessage;
use xmtp_db::prelude::*;
use xmtp_db::tasks::NewTask;
use xmtp_macro::log_event;
use xmtp_proto::xmtp::device_sync::content::{
    DeviceSyncAcknowledge, PreferenceUpdates as PreferenceUpdatesProto,
    device_sync_content::Content as ContentProto,
};
use xmtp_proto::xmtp::mls::database::{SendSyncArchive, Task};

const MAX_ATTEMPTS: i32 = 3;

impl<Context> DeviceSyncClient<Context>
where
    Context: XmtpSharedContext,
{
    pub(super) async fn process_sync_group_messages(
        &self,
        handle: &WorkerMetrics<SyncMetric>,
        messages: Vec<StoredGroupMessage>,
    ) -> Result<(), DeviceSyncError>
    where
        Context::Db: 'static,
    {
        let installation_id = self.installation_id();

        for (msg, content) in messages.clone().iter_with_content() {
            let is_external = msg.sender_installation_id != installation_id;

            let msg_type = match &content {
                ContentProto::Request(_) => "Request",
                ContentProto::Reply(_) => "Reply",
                ContentProto::PreferenceUpdates(_) => "PreferenceUpdates",
                ContentProto::Acknowledge(_) => "Acknowledge",
            };

            log_event!(
                Event::DeviceSyncProcessingMessages,
                self.context.installation_id(),
                msg_type,
                external = is_external,
                msg_id = #msg.id,
                group_id = msg.group_id
            );

            if let Err(err) = self.process_message(handle, &msg, content).await {
                log_event!(
                    Event::DeviceSyncMessageProcessingError,
                    self.context.installation_id(),
                    err = %err,
                    msg_id = #msg.id
                );
                self.context
                    .db()
                    .increment_device_sync_msg_attempt(&msg.id, MAX_ATTEMPTS)?;
            } else {
                self.context
                    .db()
                    .mark_device_sync_msg_as_processed(&msg.id)?;
            }
        }

        Ok(())
    }

    async fn process_message(
        &self,
        handle: &WorkerMetrics<SyncMetric>,
        msg: &StoredGroupMessage,
        content: ContentProto,
    ) -> Result<(), DeviceSyncError>
    where
        Context::Db: 'static,
    {
        let conn = self.context.db();
        let installation_id = self.context.installation_id();
        let is_external = msg.sender_installation_id != installation_id;

        match content {
            ContentProto::Request(request) => {
                if !is_external {
                    return Ok(());
                }

                self.context.task_channels().send(
                    NewTask::builder()
                        .originating_message_originator_id(msg.originator_id as i32)
                        .originating_message_sequence_id(msg.sequence_id)
                        .build(Task {
                            task: Some(
                                xmtp_proto::xmtp::mls::database::task::Task::SendSyncArchive(
                                    SendSyncArchive {
                                        options: request.options,
                                        pin: Some(request.pin),
                                        sync_group_id: msg.group_id.clone(),
                                        server_url: request.server_url,
                                    },
                                ),
                            ),
                        })?,
                );

                self.context
                    .db()
                    .mark_device_sync_msg_as_processed(&msg.id)?;

                handle.increment_metric(SyncMetric::PayloadTaskScheduled);
            }
            ContentProto::Reply(reply) => {
                if !is_external {
                    return Ok(());
                }

                if self.is_reply_requested_by_installation(&reply).await? {
                    self.process_archive(msg, reply).await.inspect_err(|err| {
                        log_event!(
                            Event::DeviceSyncArchiveImportFailure,
                            self.context.installation_id(),
                            err = %err
                        )
                    })?;
                } else {
                    log_event!(
                        Event::DeviceSyncArchiveNotRequested,
                        self.context.installation_id()
                    );
                }

                handle.increment_metric(SyncMetric::PayloadProcessed);
            }
            ContentProto::PreferenceUpdates(PreferenceUpdatesProto { updates }) => {
                if is_external {
                    tracing::info!("Incoming preference updates: {updates:?}");
                }
                tracing::info!(
                    "{} storing preference updates",
                    self.context.installation_id()
                );
                let updated = store_preference_updates(updates.clone(), &conn, handle)?;
                if !updated.is_empty() {
                    let _ = self
                        .context
                        .local_events()
                        .send(LocalEvents::PreferencesChanged(updated));
                }
            }
            ContentProto::Acknowledge(DeviceSyncAcknowledge { .. }) => {
                return Ok(());
            }
        }

        Ok(())
    }
}
