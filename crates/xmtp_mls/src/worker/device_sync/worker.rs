use super::{
    ArchiveOptions, BackupElementSelection, DeviceSyncClient, DeviceSyncError,
    preference_sync::PreferenceUpdate,
};
use crate::{
    client::ClientError,
    context::XmtpSharedContext,
    groups::GroupError,
    subscriptions::SyncWorkerEvent,
    worker::{
        BoxedWorker, DynMetrics, MetricsCasting, Worker, WorkerFactory, WorkerKind, WorkerResult,
        metrics::WorkerMetrics,
    },
};
use futures::TryFutureExt;
use std::{sync::Arc, time::Duration};
use tokio::sync::{OnceCell, broadcast};
use tracing::instrument;
use xmtp_archive::exporter::ArchiveExporter;
use xmtp_common::Event;
use xmtp_db::prelude::*;
use xmtp_macro::log_event;
use xmtp_proto::xmtp::device_sync::content::{
    DeviceSyncKeyType, DeviceSyncReply as DeviceSyncReplyProto,
    DeviceSyncRequest as DeviceSyncRequestProto, device_sync_content::Content as ContentProto,
    device_sync_key_type::Key,
};

const ENC_KEY_SIZE: usize = xmtp_archive::ENC_KEY_SIZE;

pub struct SyncWorker<Context> {
    client: DeviceSyncClient<Context>,
    receiver: broadcast::Receiver<SyncWorkerEvent>,
    init: OnceCell<()>,
    metrics: Arc<WorkerMetrics<SyncMetric>>,
}

impl<Context> SyncWorker<Context>
where
    Context: XmtpSharedContext + 'static,
{
    pub fn new(context: Context, metrics: Option<DynMetrics>) -> Self {
        let receiver = context.worker_events().subscribe();
        let metrics = metrics
            .and_then(|m| m.as_sync_metrics())
            .unwrap_or(Arc::new(WorkerMetrics::new(context.installation_id())));
        let client = DeviceSyncClient::new(context, metrics.clone());

        Self {
            client,
            receiver,
            init: OnceCell::new(),
            metrics,
        }
    }
}

struct Factory<Context> {
    context: Context,
}

impl<Context> WorkerFactory for Factory<Context>
where
    Context: XmtpSharedContext + 'static,
{
    fn create(&self, metrics: Option<DynMetrics>) -> (BoxedWorker, Option<DynMetrics>) {
        let worker = SyncWorker::new(self.context.clone(), metrics);
        let metrics = worker.metrics.clone();

        (Box::new(worker) as Box<_>, Some(metrics as Arc<_>))
    }

    fn kind(&self) -> WorkerKind {
        WorkerKind::DeviceSync
    }
}

#[xmtp_common::async_trait]
impl<Context> Worker for SyncWorker<Context>
where
    Context: XmtpSharedContext + 'static,
{
    fn kind(&self) -> WorkerKind {
        WorkerKind::DeviceSync
    }

    fn metrics(&self) -> Option<DynMetrics> {
        Some(self.metrics.clone())
    }

    fn factory<C>(context: C) -> impl WorkerFactory + 'static
    where
        C: XmtpSharedContext + 'static,
    {
        Factory { context }
    }

    async fn run_tasks(&mut self) -> WorkerResult<()> {
        self.run().map_err(|e| Box::new(e) as Box<_>).await
    }
}

impl<Context> SyncWorker<Context>
where
    Context: XmtpSharedContext + 'static,
{
    async fn run(&mut self) -> Result<(), DeviceSyncError> {
        self.sync_init().await?;
        self.metrics.increment_metric(SyncMetric::Init);

        let tick_fut = Self::tick(self.client.context.clone());
        let run_fut = self.run_internal();

        tokio::select! {
            _ = tick_fut => Ok(()),
            res = run_fut => res,
        }
    }

    async fn run_internal(&mut self) -> Result<(), DeviceSyncError> {
        while let Ok(event) = self.receiver.recv().await {
            tracing::info!(
                "[{}] New event: {event:?}",
                self.client.context.installation_id()
            );

            match event {
                SyncWorkerEvent::NewSyncGroupFromWelcome(_group_id) => {
                    self.evt_new_sync_group_from_welcome().await?;
                }
                SyncWorkerEvent::NewSyncGroupMsg => {
                    self.evt_new_sync_group_msg(false).await?;
                }
                SyncWorkerEvent::Tick => {
                    self.evt_new_sync_group_msg(true).await?;
                }
                SyncWorkerEvent::SyncPreferences(preference_updates) => {
                    self.evt_sync_preferences(preference_updates).await?;
                }
                SyncWorkerEvent::CycleHMAC => {
                    self.evt_cycle_hmac().await?;
                }
            }
        }
        Ok(())
    }

    async fn tick(ctx: Context) {
        loop {
            xmtp_common::time::sleep(Duration::from_secs(20)).await;

            // We don't need to worry about a mutex lock for device sync
            // to ensure that a sync payload is not being processed by two
            // threads at once because there should only ever be one sync worker
            // and the sync worker processes all events in series.
            let _ = ctx.worker_events().send(SyncWorkerEvent::Tick);
        }
    }

    //// Ideally called when the client is registered.
    //// Will auto-send a sync request if sync group is created.
    #[instrument(level = "trace", skip_all)]
    async fn sync_init(&mut self) -> Result<(), DeviceSyncError> {
        let Self { init, client, .. } = &self;

        init.get_or_try_init(|| async {
            let conn = self.client.context.db();
            log_event!(
                Event::DeviceSyncInitializing,
                self.client.context.installation_id()
            );

            // The only thing that sync init really does right now is ensures that there's a sync group.
            if conn.primary_sync_group()?.is_none() {
                log_event!(
                    Event::DeviceSyncNoPrimarySyncGroup,
                    self.client.context.installation_id()
                );
                let sync_group = client.get_sync_group().await?;
                log_event!(
                    Event::DeviceSyncCreatedPrimarySyncGroup,
                    self.client.context.installation_id(),
                    group_id = sync_group.group_id
                );
            }

            log_event!(
                Event::DeviceSyncInitializingFinished,
                self.client.context.installation_id()
            );

            Ok(())
        })
        .await
        .copied()
    }

    async fn evt_new_sync_group_from_welcome(&self) -> Result<(), DeviceSyncError> {
        tracing::info!("New sync group from welcome detected.");

        // A new sync group from a welcome indicates a new installation.
        // We need to add that installation to the groups.
        self.client.add_new_installation_to_groups().await?;

        self.metrics
            .increment_metric(SyncMetric::SyncGroupWelcomesProcessed);

        // Cycle the HMAC
        self.client.cycle_hmac().await?;

        Ok(())
    }

    async fn evt_new_sync_group_msg(&self, is_tick: bool) -> Result<(), DeviceSyncError> {
        let unprocessed_messages = self.client.context.db().unprocessed_sync_group_messages()?;

        if !is_tick || !unprocessed_messages.is_empty() {
            tracing::info!("Processing {} messages.", unprocessed_messages.len());
        }

        self.client
            .process_sync_group_messages(&self.metrics, unprocessed_messages)
            .await
    }

    async fn evt_sync_preferences(
        &self,
        updates: Vec<PreferenceUpdate>,
    ) -> Result<(), DeviceSyncError> {
        let updates = self.client.sync_preferences(updates).await?;

        updates.iter().for_each(|update| match update {
            PreferenceUpdate::Consent(_) => self.metrics.increment_metric(SyncMetric::ConsentSent),
            PreferenceUpdate::Hmac { .. } => self.metrics.increment_metric(SyncMetric::HmacSent),
        });
        Ok(())
    }

    async fn evt_cycle_hmac(&self) -> Result<(), DeviceSyncError> {
        self.client.cycle_hmac().await?;
        Ok(())
    }
}

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

        // Generate a random encryption key
        let key = xmtp_common::rand_vec::<ENC_KEY_SIZE>();

        tracing::info!("Building the exporter.");
        // Now we want to create an encrypted stream from our database to the history server.
        //
        // 1. Build the exporter
        let db = self.context.db();
        let exporter = ArchiveExporter::new(options.clone(), db, &key);
        let metadata = exporter.metadata().clone();

        tracing::info!("Uploading the archive.");
        // 5. Make the request
        let url = format!("{server_url}/upload");
        let response = exporter.post_to_url(&url).await?;

        // Build a sync reply message that the new installation will consume
        let reply = DeviceSyncReplyProto {
            encryption_key: Some(DeviceSyncKeyType {
                key: Some(Key::Aes256Gcm(key)),
            }),
            request_id: pin.to_string(),
            url: format!("{server_url}/files/{response}",),
            metadata: Some(metadata),

            // Deprecated fields
            ..Default::default()
        };

        tracing::info!("Sending sync request reply message.");
        // Send the message out over the network
        self.send_device_sync_message(ContentProto::Reply(reply))
            .await?;

        // Update metrics.
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
    ) -> Result<(), ClientError> {
        let sync_group = self.get_sync_group().await?;
        sync_group
            .sync_with_conn()
            .await
            .map_err(GroupError::from)?;

        let request = DeviceSyncRequestProto {
            pin: xmtp_common::rand_string::<5>(),
            options: Some(options.into()),
            server_url: server_url.to_string(),

            // Deprecated fields
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
    ) -> Result<(), ClientError>
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

#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug)]
pub enum SyncMetric {
    Init,
    SyncGroupCreated,
    SyncGroupWelcomesProcessed,
    RequestReceived,
    RequestSent,
    ConsentPayloadSent,
    ConsentPayloadProcessed,
    MessagesPayloadSent,
    MessagesPayloadProcessed,
    PayloadSent,
    PayloadTaskScheduled,
    PayloadProcessed,
    HmacSent,
    HmacReceived,
    ConsentSent,
    ConsentReceived,
}

impl WorkerMetrics<SyncMetric> {
    pub async fn wait_for_init(&self) -> Result<(), xmtp_common::time::Expired> {
        self.register_interest(SyncMetric::Init, 1).wait().await
    }
}
