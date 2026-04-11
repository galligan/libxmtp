use super::DeviceSyncClient;
use crate::{
    context::XmtpSharedContext,
    subscriptions::SyncWorkerEvent,
    worker::{
        BoxedWorker, DynMetrics, MetricsCasting, Worker, WorkerFactory, WorkerKind, WorkerResult,
        metrics::WorkerMetrics,
    },
};
use futures::TryFutureExt;
use std::sync::Arc;
use tokio::sync::{OnceCell, broadcast};

pub struct SyncWorker<Context> {
    pub(super) client: DeviceSyncClient<Context>,
    pub(super) receiver: broadcast::Receiver<SyncWorkerEvent>,
    pub(super) init: OnceCell<()>,
    pub(super) metrics: Arc<WorkerMetrics<SyncMetric>>,
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

impl<Context> SyncWorker<Context> where Context: XmtpSharedContext + 'static {}

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
