use super::{
    DeviceSyncError,
    preference_sync::PreferenceUpdate,
    worker::{SyncMetric, SyncWorker},
};
use crate::{context::XmtpSharedContext, subscriptions::SyncWorkerEvent};
use std::time::Duration;
use tracing::instrument;
use xmtp_common::Event;
use xmtp_db::prelude::*;
use xmtp_macro::log_event;

impl<Context> SyncWorker<Context>
where
    Context: XmtpSharedContext + 'static,
{
    pub(super) async fn run(&mut self) -> Result<(), DeviceSyncError> {
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
