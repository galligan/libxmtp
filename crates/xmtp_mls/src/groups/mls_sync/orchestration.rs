//! Top-level orchestration for a full group sync pass.
//!
//! The orchestration layer intentionally keeps publishing, receiving, and
//! post-commit work loosely coupled in the returned `SyncSummary`: one phase
//! can fail without hiding useful work completed by the others.

use super::*;

impl<Context> MlsGroup<Context>
where
    Context: XmtpSharedContext,
{
    /// Run one best-effort sync cycle for this group and any stitched DMs.
    ///
    /// Stitched DMs are synced first so their transcript state is current
    /// before the primary group folds any mirrored updates into its own view.
    #[tracing::instrument]
    pub async fn sync(&self) -> Result<SyncSummary, GroupError> {
        let conn = self.context.db();

        let epoch = self.epoch().await?;
        tracing::info!(
            inbox_id = self.context.inbox_id(),
            installation_id = %self.context.installation_id(),
            group_id = self.group_id.short_hex(),
            "[{}] syncing group, epoch = {epoch}",
            self.context.inbox_id(),
        );

        // Also sync the "stitched DMs", if any...
        for other_dm in conn.other_dms(&self.group_id)? {
            let other_dm = Self::new_from_arc(
                self.context.clone(),
                other_dm.id,
                other_dm.dm_id.clone(),
                other_dm.conversation_type,
                other_dm.created_at_ns,
            );

            other_dm.sync_with_conn().await?;
            other_dm.maybe_update_installations(None).await?;
        }

        let sync_summary = self.sync_with_conn().await.map_err(GroupError::from)?;
        self.maybe_update_installations(None).await?;
        Ok(sync_summary)
    }

    /// Execute publish, receive, and post-commit work while preserving partial results.
    ///
    /// The returned summary is intentionally lossy in only one direction: it
    /// records every phase outcome we observed so callers can decide whether to
    /// retry, even when one phase failed after another already made progress.
    #[cfg_attr(any(test, feature = "test-utils"), tracing::instrument(fields(who = %self.context.inbox_id())))]
    #[cfg_attr(not(any(test, feature = "test-utils")), tracing::instrument(skip_all))]
    pub async fn sync_with_conn(&self) -> Result<SyncSummary, SyncSummary> {
        let _mutex = self.mutex.lock().await;
        let mut summary = SyncSummary::default();

        if !self.is_active().map_err(SyncSummary::other)? {
            log_event!(
                Event::GroupSyncGroupInactive,
                self.context.installation_id(),
                group_id = self.group_id
            );
            return Err(SyncSummary::other(GroupError::GroupInactive));
        }

        if let Err(e) = self.handle_group_paused() {
            if matches!(e, GroupError::GroupPausedUntilUpdate(_)) {
                // nothing synced
                return Ok(summary);
            } else {
                return Err(SyncSummary::other(e));
            }
        }

        // Even if publish fails, continue to receiving
        let result = self.publish_intents().await;
        if let Err(e) = result {
            tracing::error!("Sync: error publishing intents {e:?}",);
            summary.add_publish_err(e);
        }

        // Even if receiving fails, we continue to post_commit
        // Errors are collected in the summary.
        let result = self.receive().await;
        match result {
            Ok(s) => summary.add_process(s),
            Err(e) => {
                summary.add_other(e);
                // We don't return an error if receive fails, because it's possible this is caused
                // by malicious data sent over the network, or messages from before the user was
                // added to the group
            }
        }

        let result = self.post_commit().await;
        if let Err(e) = result {
            tracing::error!("post commit error {e:?}",);
            summary.add_post_commit_err(e);
        }

        if summary.is_errored() {
            Err(summary)
        } else {
            Ok(summary)
        }
    }
}
