use super::*;
use xmtp_common::{MaybeSend, MaybeSync};
use xmtp_db::StorageError;

pub(super) trait PauseResolutionContext: MaybeSend + MaybeSync {
    fn paused_group_version(&self, group_id: &[u8]) -> Result<Option<String>, GroupError>;
    fn unpause_group(&self, group_id: &[u8]) -> Result<(), GroupError>;
    fn current_pkg_version(&self) -> &str;
}

#[derive(Debug)]
pub(super) enum IntentResolutionStatus {
    Processed,
    Deleted,
    Error {
        kind: IntentKind,
    },
    Pending {
        state: IntentState,
        kind: IntentKind,
    },
}

pub(super) trait IntentResolutionQueryContext: MaybeSend + MaybeSync {
    fn latest_resolvable_intent_id(&self, group_id: &[u8]) -> Result<Option<ID>, StorageError>;
    fn intent_resolution_status(
        &self,
        intent_id: &ID,
    ) -> Result<IntentResolutionStatus, StorageError>;
}

impl<Context> PauseResolutionContext for Context
where
    Context: XmtpSharedContext,
{
    fn paused_group_version(&self, group_id: &[u8]) -> Result<Option<String>, GroupError> {
        Ok(self.db().get_group_paused_version(group_id)?)
    }

    fn unpause_group(&self, group_id: &[u8]) -> Result<(), GroupError> {
        Ok(self.db().unpause_group(group_id)?)
    }

    fn current_pkg_version(&self) -> &str {
        self.version_info().pkg_version()
    }
}

impl<Context> IntentResolutionQueryContext for Context
where
    Context: XmtpSharedContext,
{
    fn latest_resolvable_intent_id(&self, group_id: &[u8]) -> Result<Option<ID>, StorageError> {
        Ok(self
            .db()
            .find_group_intents(
                group_id.to_vec(),
                Some(vec![IntentState::ToPublish, IntentState::Published]),
                None,
            )?
            .last()
            .map(|intent| intent.id))
    }

    fn intent_resolution_status(
        &self,
        intent_id: &ID,
    ) -> Result<IntentResolutionStatus, StorageError> {
        Ok(
            match Fetch::<StoredGroupIntent>::fetch(&self.db(), intent_id)? {
                Some(StoredGroupIntent {
                    state: IntentState::Processed,
                    ..
                }) => IntentResolutionStatus::Processed,
                Some(StoredGroupIntent {
                    state: IntentState::Error,
                    kind,
                    ..
                }) => IntentResolutionStatus::Error { kind },
                Some(StoredGroupIntent { state, kind, .. }) => {
                    IntentResolutionStatus::Pending { state, kind }
                }
                None => IntentResolutionStatus::Deleted,
            },
        )
    }
}

pub(super) fn resolve_paused_group<Context>(
    context: &Context,
    group_id: &[u8],
) -> Result<(), GroupError>
where
    Context: PauseResolutionContext,
{
    if let Some(required_min_version_str) = context.paused_group_version(group_id)? {
        tracing::info!(
            "Group is paused until version: {}",
            required_min_version_str
        );
        let current_version_str = context.current_pkg_version();
        let current_version = LibXMTPVersion::parse(current_version_str)?;
        let required_min_version = LibXMTPVersion::parse(&required_min_version_str)?;

        if required_min_version <= current_version {
            tracing::info!(
                "Unpausing group since version requirements are met. \
                 Group ID: {}",
                hex::encode(group_id),
            );
            context.unpause_group(group_id)?;
        } else {
            tracing::warn!(
                "Skipping sync for paused group since version requirements are not met. \
                Group ID: {}, \
                Required version: {}, \
                Current version: {}",
                hex::encode(group_id),
                required_min_version_str,
                current_version_str
            );
            return Err(GroupError::GroupPausedUntilUpdate(required_min_version_str));
        }
    }

    Ok(())
}

impl<Context> MlsGroup<Context>
where
    Context: XmtpSharedContext,
{
    pub(super) fn handle_group_paused(&self) -> Result<(), GroupError> {
        resolve_paused_group(&self.context, &self.group_id)
    }

    #[cfg_attr(any(test, feature = "test-utils"), tracing::instrument(level = "info", fields(who = %self.context.inbox_id()), skip_all))]
    #[cfg_attr(
        not(any(test, feature = "test-utils")),
        tracing::instrument(level = "trace", skip_all)
    )]
    pub(crate) async fn sync_until_last_intent_resolved(&self) -> Result<SyncSummary, GroupError> {
        let Some(intent_id) = self.context.latest_resolvable_intent_id(&self.group_id)? else {
            return Ok(Default::default());
        };

        self.sync_until_intent_resolved(intent_id).await
    }

    /**
     * Sync the group and wait for the intent to be deleted
     * Group syncing may involve picking up messages unrelated to the intent, so simply checking for errors
     * does not give a clear signal as to whether the intent was successfully completed or not.
     *
     * This method will retry up to `xmtp_configuration::MAX_GROUP_SYNC_RETRIES` times.
     */
    #[cfg_attr(any(test, feature = "test-utils"), tracing::instrument(level = "info", fields(who = %self.context.inbox_id()), skip(self)))]
    #[cfg_attr(
        not(any(test, feature = "test-utils")),
        tracing::instrument(level = "trace", skip(self))
    )]
    pub(crate) async fn sync_until_intent_resolved(
        &self,
        intent_id: ID,
    ) -> Result<SyncSummary, GroupError> {
        log_event!(
            Event::GroupSyncStart,
            self.context.installation_id(),
            group_id = self.group_id
        );

        let result = self.sync_until_intent_resolved_inner(intent_id).await;
        let summary = match &result {
            Ok(summary) => Some(summary),
            Err(GroupError::Sync(summary)) => Some(&**summary),
            Err(GroupError::SyncFailedToWait(summary)) => Some(&**summary),
            _ => None,
        };

        log_event!(
            Event::GroupSyncFinished,
            self.context.installation_id(),
            group_id = self.group_id,
            summary = ?summary,
            success = result.is_ok()
        );

        result
    }

    #[cfg_attr(any(test, feature = "test-utils"), tracing::instrument(level = "info", fields(who = %self.context.inbox_id()), skip(self)))]
    #[cfg_attr(
        not(any(test, feature = "test-utils")),
        tracing::instrument(level = "trace", skip(self))
    )]
    async fn sync_until_intent_resolved_inner(
        &self,
        intent_id: ID,
    ) -> Result<SyncSummary, GroupError> {
        let mut summary = SyncSummary::default();

        let time_spent = xmtp_common::time::Instant::now();
        let backoff = ExponentialBackoff::builder()
            .duration(Duration::from_millis(SYNC_BACKOFF_WAIT_MS.into()))
            .total_wait_max(Duration::from_secs(SYNC_BACKOFF_TOTAL_WAIT_MAX_SECS.into()))
            .max_jitter(Duration::from_millis(SYNC_JITTER_MS.into()))
            .build();

        // Return the last error to the caller if we fail to sync
        for attempt in 0..MAX_GROUP_SYNC_RETRIES {
            let wait_for = backoff
                .backoff(attempt + 1, time_spent)
                .unwrap_or(Duration::from_millis(50));

            log_event!(
                Event::GroupSyncAttempt,
                self.context.installation_id(),
                group_id = self.group_id,
                attempt,
                backoff = ?wait_for
            );

            match self.sync_with_conn().await {
                Ok(s) => summary.extend(s),
                Err(s) => {
                    tracing::error!("error syncing group {s}");
                    summary.extend(s);
                }
            }
            match self.context.intent_resolution_status(&intent_id) {
                Ok(IntentResolutionStatus::Processed) => {
                    // This is expected, we mark intents as processed on success.
                    return Ok(summary);
                }
                Ok(IntentResolutionStatus::Deleted) => {
                    // This is somewhat expected, we used to delete intents on success.
                    tracing::warn!(
                        "Intent was deleted when it should have been marked as processed.\
                         This is still okay, but unexpected. intent_id: {intent_id}",
                    );
                    return Ok(summary);
                }
                Ok(IntentResolutionStatus::Error { kind }) => {
                    log_event!(
                        Event::GroupSyncIntentErrored,
                        self.context.installation_id(),
                        level = warn,
                        group_id = self.group_id, intent_id = intent_id,
                        summary = ?summary, intent_kind = ?kind
                    );
                    return Err(GroupError::from(summary));
                }
                Ok(IntentResolutionStatus::Pending { state, kind }) => {
                    log_event!(
                        Event::GroupSyncIntentRetry,
                        self.context.installation_id(),
                        level = warn, group_id = self.group_id,
                        intent_id = intent_id, state = ?state, intent_kind = ?kind
                    );
                }
                Err(err) => {
                    tracing::error!("database error fetching intent {err:?}");
                    summary.add_other(GroupError::Storage(err));
                }
            };
            if attempt + 1 < MAX_GROUP_SYNC_RETRIES {
                xmtp_common::time::sleep(wait_for).await;
            }
        }
        Err(GroupError::SyncFailedToWait(Box::new(summary)))
    }
}
