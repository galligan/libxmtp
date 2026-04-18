use super::Result;
use crate::{
    context::XmtpSharedContext, messages::decoded_message::DecodedMessage,
    worker::device_sync::preference_sync::PreferenceUpdate,
};
use futures::{Stream, StreamExt};
use std::collections::{HashMap, HashSet};
use thiserror::Error;
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tracing::instrument;
use xmtp_common::RetryableError;
use xmtp_db::{
    consent_record::{ConsentType, StoredConsentRecord},
    group::{ConversationType, DmIdExt},
    encrypted_store::refresh_state::EntityKind,
    prelude::{QueryDms, QueryRefreshState},
};
use xmtp_mls_common::group_metadata::DmMembers;
use xmtp_proto::types::GlobalCursor;

#[derive(Debug, Error)]
pub enum LocalEventError {
    #[error("Unable to send event: {0}")]
    Send(String),
}

impl RetryableError for LocalEventError {
    fn is_retryable(&self) -> bool {
        true
    }
}

/// Events local to this client are broadcast across all senders/receivers of streams.
#[derive(Debug, Clone)]
pub enum LocalEvents {
    // A new group was created.
    NewGroup(Vec<u8>),
    PreferencesChanged(PreferenceUpdatesEvent),
    // A message was deleted (contains the decoded message that was deleted).
    MessageDeleted(Box<DecodedMessage>),
}

#[derive(Debug, Clone)]
pub struct PreferenceUpdatesEvent {
    pub updates: Vec<PreferenceUpdate>,
    pub conversation_cursors: HashMap<Vec<u8>, Option<GlobalCursor>>,
    pub conversation_replay_after_ns: HashMap<Vec<u8>, Option<i64>>,
}

pub(crate) fn preference_updates_event<Context: XmtpSharedContext>(
    context: &Context,
    updates: Vec<PreferenceUpdate>,
) -> PreferenceUpdatesEvent {
    let mut conversation_ids = Vec::new();
    let mut replay_after_by_group = HashMap::new();
    let mut seen_group_ids = HashSet::new();

    for update in &updates {
        let PreferenceUpdate::Consent(record) = update else {
            continue;
        };

        for group_id in affected_conversation_ids_for_preference(context, record) {
            if seen_group_ids.insert(group_id.clone()) {
                conversation_ids.push(group_id.clone());
            }

            let replay_after_ns = if record.state == xmtp_db::consent_record::ConsentState::Allowed
            {
                Some(record.consented_at_ns)
            } else {
                None
            };

            if replay_after_ns.is_some() || !replay_after_by_group.contains_key(&group_id) {
                replay_after_by_group.insert(group_id, replay_after_ns);
            }
        }
    }

    let current_cursors = context
        .db()
        .get_last_cursor_for_ids(
            &conversation_ids,
            &[EntityKind::ApplicationMessage, EntityKind::CommitMessage],
        )
        .unwrap_or_else(|err| {
            tracing::warn!(
                error = %err,
                "failed to capture conversation cursor snapshot for preference update event"
            );
            HashMap::new()
        });

    let mut conversation_cursors = HashMap::new();
    let mut conversation_replay_after_ns = HashMap::new();
    for group_id in conversation_ids {
        conversation_cursors.insert(
            group_id.clone(),
            current_cursors.get(group_id.as_slice()).cloned(),
        );
        conversation_replay_after_ns.insert(
            group_id.clone(),
            replay_after_by_group.get(&group_id).cloned().flatten(),
        );
    }

    PreferenceUpdatesEvent {
        updates,
        conversation_cursors,
        conversation_replay_after_ns,
    }
}

fn affected_conversation_ids_for_preference<Context: XmtpSharedContext>(
    context: &Context,
    record: &StoredConsentRecord,
) -> Vec<Vec<u8>> {
    match record.entity_type {
        ConsentType::ConversationId => hex::decode(&record.entity)
            .ok()
            .and_then(|group_id| context.db().fetch_stitched(&group_id).ok().flatten())
            .filter(|group| group.conversation_type != ConversationType::Sync)
            .map(|group| group.id)
            .into_iter()
            .collect(),
        ConsentType::InboxId => context
            .db()
            .find_active_dm_group(DmMembers {
                member_one_inbox_id: context.inbox_id().to_string(),
                member_two_inbox_id: record.entity.clone(),
            })
            .ok()
            .flatten()
            .filter(|group| {
                group.conversation_type == ConversationType::Dm
                    && group
                        .dm_id
                        .as_ref()
                        .is_some_and(|dm_id| dm_id.other_inbox_id(context.inbox_id()) == record.entity)
            })
            .map(|group| vec![group.id])
            .unwrap_or_default(),
    }
}

#[derive(Clone)]
pub enum SyncWorkerEvent {
    NewSyncGroupFromWelcome(Vec<u8>),
    NewSyncGroupMsg,
    // The sync worker will auto-sync these with other devices.
    SyncPreferences(Vec<PreferenceUpdate>),
    CycleHMAC,
    Tick,
}

impl std::fmt::Debug for SyncWorkerEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NewSyncGroupFromWelcome(arg0) => f
                .debug_tuple("NewSyncGroupFromWelcome")
                .field(&hex::encode(arg0))
                .finish(),
            Self::NewSyncGroupMsg => write!(f, "NewSyncGroupMsg"),
            Self::SyncPreferences(arg0) => f.debug_tuple("SyncPreferences").field(arg0).finish(),
            Self::CycleHMAC => write!(f, "CycleHMAC"),
            Self::Tick => write!(f, "Tick"),
        }
    }
}

impl LocalEvents {
    pub(in crate::subscriptions) fn consent_filter(self) -> Option<Vec<StoredConsentRecord>> {
        match self {
            Self::PreferencesChanged(event) => {
                let updates = event
                    .updates
                    .into_iter()
                    .filter_map(|pu| match pu {
                        PreferenceUpdate::Consent(cr) => Some(cr),
                        _ => None,
                    })
                    .collect();
                Some(updates)
            }
            _ => None,
        }
    }

    pub(in crate::subscriptions) fn preference_filter(self) -> Option<Vec<PreferenceUpdate>> {
        match self {
            Self::PreferencesChanged(event) => Some(event.updates),
            _ => None,
        }
    }

    pub(in crate::subscriptions) fn message_deletion_filter(self) -> Option<Box<DecodedMessage>> {
        match self {
            Self::MessageDeleted(message) => Some(message),
            _ => None,
        }
    }
}

pub(crate) trait StreamMessages {
    fn stream_consent_updates(self) -> impl Stream<Item = Result<Vec<StoredConsentRecord>>>;
    fn stream_preference_updates(self) -> impl Stream<Item = Result<Vec<PreferenceUpdate>>>;
    fn stream_message_deletions(self) -> impl Stream<Item = Result<Box<DecodedMessage>>>;
}

impl StreamMessages for broadcast::Receiver<LocalEvents> {
    #[instrument(level = "trace", skip_all)]
    fn stream_consent_updates(self) -> impl Stream<Item = Result<Vec<StoredConsentRecord>>> {
        BroadcastStream::new(self).filter_map(|event| async {
            xmtp_common::optify!(event, "Missed message due to event queue lag")
                .and_then(LocalEvents::consent_filter)
                .map(Result::Ok)
        })
    }

    #[instrument(level = "trace", skip_all)]
    fn stream_preference_updates(self) -> impl Stream<Item = Result<Vec<PreferenceUpdate>>> {
        BroadcastStream::new(self).filter_map(|event| async {
            xmtp_common::optify!(event, "Missed message due to event queue lag")
                .and_then(LocalEvents::preference_filter)
                .map(Result::Ok)
        })
    }

    #[instrument(level = "trace", skip_all)]
    fn stream_message_deletions(self) -> impl Stream<Item = Result<Box<DecodedMessage>>> {
        BroadcastStream::new(self).filter_map(|event| async {
            xmtp_common::optify!(event, "Missed message due to event queue lag")
                .and_then(LocalEvents::message_deletion_filter)
                .map(Result::Ok)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::preference_updates_event;
    use crate::{
        tester,
        worker::device_sync::preference_sync::PreferenceUpdate,
    };
    use xmtp_db::consent_record::{ConsentState, ConsentType, StoredConsentRecord};

    #[xmtp_common::test(unwrap_try = true)]
    async fn test_preference_updates_event_maps_dm_inbox_consent_to_active_conversation() {
        tester!(alix);
        tester!(bo);

        let (dm, _) = alix.test_talk_in_dm_with(&bo).await?;
        let record = StoredConsentRecord::new(
            ConsentType::InboxId,
            ConsentState::Allowed,
            bo.inbox_id().to_string(),
        );

        let event = preference_updates_event(&alix.context, vec![PreferenceUpdate::Consent(record.clone())]);

        assert_eq!(event.conversation_cursors.len(), 1);
        assert_eq!(
            event.conversation_replay_after_ns.get(&dm.group_id),
            Some(&Some(record.consented_at_ns))
        );
        assert!(
            event
                .conversation_cursors
                .get(&dm.group_id)
                .is_some_and(|cursor| cursor.is_some()),
            "DM inbox-id consent should snapshot the active DM cursor for replay gating"
        );
    }

    #[xmtp_common::test(unwrap_try = true)]
    async fn test_preference_updates_event_dedupes_dm_conversation_and_peer_updates() {
        tester!(alix);
        tester!(bo);

        let (dm, _) = alix.test_talk_in_dm_with(&bo).await?;
        let conversation_record = StoredConsentRecord::new(
            ConsentType::ConversationId,
            ConsentState::Denied,
            hex::encode(&dm.group_id),
        );
        let inbox_record = StoredConsentRecord::new(
            ConsentType::InboxId,
            ConsentState::Denied,
            bo.inbox_id().to_string(),
        );

        let event = preference_updates_event(
            &alix.context,
            vec![
                PreferenceUpdate::Consent(conversation_record),
                PreferenceUpdate::Consent(inbox_record),
            ],
        );

        assert_eq!(
            event.conversation_cursors.len(),
            1,
            "dual-written DM consent records should normalize to one logical conversation"
        );
        assert_eq!(
            event.conversation_replay_after_ns.get(&dm.group_id),
            Some(&None),
            "denied DM consent should not request backlog replay"
        );
    }

    #[xmtp_common::test(unwrap_try = true)]
    async fn test_preference_updates_event_ignores_sync_group_conversation_consent() {
        tester!(alix);

        let sync_group = alix.device_sync_client().get_sync_group().await?;
        let sync_record = StoredConsentRecord::new(
            ConsentType::ConversationId,
            ConsentState::Allowed,
            hex::encode(&sync_group.group_id),
        );

        let event =
            preference_updates_event(&alix.context, vec![PreferenceUpdate::Consent(sync_record)]);

        assert!(
            event.conversation_cursors.is_empty(),
            "sync-group consent should not become a user-facing conversation replay event"
        );
        assert!(
            event.conversation_replay_after_ns.is_empty(),
            "sync-group consent should not request replay state for conversation streams"
        );
    }

    #[xmtp_common::test(unwrap_try = true)]
    async fn test_preference_updates_event_ignores_inbox_consent_without_active_dm() {
        tester!(alix);
        tester!(bo);

        let inbox_record = StoredConsentRecord::new(
            ConsentType::InboxId,
            ConsentState::Allowed,
            bo.inbox_id().to_string(),
        );

        let event =
            preference_updates_event(&alix.context, vec![PreferenceUpdate::Consent(inbox_record)]);

        assert!(
            event.conversation_cursors.is_empty(),
            "peer inbox consent without an active DM should not fabricate a conversation event"
        );
        assert!(
            event.conversation_replay_after_ns.is_empty(),
            "peer inbox consent without an active DM should not request replay state"
        );
    }
}
