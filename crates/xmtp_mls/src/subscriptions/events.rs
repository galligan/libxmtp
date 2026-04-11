use super::Result;
use crate::{
    messages::decoded_message::DecodedMessage,
    worker::device_sync::preference_sync::PreferenceUpdate,
};
use futures::{Stream, StreamExt};
use thiserror::Error;
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tracing::instrument;
use xmtp_common::RetryableError;
use xmtp_db::consent_record::StoredConsentRecord;

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
    PreferencesChanged(Vec<PreferenceUpdate>),
    // A message was deleted (contains the decoded message that was deleted).
    MessageDeleted(Box<DecodedMessage>),
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
    pub(in crate::subscriptions) fn group_filter(self) -> Option<Vec<u8>> {
        use LocalEvents::*;

        match self {
            NewGroup(c) => Some(c),
            _ => None,
        }
    }

    pub(in crate::subscriptions) fn consent_filter(self) -> Option<Vec<StoredConsentRecord>> {
        match self {
            Self::PreferencesChanged(updates) => {
                let updates = updates
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
            Self::PreferencesChanged(updates) => Some(updates),
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
