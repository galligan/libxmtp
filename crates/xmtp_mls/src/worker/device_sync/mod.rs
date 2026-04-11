use crate::{
    client::ClientError,
    context::XmtpSharedContext,
    groups::{GroupError, summary::SyncSummary, welcome_sync::WelcomeService},
    mls_store::{MlsStore, MlsStoreError},
    subscriptions::SubscribeError,
    worker::{NeedsDbReconnect, metrics::WorkerMetrics},
};
use prost::Message;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::broadcast::error::RecvError;
use worker::SyncMetric;
use xmtp_archive::{ArchiveError, BackupMetadata};
use xmtp_common::ErrorCode;
use xmtp_common::RetryableError;
use xmtp_db::{NotFound, StorageError, group_message::StoredGroupMessage};
use xmtp_db::{XmtpDb, prelude::*};
use xmtp_id::{InboxIdRef, associations::DeserializationError};
use xmtp_proto::types::InstallationId;
use xmtp_proto::xmtp::{
    device_sync::content::{
        DeviceSyncContent as DeviceSyncContentProto, device_sync_content::Content as ContentProto,
    },
    mls::message_contents::EncodedContent,
};

pub mod archive;
pub(crate) mod archive_receive;
pub(crate) mod catalog;
pub(crate) mod inbound;
pub(crate) mod outbound;
pub mod preference_sync;
pub(crate) mod sync_group;
pub mod worker;

pub use xmtp_archive::archive_options::{ArchiveOptions, BackupElementSelection};

#[cfg(test)]
mod tests;

#[derive(Debug, Error, ErrorCode)]
pub enum DeviceSyncError {
    /// I/O error.
    ///
    /// File system or network I/O failed. May be retryable.
    #[error("IO error: {0}")]
    IO(#[from] std::io::Error),
    /// Serialization error.
    ///
    /// JSON serialization/deserialization failed. Retryable.
    #[error("Serialization/Deserialization Error {0}")]
    Serde(#[from] serde_json::Error),
    #[error(transparent)]
    #[error_code(inherit)]
    ProtoConversion(#[from] xmtp_proto::ConversionError),
    /// AES-GCM encryption error.
    ///
    /// Encryption/decryption of sync payload failed. Retryable.
    #[error("AES-GCM encryption error")]
    AesGcm(#[from] aes_gcm::Error),
    #[error("storage error: {0}")]
    #[error_code(inherit)]
    Storage(#[from] StorageError),
    /// HTTP request error.
    ///
    /// HTTP request for sync payload failed. Retryable.
    #[error("reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),
    /// Type conversion error.
    ///
    /// Internal type conversion failed. Retryable.
    #[error("type conversion error")]
    Conversion,
    /// UTF-8 error.
    ///
    /// String is not valid UTF-8. Retryable.
    #[error("utf-8 error: {0}")]
    UTF8(#[from] std::str::Utf8Error),
    #[error("client error: {0}")]
    #[error_code(inherit)]
    Client(#[from] ClientError),
    #[error("group error: {0}")]
    #[error_code(inherit)]
    Group(#[from] GroupError),
    /// No pending request.
    ///
    /// No pending sync request to reply to. Retryable.
    #[error("no pending request to reply to")]
    NoPendingRequest,
    /// Invalid payload.
    ///
    /// Sync message payload is malformed. Retryable.
    #[error("invalid history message payload")]
    InvalidPayload,
    /// Unspecified sync kind.
    ///
    /// Device sync kind not specified. Not retryable.
    #[error("unspecified device sync kind")]
    UnspecifiedDeviceSyncKind,
    /// Sync payload too old.
    ///
    /// Sync reply is outdated. Retryable.
    #[error("sync reply is too old")]
    SyncPayloadTooOld,
    #[error(transparent)]
    #[error_code(inherit)]
    Subscribe(#[from] SubscribeError),
    /// Bincode error.
    ///
    /// Binary serialization failed. Retryable.
    #[error(transparent)]
    Bincode(#[from] bincode::Error),
    /// Archive error.
    ///
    /// Sync archive operation failed. Retryable.
    #[error(transparent)]
    Archive(#[from] ArchiveError),
    /// Decode error.
    ///
    /// Protobuf decoding failed. Retryable.
    #[error(transparent)]
    Decode(#[from] prost::DecodeError),
    #[error(transparent)]
    #[error_code(inherit)]
    Deserialization(#[from] DeserializationError),
    /// Already acknowledged.
    ///
    /// Sync interaction already acknowledged. Not retryable.
    #[error("Sync interaction is already acknowledged by another installation")]
    AlreadyAcknowledged,
    /// Missing options.
    ///
    /// Sync request options not provided. Retryable.
    #[error("Sync request is missing options")]
    MissingOptions,
    /// Missing sync server URL.
    ///
    /// Sync server URL not configured. Not retryable.
    #[error("Missing sync server url")]
    MissingSyncServerUrl,
    /// Missing sync group.
    ///
    /// Sync group not found. Not retryable.
    #[error("Missing sync group")]
    MissingSyncGroup,
    #[error(transparent)]
    #[error_code(inherit)]
    Db(#[from] xmtp_db::ConnectionError),
    /// Sync summary.
    ///
    /// Sync completed with errors. May be retryable.
    #[error("{}", _0.to_string())]
    Sync(Box<SyncSummary>),
    /// MLS store error.
    ///
    /// OpenMLS key store operation failed. Retryable.
    #[error(transparent)]
    MlsStore(#[from] MlsStoreError),
    /// Receive error.
    ///
    /// Channel receive failed. Retryable.
    #[error(transparent)]
    Recv(#[from] RecvError),
    /// Missing field.
    ///
    /// Required field not present. Retryable.
    #[error("Missing Field: {0:?} {1}")]
    MissingField(MissingField, String),
    /// Missing payload.
    ///
    /// Sync payload not found for PIN. Retryable.
    #[error("Could not find payload with pin {0:?}")]
    MissingPayload(Option<String>),
}

#[derive(Debug)]
pub enum MissingField {
    Conversation(ConversationField),
}
#[derive(Debug)]
pub enum ConversationField {
    DmId,
}

impl From<SyncSummary> for DeviceSyncError {
    fn from(value: SyncSummary) -> Self {
        DeviceSyncError::Sync(Box::new(value))
    }
}

impl NeedsDbReconnect for DeviceSyncError {
    fn needs_db_reconnect(&self) -> bool {
        match self {
            Self::Client(s) => s.db_needs_connection(),
            _ => false,
        }
    }
}

impl RetryableError for DeviceSyncError {
    fn is_retryable(&self) -> bool {
        !matches!(
            self,
            Self::AlreadyAcknowledged
                | Self::MissingSyncGroup
                | Self::MissingSyncServerUrl
                | Self::UnspecifiedDeviceSyncKind
        )
    }
}

impl From<NotFound> for DeviceSyncError {
    fn from(value: NotFound) -> Self {
        DeviceSyncError::Storage(StorageError::NotFound(value))
    }
}

#[derive(Clone)]
pub struct DeviceSyncClient<Context> {
    pub(crate) context: Context,
    pub(crate) welcome_service: WelcomeService<Context>,
    pub(crate) mls_store: MlsStore<Context>,
    pub(crate) metrics: Arc<WorkerMetrics<SyncMetric>>,
}

impl<Context: XmtpSharedContext> DeviceSyncClient<Context> {
    pub fn new(context: Context, metrics: Arc<WorkerMetrics<SyncMetric>>) -> Self {
        Self {
            context: context.clone(),
            welcome_service: WelcomeService::new(context.clone()),
            mls_store: MlsStore::new(context),
            metrics,
        }
    }
}

impl<Context> DeviceSyncClient<Context>
where
    Context: XmtpSharedContext,
{
    pub fn inbox_id(&self) -> InboxIdRef<'_> {
        self.context.identity().inbox_id()
    }

    pub fn installation_id(&self) -> InstallationId {
        self.context.installation_id()
    }

    pub fn db(&self) -> <Context::Db as XmtpDb>::DbQuery {
        self.context.db()
    }

    /// Blocks until the sync worker notifies that it is initialized and running.
    pub async fn wait_for_sync_worker_init(&self) -> Result<(), xmtp_common::time::Expired> {
        self.metrics.wait_for_init().await
    }
}

pub trait IterWithContent<A, B> {
    fn iter_with_content(self) -> impl DoubleEndedIterator<Item = (A, B)>;
}

impl IterWithContent<StoredGroupMessage, ContentProto> for Vec<StoredGroupMessage> {
    fn iter_with_content(
        self,
    ) -> impl DoubleEndedIterator<Item = (StoredGroupMessage, ContentProto)> {
        self.into_iter().flat_map(|msg| {
            let result = (|| {
                let encoded_content = EncodedContent::decode(&*msg.decrypted_message_bytes).ok()?;
                let content = DeviceSyncContentProto::decode(&*encoded_content.content).ok()?;
                content.content.map(|c| (msg, c))
            })();

            result.into_iter()
        })
    }
}

pub struct AvailableArchive {
    pub pin: String,
    pub metadata: BackupMetadata,
    pub sent_by_installation: Vec<u8>,
}
