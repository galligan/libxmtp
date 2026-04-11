pub(crate) use stream_conversations::WelcomeOrGroup;

pub(crate) mod d14n_compat;
mod events;
mod facade;
pub mod process_message;
pub mod process_welcome;
mod stream_all;
mod stream_conversations;
pub mod stream_messages;
pub(crate) use process_welcome::ProcessWelcomeResult;
pub(crate) use stream_all::StreamAllMessages;

use crate::groups::{GroupError, mls_sync::GroupMessageProcessingError};
pub(crate) use events::{LocalEventError, LocalEvents, StreamMessages, SyncWorkerEvent};
use xmtp_common::{ErrorCode, RetryableError, retryable};
use xmtp_db::{NotFound, StorageError};

pub(crate) type Result<T> = std::result::Result<T, SubscribeError>;

#[derive(thiserror::Error, Debug, ErrorCode)]
pub enum SubscribeError {
    /// Group error.
    ///
    /// Group operation failed during subscription. May be retryable.
    #[error(transparent)]
    Group(#[from] Box<GroupError>),
    /// Not found.
    ///
    /// Subscribed resource not found. Retryable.
    #[error(transparent)]
    NotFound(#[from] NotFound),
    /// Group message not found.
    ///
    /// Expected message missing from database. Retryable.
    // TODO: Add this to `NotFound`
    #[error("group message expected in database but is missing")]
    GroupMessageNotFound,
    /// Receive group error.
    ///
    /// Processing streamed group message failed. May be retryable.
    #[error("processing group message in stream: {0}")]
    ReceiveGroup(#[from] Box<GroupMessageProcessingError>),
    /// Storage error.
    ///
    /// Database operation failed. May be retryable.
    #[error(transparent)]
    Storage(#[from] StorageError),
    /// Decode error.
    ///
    /// Protobuf decoding failed. Not retryable.
    #[error(transparent)]
    Decode(#[from] prost::DecodeError),
    /// Message stream error.
    ///
    /// Message stream failed. Retryable.
    #[error(transparent)]
    MessageStream(#[from] stream_messages::MessageStreamError),
    /// Conversation stream error.
    ///
    /// Conversation stream failed. Retryable.
    #[error(transparent)]
    ConversationStream(#[from] stream_conversations::ConversationStreamError),
    /// API client error.
    ///
    /// Network request failed. Retryable.
    #[error(transparent)]
    ApiClient(#[from] xmtp_api::ApiError),
    /// Boxed error.
    ///
    /// Wrapped dynamic error. May be retryable.
    #[error("{0}")]
    BoxError(Box<dyn RetryableError>),
    /// Database connection error.
    ///
    /// Database connection failed. Retryable.
    #[error(transparent)]
    Db(#[from] xmtp_db::ConnectionError),
    /// Conversion error.
    ///
    /// Proto conversion failed. Not retryable.
    #[error(transparent)]
    Conversion(#[from] xmtp_proto::ConversionError),
    /// Envelope error.
    ///
    /// Decentralized API envelope error. May be retryable.
    #[error(transparent)]
    Envelope(#[from] xmtp_api_d14n::protocol::EnvelopeError),
}

impl SubscribeError {
    pub fn dyn_err(other: impl RetryableError + 'static) -> Self {
        SubscribeError::BoxError(Box::new(other) as _)
    }
}

impl From<GroupError> for SubscribeError {
    fn from(value: GroupError) -> Self {
        SubscribeError::Group(Box::new(value))
    }
}

impl From<GroupMessageProcessingError> for SubscribeError {
    fn from(value: GroupMessageProcessingError) -> Self {
        SubscribeError::ReceiveGroup(Box::new(value))
    }
}

impl RetryableError for SubscribeError {
    fn is_retryable(&self) -> bool {
        use SubscribeError::*;
        match self {
            Group(e) => retryable!(e),
            GroupMessageNotFound => true,
            ReceiveGroup(e) => retryable!(e),
            Storage(e) => retryable!(e),
            Decode(_) => false,
            NotFound(e) => retryable!(e),
            MessageStream(e) => retryable!(e),
            ConversationStream(e) => retryable!(e),
            ApiClient(e) => retryable!(e),
            BoxError(e) => retryable!(e),
            Db(c) => retryable!(c),
            Conversion(c) => retryable!(c),
            Envelope(c) => retryable!(c),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum StreamKind {
    All,
    Conversations,
    Messages,
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::context::XmtpSharedContext;
    use crate::tester;
    use xmtp_api_d14n::protocol::XmtpQuery;

    /// A macro for asserting that a stream yields a specific decrypted message.
    ///
    /// # Example
    /// ```rust
    /// assert_msg!(stream, b"first");
    /// ```
    #[macro_export]
    macro_rules! assert_msg {
        ($stream:expr, $expected:expr) => {
            let next = $stream
                .next()
                .await
                .unwrap()
                .inspect_err(|e| tracing::error!("{}", e.to_string()))
                .unwrap();

            assert_eq!(
                String::from_utf8_lossy(next.decrypted_message_bytes.as_slice()),
                String::from_utf8_lossy($expected.as_bytes())
            );
        };
    }

    /// A macro for asserting that a stream yields a specific decrypted message.
    ///
    /// # Example
    /// ```rust
    /// assert_msg!(stream, b"first");
    /// ```
    #[macro_export]
    macro_rules! assert_msg_exists {
        ($stream:expr) => {
            assert!(
                !$stream
                    .next()
                    .await
                    .unwrap()
                    .unwrap()
                    .decrypted_message_bytes
                    .is_empty()
            );
        };
    }

    #[cfg(not(feature = "d14n"))]
    #[xmtp_common::test(flavor = "multi_thread", worker_threads = 5, unwrap_try = true)]
    async fn test_process_streamed_welcome_message_v3() {
        use prost::Message;

        tester!(alix);
        tester!(bo);

        // Alix creates a group and adds Bo
        let alix_group = alix.create_group(None, None)?;
        alix_group.add_members(&[bo.inbox_id()]).await?;

        // Query the welcome message envelope using query_at
        let envelope = alix
            .context
            .api()
            .query_at(
                xmtp_proto::types::TopicKind::WelcomeMessagesV1
                    .create(bo.context.installation_id()),
                None,
            )
            .await?;

        // Get the welcome messages and encode the first one as V3 protobuf
        let welcomes = envelope.welcome_messages()?;
        assert!(!welcomes.is_empty(), "Should have at least one welcome");

        let welcome = &welcomes[0];
        let v1 = welcome.as_v1().expect("Should be a V1 welcome");

        // Manually construct the protobuf welcome message from V1 fields
        let mut envelope_bytes = Vec::new();
        let proto_welcome = xmtp_proto::xmtp::mls::api::v1::WelcomeMessage {
            version: Some(
                xmtp_proto::xmtp::mls::api::v1::welcome_message::Version::V1(
                    xmtp_proto::xmtp::mls::api::v1::welcome_message::V1 {
                        id: welcome.sequence_id(),
                        created_ns: welcome.timestamp() as u64,
                        installation_key: v1.installation_key.to_vec(),
                        data: v1.data.clone(),
                        hpke_public_key: v1.hpke_public_key.clone(),
                        wrapper_algorithm: v1.wrapper_algorithm as i32,
                        welcome_metadata: v1.welcome_metadata.clone(),
                    },
                ),
            ),
        };
        proto_welcome.encode(&mut envelope_bytes)?;

        // Process the streamed welcome message
        let groups = bo.process_streamed_welcome_message(envelope_bytes).await?;

        assert_eq!(groups.len(), 1, "Should have exactly one group");
    }

    #[cfg(feature = "d14n")]
    #[xmtp_common::test(flavor = "multi_thread", worker_threads = 5, unwrap_try = true)]
    async fn test_process_streamed_welcome_message_d14n() {
        use prost::Message;
        use xmtp_api_d14n::protocol::extractors::test_utils::TestEnvelopeBuilder;
        use xmtp_proto::types::TopicKind;

        tester!(alix);
        tester!(bo);

        // Alix creates a group and adds Bo
        let alix_group = alix.create_group(None, None)?;
        alix_group.add_members(&[bo.inbox_id()]).await?;

        // Query the welcome envelope using query_at for D14n format
        let envelope = alix
            .context
            .api()
            .query_at(
                TopicKind::WelcomeMessagesV1.create(bo.context.installation_id()),
                None,
            )
            .await?;

        let client_env = envelope
            .client_envelopes()?
            .into_iter()
            .next()
            .expect("expected at least one welcome envelope");
        let cursor = envelope
            .cursors()?
            .into_iter()
            .next()
            .expect("expected at least one welcome cursor");
        let envelope_bytes = TestEnvelopeBuilder::new()
            .with_cursor(cursor)
            .with_originator_ns(1_000_000)
            .with_client_envelope(client_env)
            .build()
            .encode_to_vec();

        // Process the streamed welcome message
        let groups = bo.process_streamed_welcome_message(envelope_bytes).await?;

        assert_eq!(groups.len(), 1, "Should have exactly one group");
    }
}
