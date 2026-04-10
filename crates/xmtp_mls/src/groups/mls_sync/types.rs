use super::*;

#[derive(Debug, Error)]
pub enum GroupMessageProcessingError {
    #[error("intent already processed")]
    IntentAlreadyProcessed,
    #[error("message with cursor [{}] for group [{}] already processed", _0.cursor, xmtp_common::fmt::debug_hex(&_0.group_id)
    )]
    MessageAlreadyProcessed(MessageIdentifier),
    #[error("message identifier not found")]
    MessageIdentifierNotFound,
    #[error("welcome with cursor [{0}] already processed")]
    WelcomeAlreadyProcessed(u64),
    #[error("[{message_time_ns:?}] invalid sender with credential: {credential:?}")]
    InvalidSender {
        message_time_ns: u64,
        credential: Vec<u8>,
    },
    #[error("invalid payload")]
    InvalidPayload,
    #[error("storage error: {0}")]
    Storage(#[from] xmtp_db::StorageError),
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error("openmls process message error: {0}")]
    OpenMlsProcessMessage(
        #[from] openmls::prelude::ProcessMessageError<sql_key_store::SqlKeyStoreError>,
    ),
    #[error("merge staged commit: {0}")]
    MergeStagedCommit(#[from] openmls::group::MergeCommitError<sql_key_store::SqlKeyStoreError>),
    #[error("TLS Codec error: {0}")]
    TlsError(#[from] TlsCodecError),
    #[error("unsupported message type: {0:?}")]
    UnsupportedMessageType(Discriminant<ProtocolMessage>),
    #[error("commit validation")]
    CommitValidation(#[from] CommitValidationError),
    #[error("epoch increment not allowed")]
    EpochIncrementNotAllowed,
    #[error("clear pending commit error: {0}")]
    ClearPendingCommit(#[from] sql_key_store::SqlKeyStoreError),
    #[error("Serialization/Deserialization Error {0}")]
    Serde(#[from] serde_json::Error),
    #[error("intent is missing staged_commit field")]
    IntentMissingStagedCommit,
    #[error("encode proto: {0}")]
    EncodeProto(#[from] prost::EncodeError),
    #[error("proto decode error: {0}")]
    DecodeProto(#[from] prost::DecodeError),
    #[error(transparent)]
    Intent(#[from] IntentError),
    #[error(transparent)]
    Codec(#[from] CodecError),
    #[error("wrong credential type")]
    WrongCredentialType(#[from] BasicCredentialError),
    #[error(transparent)]
    ProcessIntent(#[from] ProcessIntentError),
    #[error(transparent)]
    AssociationDeserialization(#[from] xmtp_id::associations::DeserializationError),
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error("Group paused due to minimum protocol version requirement")]
    GroupPaused,
    #[error("Message epoch [{0}] is too old [{1}]")]
    OldEpoch(u64, u64),
    #[error("Message epoch [{0}] is greater than group epoch [{1}]")]
    FutureEpoch(u64, u64),
    #[error(transparent)]
    Db(#[from] xmtp_db::ConnectionError),
    #[error(transparent)]
    Builder(#[from] derive_builder::UninitializedFieldError),
    #[error(transparent)]
    Diesel(#[from] xmtp_db::diesel::result::Error),
    #[error(transparent)]
    EnrichMessage(#[from] EnrichMessageError),
    #[error("pre-commit proposal phase complete, re-queuing intent")]
    PreCommitProposalPhaseComplete,
}

impl RetryableError for GroupMessageProcessingError {
    fn is_retryable(&self) -> bool {
        match self {
            Self::Storage(err) => err.is_retryable(),
            Self::Diesel(err) => err.is_retryable(),
            Self::Identity(err) => err.is_retryable(),
            Self::OpenMlsProcessMessage(err) => err.is_retryable(),
            Self::MergeStagedCommit(err) => err.is_retryable(),
            Self::ProcessIntent(err) => err.is_retryable(),
            Self::CommitValidation(err) => err.is_retryable(),
            Self::ClearPendingCommit(err) => err.is_retryable(),
            Self::Client(err) => err.is_retryable(),
            Self::Db(e) => e.is_retryable(),
            Self::EnrichMessage(e) => e.is_retryable(),
            Self::IntentAlreadyProcessed
            | Self::MessageIdentifierNotFound
            | Self::WrongCredentialType(_)
            | Self::Codec(_)
            | Self::MessageAlreadyProcessed(_)
            | Self::WelcomeAlreadyProcessed(_)
            | Self::InvalidSender { .. }
            | Self::DecodeProto(_)
            | Self::InvalidPayload
            | Self::Intent(_)
            | Self::EpochIncrementNotAllowed
            | Self::EncodeProto(_)
            | Self::IntentMissingStagedCommit
            | Self::Serde(_)
            | Self::AssociationDeserialization(_)
            | Self::TlsError(_)
            | Self::UnsupportedMessageType(_)
            | Self::GroupPaused
            | Self::FutureEpoch(_, _)
            | Self::OldEpoch(_, _)
            | Self::PreCommitProposalPhaseComplete => false,
            Self::Builder(_) => false,
        }
    }
}

impl GroupMessageProcessingError {
    pub(crate) fn commit_result(&self) -> CommitResult {
        match self {
            GroupMessageProcessingError::OpenMlsProcessMessage(
                ProcessMessageError::ValidationError(ValidationError::WrongEpoch),
            ) => CommitResult::WrongEpoch,
            GroupMessageProcessingError::OldEpoch(_, _) => CommitResult::WrongEpoch,
            GroupMessageProcessingError::FutureEpoch(_, _) => CommitResult::WrongEpoch,
            GroupMessageProcessingError::CommitValidation(_) => CommitResult::Invalid,
            GroupMessageProcessingError::OpenMlsProcessMessage(_) => CommitResult::Undecryptable,
            _ => CommitResult::Unknown,
        }
    }
}

#[derive(Debug, Error)]
pub struct IntentResolutionError {
    pub(super) processing_error: GroupMessageProcessingError,
    // The next intent state to transition to, if the error is non-retriable.
    // Should not be used for retryable errors.
    pub(super) next_intent_state: IntentState,
}

impl std::fmt::Display for IntentResolutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "IntentValidationError: {}", self.processing_error)
    }
}

impl RetryableError for IntentResolutionError {
    fn is_retryable(&self) -> bool {
        self.processing_error.is_retryable()
    }
}

#[derive(Debug)]
pub(crate) struct PublishIntentData {
    pub(super) staged_commit: Option<Vec<u8>>,
    pub(super) post_commit_action: Option<Vec<u8>>,
    /// One or more payloads to publish. Most intents have a single payload (commit or message),
    /// but proposal intents may have multiple payloads (one per proposal).
    pub(super) payloads_to_publish: Vec<Vec<u8>>,
    pub(super) should_send_push_notification: bool,
    pub(super) group_epoch: u64,
}

#[cfg(any(test, feature = "test-utils"))]
impl PublishIntentData {
    #[allow(dead_code)]
    pub fn post_commit_data(&self) -> Option<Vec<u8>> {
        self.post_commit_action.clone()
    }

    #[allow(dead_code)]
    pub fn staged_commit(&self) -> Option<Vec<u8>> {
        self.staged_commit.clone()
    }
}
