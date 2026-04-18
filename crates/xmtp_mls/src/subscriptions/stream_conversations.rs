//! Conversation stream orchestration.
//!
//! This stream is the bootstrap surface used by bindings when they want
//! "conversations" rather than raw protocol events. It merges:
//! - remote welcomes,
//! - local synthetic group events, and
//! - follow-on catch-up work needed to hand callers a usable `MlsGroup`.

mod adapters;
#[cfg(test)]
mod tests;

use super::{LocalEvents, Result, SubscribeError, process_welcome::ProcessWelcomeResult};
use crate::subscriptions::StreamKind;
use crate::{
    context::XmtpSharedContext, groups::MlsGroup,
    subscriptions::process_welcome::ProcessWelcomeFuture,
};
use adapters::{BroadcastGroupStream, SubscriptionStream};
pub(crate) use adapters::{WelcomeOrGroup, WelcomesApiSubscription};
use xmtp_api_grpc::streams::multiplexed;
use xmtp_common::task::JoinSet;
use xmtp_db::{consent_record::ConsentState, group::ConversationType};

use futures::Stream;
use pin_project::{pin_project, pinned_drop};
use std::{
    borrow::Cow,
    collections::HashSet,
    pin::Pin,
    task::{Poll, ready},
};
use tokio_stream::wrappers::BroadcastStream;
use xmtp_common::{BoxDynFuture, Event};
use xmtp_db::prelude::*;
use xmtp_macro::log_event;
use xmtp_proto::api_client::XmtpMlsStreams;
use xmtp_proto::types::{Cursor, OriginatorId, SequenceId};

#[derive(thiserror::Error, Debug)]
pub enum ConversationStreamError {
    #[error("unexpected message type in welcome")]
    InvalidPayload,
    #[error("the conversation was filtered because of the given conversation type")]
    InvalidConversationType,
    #[error("the welcome pointer was not found")]
    WelcomePointerNotFound,
}

impl xmtp_common::RetryableError for ConversationStreamError {
    fn is_retryable(&self) -> bool {
        use ConversationStreamError::*;
        match self {
            InvalidPayload | InvalidConversationType => false,
            WelcomePointerNotFound => true,
        }
    }
}

/// The stream for conversations.
/// Handles the state machine that processes welcome messages and groups. It handles
/// two main states:
///
/// - `Waiting`: Ready to receive the next message from the inner stream
/// - `Processing`: Currently processing a welcome/group through a future
///
/// The implementation ensures efficient processing by immediately attempting
/// to advance futures when possible, rather than waiting for the next poll cycle.
///
/// # Arguments
/// * `cx` - The task context for polling
///
/// # Returns
/// * `Poll<Option<Result<MlsGroup<Context>>>>` - The polling result:
///   - `Ready(Some(Ok(group)))` when a group is successfully processed
///   - `Ready(Some(Err(e)))` when an error occurs
///   - `Pending` when waiting for more data or for future completion
///   - `Ready(None)` when the stream has ended
#[pin_project(PinnedDrop)]
pub struct StreamConversations<'a, Context: Clone + XmtpSharedContext, Subscription> {
    #[pin]
    inner: Subscription,
    context: Cow<'a, Context>,
    #[pin]
    welcome_syncs: JoinSet<Result<ProcessWelcomeResult<Context>>>,
    conversation_type: Option<ConversationType>,
    known_welcome_ids: HashSet<Cursor>,
    include_duplicated_dms: bool,
    consent_states: Option<Vec<ConsentState>>,
}

#[pinned_drop]
impl<'a, Context, Subscription> PinnedDrop for StreamConversations<'a, Context, Subscription>
where
    Context: Clone + XmtpSharedContext,
{
    fn drop(self: Pin<&mut Self>) {
        log_event!(
            Event::StreamClosed,
            self.context.installation_id(),
            kind = ?StreamKind::Conversations
        );
    }
}

#[pin_project(project = ProcessProject)]
#[derive(Default)]
enum ProcessState<'a, Context> {
    /// State that indicates the stream is waiting on the next message from the network
    #[default]
    Waiting,
    /// State that indicates the stream is waiting on a IO/Network future to finish processing the current message
    /// before moving on to the next one
    #[allow(unused)]
    Processing {
        #[pin]
        future: BoxDynFuture<'a, Result<ProcessWelcomeResult<Context>>>,
    },
}

impl<'a, C> StreamConversations<'a, C, WelcomesApiSubscription<'a, C::ApiClient>>
where
    C: XmtpSharedContext + 'a,
    C::ApiClient: XmtpMlsStreams + 'a,
    C::Db: 'a,
{
    /// Creates a new welcome message and conversation stream.
    ///
    /// This function initializes a stream that combines local and remote events
    /// for receiving conversation updates. It handles both welcome messages from
    /// the network and locally generated group events.
    ///
    /// Key initialization steps:
    /// 1. Retrieves the last cursor position for welcome messages
    /// 2. Sets up a broadcast stream for internal events
    /// 3. Creates a network subscription starting from the cursor
    /// 4. Loads existing welcome IDs to prevent reprocessing
    /// 5. Combines these sources into a multiplexed stream
    ///
    /// # Arguments
    /// * `client` - Reference to the client used for API communication
    /// * `conversation_type` - Optional filter to only receive specific conversation types
    /// * `include_duplicate_dms` - Optional filter to include duplicate dms in the stream
    /// * `consent_states` - Optional filter to only receive conversations with specific consent states
    ///
    /// # Returns
    /// * `Result<Self>` - A new conversation stream if successful
    ///
    /// # Errors
    /// May return errors if:
    /// - Database operations fail
    /// - API subscription creation fails
    ///
    pub async fn new(
        context: &'a C,
        conversation_type: Option<ConversationType>,
        include_duplicate_dms: bool,
        consent_states: Option<Vec<ConsentState>>,
    ) -> Result<Self> {
        log_event!(
            Event::StreamOpened,
            context.installation_id(),
            kind = ?StreamKind::Conversations
        );
        Self::from_cow(
            Cow::Borrowed(context),
            conversation_type,
            include_duplicate_dms,
            consent_states,
        )
        .await
    }

    /// Builds the stream from either borrowed or owned context.
    ///
    /// This is the single initialization path used by both borrowed and owned
    /// constructors so that cursor setup, event fan-in, and dedupe state all stay
    /// aligned across bindings.
    pub async fn from_cow(
        context: Cow<'a, C>,
        conversation_type: Option<ConversationType>,
        include_duplicated_dms: bool,
        consent_states: Option<Vec<ConsentState>>,
    ) -> Result<Self> {
        let conn = context.db();
        let installation_key = context.installation_id();
        tracing::debug!(
            inbox_id = context.inbox_id(),
            "Setting up conversation stream cursor",
        );

        let events = BroadcastGroupStream::new(
            BroadcastStream::new(context.local_events().subscribe()),
            consent_states.is_some(),
        );

        let subscription = context
            .api()
            .subscribe_welcome_messages(&installation_key)
            .await?;
        let subscription = SubscriptionStream::new(subscription);
        let known_welcome_ids = HashSet::from_iter(conn.group_cursors()?.into_iter());

        let stream = multiplexed(subscription, events);

        Ok(Self {
            context,
            inner: stream,
            known_welcome_ids,
            conversation_type,
            welcome_syncs: JoinSet::new(),
            include_duplicated_dms,
            consent_states,
        })
    }
}

impl<C> StreamConversations<'static, C, WelcomesApiSubscription<'static, C::ApiClient>>
where
    C: XmtpSharedContext + 'static,
    C::ApiClient: XmtpMlsStreams + 'static,
    C::Db: 'static,
{
    /// Creates an owned stream for bindings that cannot borrow client state for
    /// the lifetime of the subscription task.
    pub async fn new_owned(
        context: C,
        conversation_type: Option<ConversationType>,
        include_duplicate_dms: bool,
        consent_states: Option<Vec<ConsentState>>,
    ) -> Result<Self> {
        Self::from_cow(
            Cow::Owned(context),
            conversation_type,
            include_duplicate_dms,
            consent_states,
        )
        .await
    }
}

impl<'a, C, Subscription> Stream for StreamConversations<'a, C, Subscription>
where
    C: XmtpSharedContext + 'static,
    Subscription: Stream<Item = Result<WelcomeOrGroup>> + 'static,
    C::ApiClient: 'static,
    C::Db: 'static,
{
    type Item = Result<MlsGroup<C>>;

    #[tracing::instrument(skip_all, name = "poll_next_stream_conversations" level = "trace")]
    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        // We don't care if this is:
        // - Pending: we return pending by-default in the next section
        // - Ready(None): this just means the JoinSet is empty (no welcome syncs ongoing)
        // - Ready(Some(Err(welcome_result))): processing the welcome failed and the task failed with
        // a panic/error, we just ignore this.
        if let Poll::Ready(Some(Ok(welcome_result))) =
            self.as_mut().project().welcome_syncs.poll_join_next(cx)
        {
            // if filter is None, we continue to poll the inner stream.
            // the inner stream propagates a Pending, if its not pending, we register the task for
            // wakeup again. Therefore, we can ignore the None.
            if let Some(new_welcome) = self.as_mut().filter_welcome(welcome_result) {
                return Poll::Ready(Some(new_welcome));
            }
        }

        let mut this = self.as_mut().project();
        match ready!(this.inner.poll_next(cx)) {
            Some(welcome_envelope) => {
                let future = ProcessWelcomeFuture::new(
                    this.known_welcome_ids.clone(),
                    this.context.clone().into_owned(),
                    welcome_envelope?,
                    *this.conversation_type,
                    *this.include_duplicated_dms,
                    this.consent_states.clone(),
                )?;
                this.welcome_syncs.spawn(future.process());
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            None => Poll::Ready(None),
        }
    }
}

impl<'a, C, Subscription> StreamConversations<'a, C, Subscription>
where
    C: XmtpSharedContext + 'static,
    C::ApiClient: 'static,
    C::Db: 'static,
    Subscription: Stream<Item = Result<WelcomeOrGroup>> + 'static,
{
    /// adds the processed welcome id to our inner hashset
    fn filter_welcome(
        mut self: Pin<&mut Self>,
        welcome: Result<ProcessWelcomeResult<C>>,
    ) -> Option<<Self as Stream>::Item> {
        let this = self.as_mut().project();
        match welcome {
            Ok(ProcessWelcomeResult::New {
                group,
                id: welcome_id,
            }) => {
                tracing::debug!(
                    group_id = hex::encode(&group.group_id),
                    "finished processing with group {}",
                    hex::encode(&group.group_id)
                );
                this.known_welcome_ids.insert(welcome_id);
                Some(Ok(group))
            }
            // we are ignoring this payload with id
            Ok(ProcessWelcomeResult::IgnoreId { id }) => {
                tracing::debug!("ignoring streamed conversation payload with welcome id {id}");
                this.known_welcome_ids.insert(id);
                None
            }
            Ok(ProcessWelcomeResult::Ignore) => {
                tracing::debug!("ignoring streamed conversation payload");
                None
            }
            Ok(ProcessWelcomeResult::NewStored {
                group,
                maybe_sequence_id,
                maybe_originator,
            }) => {
                tracing::debug!(
                    group_id = hex::encode(&group.group_id),
                    "finished processing with group {}",
                    hex::encode(&group.group_id)
                );
                if let Some(id) = maybe_sequence_id
                    && let Some(originator) = maybe_originator
                {
                    this.known_welcome_ids
                        .insert(Cursor::new(id as SequenceId, originator as OriginatorId));
                }
                Some(Ok(group))
            }
            Err(e) => Some(Err(e)),
        }
    }
}
