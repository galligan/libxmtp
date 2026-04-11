#[cfg(any(test, feature = "test-utils"))]
pub mod stream_stats;
mod subscription;
#[cfg(any(test, feature = "test-utils"))]
mod test_utils;
#[cfg(test)]
mod tests;
mod types;

#[cfg(any(test, feature = "test-utils"))]
pub use test_utils::*;

use types::GroupList;
pub use types::MessageStreamError;
use xmtp_macro::log_event;

use super::{
    Result, SubscribeError,
    process_message::{ProcessFutureFactory, ProcessMessageFuture},
};
use crate::{
    context::XmtpSharedContext,
    groups::MlsGroup,
    subscriptions::{StreamKind, process_message::ProcessedMessage},
};
use futures::Stream;
use pin_project::{pin_project, pinned_drop};
use std::{
    borrow::Cow,
    collections::VecDeque,
    pin::Pin,
    task::{Poll, ready},
};
use xmtp_common::{BoxDynFuture, Event};
use xmtp_db::group_message::StoredGroupMessage;
use xmtp_proto::api_client::XmtpMlsStreams;
use xmtp_proto::types::{Cursor, GlobalCursor, OriginatorId, SequenceId};

impl xmtp_common::RetryableError for MessageStreamError {
    fn is_retryable(&self) -> bool {
        use MessageStreamError::*;
        match self {
            NotSubscribed(_) | InvalidPayload => false,
        }
    }
}

type AddingResult<Out> = (Out, Vec<u8>, Option<Cursor>);

#[pin_project(PinnedDrop)]
pub struct StreamGroupMessages<
    'a,
    Context: Clone + XmtpSharedContext,
    Subscription,
    Factory = ProcessMessageFuture<Context>,
> {
    #[pin]
    inner: Subscription,
    #[pin]
    state: State<'a, Subscription>,
    factory: Factory,
    context: Cow<'a, Context>,
    groups: GroupList,
    add_queue: VecDeque<(MlsGroup<Context>, Option<GlobalCursor>)>,
    returned: Vec<Cursor>,
    got: Vec<Cursor>,
}

#[pinned_drop]
impl<'a, Context, Subscription, Factory> PinnedDrop
    for StreamGroupMessages<'a, Context, Subscription, Factory>
where
    Context: Clone + XmtpSharedContext,
{
    fn drop(self: Pin<&mut Self>) {
        log_event!(
            Event::StreamClosed,
            self.context.installation_id(),
            kind = ?StreamKind::Messages
        );
    }
}

#[pin_project(project = ProjectState)]
#[derive(Default)]
enum State<'a, Out> {
    /// State that indicates the stream is waiting on the next message from the network
    #[default]
    Waiting,
    /// State that indicates the stream is waiting on a IO/Network future to finish processing
    /// the current message before moving on to the next one
    Processing {
        #[pin]
        future: BoxDynFuture<'a, Result<ProcessedMessage>>,
        message: Cursor,
    },
    // State that indicates that the stream is adding a new group to the stream.
    Adding {
        #[pin]
        future: BoxDynFuture<'a, Result<AddingResult<Out>>>,
    },
}

pub(super) type MessagesApiSubscription<'a, ApiClient> =
    <ApiClient as XmtpMlsStreams>::GroupMessageStream;

impl<'a, C, Factory> Stream
    for StreamGroupMessages<'a, C, MessagesApiSubscription<'a, C::ApiClient>, Factory>
where
    C: XmtpSharedContext + 'a,
    C::ApiClient: XmtpMlsStreams + 'a,
    Factory: ProcessFutureFactory<'a> + 'a,
{
    type Item = Result<StoredGroupMessage>;

    #[tracing::instrument(level = "trace", skip_all, name = "poll_next_message")]
    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        use ProjectState::*;
        let mut this = self.as_mut();
        match this.as_mut().project().state.as_mut().project() {
            Waiting => {
                tracing::trace!("stream messages in waiting state");
                let this = self.as_mut().project();
                if let Some((group, cursor)) = this.add_queue.pop_front() {
                    self.as_mut().resolve_group_additions(group, cursor);
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                let r = self.as_mut().on_waiting(cx);
                if self.as_mut().current_state() != "waiting" {
                    tracing::trace!(
                        "stream messages returning from waiting state, transitioning to {}",
                        self.as_mut().current_state()
                    );
                }
                r
            }
            Processing { message, .. } => {
                tracing::trace!(
                    "stream messages in processing state. Processing future for envelope @cursor=[{}]",
                    message
                );
                let r = self.as_mut().resolve_futures(cx);
                match r {
                    Poll::Ready(Some(_)) => {
                        tracing::trace!(
                            "stream messages returning from processing state, transitioning to {} state, ready with item",
                            self.as_mut().current_state()
                        )
                    }
                    Poll::Ready(None) => {
                        tracing::trace!(
                            "stream messages returning from processing state, Ready with None"
                        )
                    }
                    _ => (),
                }
                r
            }
            Adding { future } => {
                tracing::trace!("stream messages in adding state");
                if let Ok((stream, group, cursor)) = ready!(future.poll(cx)) {
                    if let Some(c) = cursor {
                        this.as_mut().set_cursor(group.as_slice(), c)
                    };
                    this.as_mut().project().inner.set(stream);
                    let position = this.groups.position(&group);
                    tracing::debug!(
                        "added group_id={} at cursor={} to messages stream",
                        hex::encode(&group),
                        position
                    );
                }
                this.project().state.as_mut().set(State::Waiting);
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }
}

impl<'a, C, Factory> StreamGroupMessages<'a, C, MessagesApiSubscription<'a, C::ApiClient>, Factory>
where
    C: XmtpSharedContext + 'a,
    Factory: ProcessFutureFactory<'a> + 'a,
    C::ApiClient: XmtpMlsStreams + 'a,
{
    /// Get the current state of the stream as a [`String`]
    fn current_state(self: Pin<&mut Self>) -> String {
        match self.as_ref().state {
            State::Waiting { .. } => "waiting".into(),
            State::Processing { .. } => "processing".into(),
            State::Adding { .. } => "adding".into(),
        }
    }

    /// Handles the stream when in the `Waiting` state.
    ///
    /// This method is called when the stream is ready to process the next message.
    /// It:
    /// 1. Waits for the next message from the inner stream
    /// 2. Checks if the message has already been processed by comparing cursors
    /// 3. Either processes the message or transitions to replay mode if needed
    ///
    /// # Arguments
    /// * `cx` - The task context for polling
    ///
    /// # Returns
    /// * `Poll<Option<Result<StoredGroupMessage>>>` - The polling result:
    ///   - `Ready(Some(Ok(msg)))` if a message is successfully processed
    ///   - `Ready(None)` if the stream is terminated
    ///   - `Pending` if waiting for more data
    #[tracing::instrument(level = "trace", skip_all)]
    fn on_waiting(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<<Self as Stream>::Item>> {
        let next_msg = ready!(self.as_mut().next_message(cx));
        let Some(next_msg) = next_msg else {
            return Poll::Ready(None);
        };
        let next_msg = next_msg?;
        // ensure we have not tried processing this message yet
        // if we have tried to process, replay messages up to the known cursor.
        if self.groups.has_seen(next_msg.cursor) {
            tracing::warn!(
                "msg @cursor[{}] for group_id@[{}] has been seen, skipping.",
                next_msg.cursor,
                next_msg.group_id
            );
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        if let Some(stored) = self.factory.retrieve(&next_msg)? {
            tracing::debug!(
                "msg @cursor[{:?}] for group_id@[{}] is available locally",
                next_msg.cursor,
                next_msg.group_id
            );
            let this = self.as_mut().project();
            this.groups.set(next_msg.group_id, next_msg.cursor);
            return Poll::Ready(Some(Ok(stored)));
        }
        tracing::info!(
            "group_id@[{}] encountered newly unprocessed message @cursor=[{}]",
            next_msg.group_id,
            next_msg.cursor
        );
        let future = self.factory.create(next_msg.clone());
        let msg_cursor = next_msg.cursor;
        let mut this = self.as_mut().project();
        this.state.set(State::Processing {
            future,
            message: msg_cursor,
        });
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    pub(super) fn add_with_cursor(
        mut self: Pin<&mut Self>,
        group: MlsGroup<C>,
        cursor: Option<GlobalCursor>,
    ) {
        self.as_mut().project().add_queue.push_back((group, cursor));
    }

    /// Add the group to the group list
    /// and transition the stream to Adding state
    fn resolve_group_additions(
        mut self: Pin<&mut Self>,
        group: MlsGroup<C>,
        cursor: Option<GlobalCursor>,
    ) {
        tracing::debug!(
            "begin establishing new message stream to include group_id={}",
            hex::encode(&group.group_id)
        );
        let this = self.as_mut().project();
        if !this.groups.contains(&group.group_id) {
            let position = cursor.unwrap_or_default();
            this.groups.add(&group.group_id, position);
        }
        let groups_with_positions = self.groups.groups_with_positions().clone();
        let future = Self::subscribe(self.context.clone(), groups_with_positions, group.group_id);
        let mut this = self.as_mut().project();

        this.state.set(State::Adding {
            future: Box::pin(future),
        });
    }

    /// Retrieves the next message from the inner stream.
    ///
    /// Polls the underlying subscription for the next message and extracts
    /// the V1 payload if available.
    ///
    /// # Arguments
    /// * `cx` - The task context for polling
    ///
    /// # Returns
    /// * `Poll<Option<Result<group_message::V1>>>` - The polling result:
    ///   - `Ready(Some(Ok(msg)))` if a valid message is available
    ///   - `Ready(None)` if the stream is terminated
    ///   - `Pending` if waiting for more data
    ///
    /// # Errors
    /// Returns an error if:
    /// - The inner stream returns an error
    /// - The message cannot be extracted (unsupported version)
    #[tracing::instrument(level = "trace", skip_all)]
    fn next_message(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Result<xmtp_proto::types::GroupMessage>>> {
        let this = self.as_mut().project();
        if let Some(envelope) = ready!(this.inner.poll_next(cx)) {
            let envelope = envelope.map_err(|e| SubscribeError::BoxError(Box::new(e)))?;
            this.got.push(envelope.cursor);
            tracing::trace!(
                "got new message for group=[{}] @cursor=[{}] from network, total messages=[{}]",
                xmtp_common::fmt::debug_hex(&envelope.group_id),
                envelope.cursor,
                this.got.len()
            );
            Poll::Ready(Some(Ok(envelope)))
        } else {
            Poll::Ready(None)
        }
    }

    /// Resolves futures when the stream is in the `Processing` state.
    ///
    /// This method handles the completion of asynchronous operations:
    /// - When a message is processed, updates the cursor and yields the message
    /// - When no message is available, updates the cursor and continues polling
    /// - When in replay mode, delegates to `resolve_replaying`
    ///
    /// # Arguments
    /// * `cx` - The task context for polling
    ///
    /// # Returns
    /// * `Poll<Option<Result<StoredGroupMessage>>>` - The polling result based on
    ///   the current state and operation outcome
    #[tracing::instrument(level = "trace", skip_all)]
    fn resolve_futures(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<<Self as Stream>::Item>> {
        use ProjectState::*;
        if let Processing { future, .. } = self.as_mut().project().state.project() {
            let processed = ready!(future.poll(cx))
                .inspect_err(|_| self.as_mut().project().state.set(State::Waiting))?;
            tracing::trace!(
                "message @cursor=[{}] finished processing",
                processed.tried_to_process
            );
            let this = self.as_mut().project();
            if let Some(msg) = processed.message {
                this.returned.push(Cursor::new(
                    msg.sequence_id as SequenceId,
                    msg.originator_id as OriginatorId,
                ));
                self.as_mut()
                    .set_cursor(msg.group_id.as_slice(), processed.next_message);
                tracing::trace!(
                    "returning new message for group=[{}] @cursor=[{:?}], total messages={}",
                    xmtp_common::fmt::debug_hex(msg.group_id.as_slice()),
                    processed.tried_to_process,
                    self.returned.len()
                );
                self.as_mut().project().state.set(State::Waiting);
                return Poll::Ready(Some(Ok(msg)));
            } else {
                self.as_mut()
                    .set_cursor(processed.group_id.as_slice(), processed.next_message);
                tracing::trace!(
                    "skipping message for group=[{}] @cursor=[{}], setting cursor to [{:?}]",
                    xmtp_common::fmt::debug_hex(&processed.group_id),
                    processed.tried_to_process,
                    processed.next_message
                );
                self.as_mut().project().state.set(State::Waiting);
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        }
        Poll::Pending
    }

    /// Updates the cursor position for a specific group.
    ///
    /// This method updates the tracking information for a group after
    /// successfully processing a message, allowing the stream to maintain
    /// proper ordering and prevent duplicate processing.
    ///
    /// # Arguments
    /// * `group_id` - The ID of the group to update
    /// * `new_cursor` - The new cursor position to set
    fn set_cursor(mut self: Pin<&mut Self>, group_id: &[u8], new_cursor: Cursor) {
        let this = self.as_mut().project();
        this.groups.set(group_id, new_cursor);
    }
}
