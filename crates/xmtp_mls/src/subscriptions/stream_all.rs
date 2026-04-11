mod bootstrap;
#[cfg(test)]
mod tests;

use super::{
    Result, SubscribeError,
    stream_conversations::{StreamConversations, WelcomesApiSubscription},
    stream_messages::StreamGroupMessages,
};
use crate::subscriptions::SyncWorkerEvent;
use crate::{context::XmtpSharedContext, subscriptions::stream_messages::MessagesApiSubscription};
use crate::{groups::MlsGroup, subscriptions::StreamKind};
use bootstrap::load_stream_bootstrap;
use futures::stream::Stream;
use pin_project::{pin_project, pinned_drop};
use std::{
    borrow::Cow,
    pin::Pin,
    task::{Poll, ready},
};
use xmtp_common::Event;
use xmtp_db::{
    consent_record::ConsentState, group::ConversationType, group_message::StoredGroupMessage,
};
use xmtp_macro::log_event;
use xmtp_proto::api_client::XmtpMlsStreams;

#[pin_project(PinnedDrop)]
pub struct StreamAllMessages<'a, Context, Conversations, Messages>
where
    Context: Clone + XmtpSharedContext,
{
    #[pin]
    pub(super) conversations: Conversations,
    #[pin]
    pub(super) messages: Messages,
    pub(super) context: Cow<'a, Context>,
    pub(super) sync_groups: Vec<Vec<u8>>,
    pub(super) conversation_type: Option<ConversationType>,
}

#[pinned_drop]
impl<'a, Context, Conversations, Messages> PinnedDrop
    for StreamAllMessages<'a, Context, Conversations, Messages>
where
    Context: Clone + XmtpSharedContext,
{
    fn drop(self: Pin<&mut Self>) {
        log_event!(
            Event::StreamClosed,
            self.context.installation_id(),
            kind = ?StreamKind::All
        );
    }
}

impl<Context>
    StreamAllMessages<
        'static,
        Context,
        StreamConversations<'static, Context, WelcomesApiSubscription<'static, Context::ApiClient>>,
        StreamGroupMessages<'static, Context, MessagesApiSubscription<'static, Context::ApiClient>>,
    >
where
    Context: Clone + XmtpSharedContext + 'static,
    Context::ApiClient: XmtpMlsStreams + 'static,
{
    pub async fn new_owned(
        context: Context,
        conversation_type: Option<ConversationType>,
        consent_states: Option<Vec<ConsentState>>,
    ) -> Result<Self> {
        Self::from_cow(Cow::Owned(context), conversation_type, consent_states).await
    }
}

impl<'a, Context>
    StreamAllMessages<
        'a,
        Context,
        StreamConversations<'a, Context, WelcomesApiSubscription<'a, Context::ApiClient>>,
        StreamGroupMessages<'a, Context, MessagesApiSubscription<'a, Context::ApiClient>>,
    >
where
    Context: Clone + XmtpSharedContext + 'a,
    Context::ApiClient: XmtpMlsStreams + 'a,
{
    pub async fn new(
        context: &'a Context,
        conversation_type: Option<ConversationType>,
        consent_states: Option<Vec<ConsentState>>,
    ) -> Result<Self> {
        log_event!(
            Event::StreamOpened,
            context.installation_id(),
            kind = ?StreamKind::All
        );
        Self::from_cow(Cow::Borrowed(context), conversation_type, consent_states).await
    }

    pub async fn from_cow(
        context: Cow<'a, Context>,
        conversation_type: Option<ConversationType>,
        consent_states: Option<Vec<ConsentState>>,
    ) -> Result<Self> {
        let bootstrap =
            load_stream_bootstrap(context.as_ref(), conversation_type, consent_states.clone())
                .await?;

        let conversations = super::stream_conversations::StreamConversations::from_cow(
            context.clone(),
            conversation_type,
            true,
            consent_states,
        )
        .await?;
        let messages =
            StreamGroupMessages::from_cow(context.clone(), bootstrap.active_conversations).await?;

        Ok(Self {
            context,
            conversation_type,
            messages,
            conversations,
            sync_groups: bootstrap.sync_groups,
        })
    }
}

impl<'a, Context, Conversations> Stream
    for StreamAllMessages<
        'a,
        Context,
        Conversations,
        StreamGroupMessages<'a, Context, MessagesApiSubscription<'a, Context::ApiClient>>,
    >
where
    Context: XmtpSharedContext + 'a,
    Context::ApiClient: XmtpMlsStreams + 'a,
    Conversations: Stream<Item = Result<MlsGroup<Context>>>,
{
    type Item = Result<StoredGroupMessage>;

    #[tracing::instrument(skip_all, level = "trace", name = "poll_next_stream_all")]
    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        use std::task::Poll::*;
        let mut this = self.as_mut().project();

        let next_message = this.messages.as_mut().poll_next(cx);
        if let Ready(Some(msg)) = next_message {
            if let Ok(msg) = &msg
                && self.sync_groups.contains(&msg.group_id)
            {
                let _ = self
                    .context
                    .worker_events()
                    .send(SyncWorkerEvent::NewSyncGroupMsg);
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            return Ready(Some(msg));
        }

        if let Ready(None) = next_message {
            return Ready(None);
        }

        if let Some(group) = ready!(this.conversations.poll_next(cx)) {
            let group_result = group?;
            this.messages.as_mut().add(group_result);
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    }
}
