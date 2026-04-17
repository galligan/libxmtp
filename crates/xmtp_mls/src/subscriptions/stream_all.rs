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
    collections::VecDeque,
    pin::Pin,
    task::{Poll, ready},
};
use xmtp_common::Event;
use xmtp_db::{
    consent_record::{ConsentState, ConsentType},
    encrypted_store::refresh_state::EntityKind,
    group::{ConversationType, DmIdExt},
    group_message::{GroupMessageKind, MsgQueryArgs, StoredGroupMessage},
    prelude::{QueryConsentRecord, QueryGroup, QueryGroupMessage, QueryRefreshState},
};
use xmtp_macro::log_event;
use xmtp_proto::{api_client::XmtpMlsStreams, types::GlobalCursor};

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
    pub(super) replay_queue: VecDeque<StoredGroupMessage>,
    pub(super) sync_groups: Vec<Vec<u8>>,
    pub(super) conversation_type: Option<ConversationType>,
    pub(super) consent_states: Option<Vec<ConsentState>>,
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
            consent_states.clone(),
        )
        .await?;
        let messages =
            StreamGroupMessages::from_cow(context.clone(), bootstrap.active_conversations).await?;

        Ok(Self {
            context,
            conversation_type,
            messages,
            conversations,
            replay_queue: VecDeque::new(),
            sync_groups: bootstrap.sync_groups,
            consent_states,
        })
    }
}

fn current_group_cursor<Context>(context: &Context, group_id: &[u8]) -> Result<Option<GlobalCursor>>
where
    Context: XmtpSharedContext,
{
    Ok(context
        .db()
        .get_last_cursor_for_ids(
            &[group_id.to_vec()],
            &[EntityKind::ApplicationMessage, EntityKind::CommitMessage],
        )?
        .get(group_id)
        .cloned())
}

fn replayable_group_messages_after<Context>(
    context: &Context,
    group_id: &[u8],
    replay_after_ns: i64,
) -> Result<Vec<StoredGroupMessage>>
where
    Context: XmtpSharedContext,
{
    let query = MsgQueryArgs {
        sent_after_ns: Some(replay_after_ns.saturating_sub(1)),
        kind: Some(GroupMessageKind::Application),
        ..Default::default()
    };
    Ok(context.db().get_group_messages(group_id, &query)?)
}

fn message_matches_consent_filter<Context>(
    context: &Context,
    consent_states: Option<&[ConsentState]>,
    message: &StoredGroupMessage,
) -> Result<bool>
where
    Context: XmtpSharedContext,
{
    let Some(consent_states) = consent_states else {
        return Ok(true);
    };

    let db = context.db();
    let direct_state = || -> Result<Option<ConsentState>> {
        Ok(db
            .get_consent_record(hex::encode(&message.group_id), ConsentType::ConversationId)?
            .map(|record| record.state))
    };

    let current_state = match db.find_group(&message.group_id)? {
        Some(group) if group.conversation_type == ConversationType::Dm => {
            let stitched_state = match group.dm_id.as_ref() {
                Some(dm_id) => {
                    let inbox_state = db
                        .get_consent_record(
                            dm_id.other_inbox_id(context.inbox_id()),
                            ConsentType::InboxId,
                        )?
                        .map(|record| record.state);

                    inbox_state.or(db
                        .find_consent_by_dm_id(dm_id)?
                        .into_iter()
                        .next()
                        .map(|record| record.state))
                }
                None => None,
            };

            stitched_state
                .or(direct_state()?)
                .unwrap_or(ConsentState::Unknown)
        }
        _ => direct_state()?.unwrap_or(ConsentState::Unknown),
    };

    Ok(consent_states.contains(&current_state))
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
        loop {
            let mut this = self.as_mut().project();

            while let Some(message) = this.replay_queue.pop_front() {
                if !message_matches_consent_filter(
                    this.context.as_ref(),
                    this.consent_states.as_deref(),
                    &message,
                )? {
                    tracing::debug!(
                        group_id = hex::encode(&message.group_id),
                        sequence_id = message.sequence_id,
                        originator_id = message.originator_id,
                        "suppressing replayed message due to current consent filter"
                    );
                    continue;
                }

                tracing::debug!(
                    group_id = hex::encode(&message.group_id),
                    sequence_id = message.sequence_id,
                    originator_id = message.originator_id,
                    "returning replayed message from stream_all replay queue"
                );
                return Ready(Some(Ok(message)));
            }

            let next_message = this.messages.as_mut().poll_next(cx);
            if let Ready(Some(msg)) = next_message {
                if let Ok(msg) = &msg
                    && this.sync_groups.contains(&msg.group_id)
                {
                    tracing::debug!(
                        group_id = hex::encode(&msg.group_id),
                        sequence_id = msg.sequence_id,
                        originator_id = msg.originator_id,
                        "suppressing sync-group message from stream_all output"
                    );
                    let _ = this
                        .context
                        .worker_events()
                        .send(SyncWorkerEvent::NewSyncGroupMsg);
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }

                if let Ok(msg) = &msg
                    && !message_matches_consent_filter(
                        this.context.as_ref(),
                        this.consent_states.as_deref(),
                        msg,
                    )?
                {
                    tracing::debug!(
                        group_id = hex::encode(&msg.group_id),
                        sequence_id = msg.sequence_id,
                        originator_id = msg.originator_id,
                        "suppressing streamed message due to current consent filter"
                    );
                    continue;
                }

                return Ready(Some(msg));
            }

            if let Ready(None) = next_message {
                return Ready(None);
            }

            if let Some(group) = ready!(this.conversations.poll_next(cx)) {
                let group_result = group?;
                let seed_cursor = group_result.stream_seed_cursor();
                let replay_after_ns = group_result.stream_replay_after_ns();
                tracing::debug!(
                    group_id = hex::encode(&group_result.group_id),
                    has_stream_seed_cursor = seed_cursor.is_some(),
                    replay_after_ns,
                    "stream_all received conversation event"
                );
                let group_cursor = if let Some(replay_after_ns) = replay_after_ns {
                    let replayed_messages = replayable_group_messages_after(
                        this.context.as_ref(),
                        group_result.group_id.as_slice(),
                        replay_after_ns,
                    )?;
                    if !replayed_messages.is_empty() {
                        tracing::debug!(
                            group_id = hex::encode(&group_result.group_id),
                            replayed_messages = replayed_messages.len(),
                            replay_after_ns,
                            "stream_all queued replayed messages after consent transition"
                        );
                        this.replay_queue.extend(replayed_messages);
                    }
                    current_group_cursor(this.context.as_ref(), group_result.group_id.as_slice())?
                } else {
                    match seed_cursor {
                        Some(cursor) => Some(cursor),
                        None => current_group_cursor(
                            this.context.as_ref(),
                            group_result.group_id.as_slice(),
                        )?,
                    }
                };
                tracing::debug!(
                    group_id = hex::encode(&group_result.group_id),
                    group_cursor = ?group_cursor,
                    "stream_all attaching message stream for conversation"
                );
                this.messages
                    .as_mut()
                    .add_with_cursor(group_result, group_cursor);
                cx.waker().wake_by_ref();
            }

            return Poll::Pending;
        }
    }
}
