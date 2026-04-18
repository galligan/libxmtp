use super::{LocalEvents, Result, SubscribeError};
use futures::Stream;
use pin_project::pin_project;
use std::{
    collections::VecDeque,
    pin::Pin,
    task::{Poll, ready},
};
use tokio_stream::wrappers::BroadcastStream;
use xmtp_api_grpc::streams::MultiplexedStream;
use xmtp_common::MaybeSend;
use xmtp_proto::{
    api_client::XmtpMlsStreams,
    types::{GlobalCursor, WelcomeMessage, WelcomeMessage as ProtoWelcomeMessage},
};

pub enum WelcomeOrGroup {
    Group {
        id: Vec<u8>,
        catch_up_before_stream: bool,
        attach_cursor: Option<GlobalCursor>,
        replay_after_ns: Option<i64>,
    },
    Welcome(ProtoWelcomeMessage),
}

impl std::fmt::Debug for WelcomeOrGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Group {
                id,
                catch_up_before_stream,
                attach_cursor,
                replay_after_ns,
            } => f
                .debug_struct("Group")
                .field("id", &hex::encode(id))
                .field("catch_up_before_stream", catch_up_before_stream)
                .field("attach_cursor", attach_cursor)
                .field("replay_after_ns", replay_after_ns)
                .finish(),
            Self::Welcome(arg0) => f.debug_tuple("Welcome").field(arg0).finish(),
        }
    }
}

#[pin_project]
/// Broadcast stream filtered + mapped to WelcomeOrGroup
pub struct BroadcastGroupStream {
    #[pin]
    inner: BroadcastStream<LocalEvents>,
    pending_events: VecDeque<WelcomeOrGroup>,
    include_preference_groups: bool,
}

impl BroadcastGroupStream {
    pub(super) fn new(
        inner: BroadcastStream<LocalEvents>,
        include_preference_groups: bool,
    ) -> Self {
        Self {
            inner,
            pending_events: VecDeque::new(),
            include_preference_groups,
        }
    }
}

impl Stream for BroadcastGroupStream {
    type Item = Result<WelcomeOrGroup>;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        use std::task::Poll::*;
        let mut this = self.project();

        if let Some(event) = this.pending_events.pop_front() {
            return Ready(Some(Ok(event)));
        }

        loop {
            if let Some(event) = ready!(this.inner.as_mut().poll_next(cx)) {
                if let Some(event) =
                    xmtp_common::optify!(event, "Missed messages due to event queue lag")
                {
                    match event {
                        LocalEvents::NewGroup(group) => {
                            return Ready(Some(Ok(WelcomeOrGroup::Group {
                                id: group,
                                catch_up_before_stream: false,
                                attach_cursor: None,
                                replay_after_ns: None,
                            })));
                        }
                        LocalEvents::PreferencesChanged(event)
                            if *this.include_preference_groups =>
                        {
                            let replay_after_ns = event.conversation_replay_after_ns;
                            let mut groups = event
                                .conversation_cursors
                                .into_iter()
                                .map(|(group, attach_cursor)| WelcomeOrGroup::Group {
                                    replay_after_ns: replay_after_ns
                                        .get(group.as_slice())
                                        .cloned()
                                        .flatten(),
                                    id: group,
                                    catch_up_before_stream: true,
                                    attach_cursor,
                                });

                            if let Some(group) = groups.next() {
                                this.pending_events.extend(groups);
                                return Ready(Some(Ok(group)));
                            }
                        }
                        _ => {}
                    }
                }
            } else {
                return Ready(None);
            }
        }
    }
}

#[pin_project]
/// Subscription Stream mapped to WelcomeOrGroup
pub struct SubscriptionStream<S, E> {
    #[pin]
    inner: S,
    _marker: std::marker::PhantomData<E>,
}

impl<S, E> SubscriptionStream<S, E> {
    pub(super) fn new(inner: S) -> Self {
        Self {
            inner,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<S, E> Stream for SubscriptionStream<S, E>
where
    S: Stream<Item = std::result::Result<WelcomeMessage, E>> + MaybeSend,
    E: xmtp_common::RetryableError + 'static,
{
    type Item = Result<WelcomeOrGroup>;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        use std::task::Poll::*;
        let this = self.project();

        match this.inner.poll_next(cx) {
            Ready(Some(welcome)) => {
                let welcome = welcome.map_err(|e| SubscribeError::BoxError(Box::new(e)))?;
                Ready(Some(Ok(WelcomeOrGroup::Welcome(welcome))))
            }
            Pending => Pending,
            Ready(None) => Ready(None),
        }
    }
}

pub(crate) type WelcomesApiSubscription<'a, ApiClient> = MultiplexedStream<
    SubscriptionStream<
        <ApiClient as XmtpMlsStreams>::WelcomeMessageStream,
        <ApiClient as XmtpMlsStreams>::Error,
    >,
    BroadcastGroupStream,
>;
