use super::{LocalEvents, Result, SubscribeError};
use futures::Stream;
use pin_project::pin_project;
use std::{
    pin::Pin,
    task::{Poll, ready},
};
use tokio_stream::wrappers::BroadcastStream;
use xmtp_api_grpc::streams::MultiplexedStream;
use xmtp_common::MaybeSend;
use xmtp_proto::{
    api_client::XmtpMlsStreams,
    types::{WelcomeMessage, WelcomeMessage as ProtoWelcomeMessage},
};

pub enum WelcomeOrGroup {
    Group(Vec<u8>),
    Welcome(ProtoWelcomeMessage),
}

impl std::fmt::Debug for WelcomeOrGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Group(arg0) => f.debug_tuple("Group").field(&hex::encode(arg0)).finish(),
            Self::Welcome(arg0) => f.debug_tuple("Welcome").field(arg0).finish(),
        }
    }
}

#[pin_project]
/// Broadcast stream filtered + mapped to WelcomeOrGroup
pub struct BroadcastGroupStream {
    #[pin]
    inner: BroadcastStream<LocalEvents>,
}

impl BroadcastGroupStream {
    pub(super) fn new(inner: BroadcastStream<LocalEvents>) -> Self {
        Self { inner }
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
        loop {
            if let Some(event) = ready!(this.inner.as_mut().poll_next(cx)) {
                if let Some(group) =
                    xmtp_common::optify!(event, "Missed messages due to event queue lag")
                        .and_then(LocalEvents::group_filter)
                {
                    return Ready(Some(Ok(WelcomeOrGroup::Group(group))));
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
