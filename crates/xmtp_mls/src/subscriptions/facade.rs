use super::{
    Result,
    d14n_compat::{V3OrD14n, decode_welcome_message},
    events::StreamMessages,
    process_welcome::{ProcessWelcomeFuture, ProcessWelcomeResult},
    stream_all::StreamAllMessages,
    stream_conversations::{self, StreamConversations, WelcomeOrGroup},
};
use crate::{
    Client, context::XmtpSharedContext, groups::MlsGroup,
    messages::decoded_message::DecodedMessage,
    worker::device_sync::preference_sync::PreferenceUpdate,
};
use futures::{FutureExt, Stream, StreamExt, TryStreamExt, future, stream as future_stream};
use std::{collections::HashSet, sync::Arc};
use tokio::sync::oneshot;
use xmtp_api_d14n::protocol::{EnvelopeError, V3WelcomeMessageExtractor, WelcomeMessageExtractor};
use xmtp_api_d14n::stream;
use xmtp_common::{MaybeSend, StreamHandle};
use xmtp_db::{
    consent_record::{ConsentState, StoredConsentRecord},
    group::ConversationType,
    group_message::StoredGroupMessage,
    prelude::*,
};
use xmtp_proto::{api_client::XmtpMlsStreams, types::WelcomeMessage};

#[cfg(any(test, feature = "test-utils"))]
use crate::subscriptions::stream_messages::stream_stats::{StreamStatsWrapper, StreamWithStats};

impl<Context> Client<Context>
where
    Context: XmtpSharedContext + 'static,
{
    /// Async proxy for processing a streamed welcome message.
    /// Shouldn't be used unless for out-of-process utilities like Push Notifications.
    /// Pulls a new provider/database connection.
    pub async fn process_streamed_welcome_message(
        &self,
        envelope_bytes: Vec<u8>,
    ) -> Result<Vec<MlsGroup<Context>>> {
        let conn = self.context.db();
        let mut known_welcomes = HashSet::from_iter(conn.group_cursors()?.into_iter());
        let welcome = decode_welcome_message(envelope_bytes.as_slice())?;
        let welcomes: Vec<_> = match welcome {
            V3OrD14n::D14n(envelope) => {
                let messages = vec![envelope];
                stream::try_extractor::<_, WelcomeMessageExtractor>(future_stream::once(
                    future::ready(Ok::<_, EnvelopeError>(messages)),
                ))
                .try_collect()
                .now_or_never()
                .expect("stream has no pending operations, created with one item")
            }
            V3OrD14n::V3(message) => {
                let s: Vec<WelcomeMessage> = stream::try_extractor::<_, V3WelcomeMessageExtractor>(
                    future_stream::iter(vec![Ok::<_, EnvelopeError>(vec![message])]),
                )
                .try_collect::<Vec<WelcomeMessage>>()
                .now_or_never()
                .expect("stream must not fail because it is statically created with one item")?
                .into_iter()
                .collect();
                Ok(s)
            }
        }?;

        let mut out = Vec::with_capacity(welcomes.len());
        for welcome in welcomes {
            let welcome_id = welcome.cursor;
            let future = ProcessWelcomeFuture::new(
                known_welcomes.clone(),
                self.context.clone(),
                WelcomeOrGroup::Welcome(welcome),
                None,
                false,
                None,
            )?;

            match future.process().await? {
                ProcessWelcomeResult::New { group, .. } => {
                    known_welcomes.insert(welcome_id);
                    out.push(group)
                }
                ProcessWelcomeResult::NewStored { group, .. } => {
                    known_welcomes.insert(welcome_id);
                    out.push(group)
                }
                ProcessWelcomeResult::IgnoreId { .. } | ProcessWelcomeResult::Ignore => {
                    known_welcomes.insert(welcome_id);
                    return Err(
                        stream_conversations::ConversationStreamError::InvalidConversationType
                            .into(),
                    );
                }
            }
        }
        Ok(out)
    }

    #[tracing::instrument(level = "trace", skip_all)]
    pub async fn stream_conversations(
        &self,
        conversation_type: Option<ConversationType>,
        include_duplicate_dms: bool,
    ) -> Result<impl Stream<Item = Result<MlsGroup<Context>>> + use<'_, Context>>
    where
        Context::ApiClient: XmtpMlsStreams,
    {
        StreamConversations::new(
            &self.context,
            conversation_type,
            include_duplicate_dms,
            None,
        )
        .await
    }

    /// Stream conversations but decouple the lifetime of 'self' from the stream.
    #[tracing::instrument(level = "trace", skip_all)]
    pub async fn stream_conversations_owned(
        &self,
        conversation_type: Option<ConversationType>,
        include_duplicate_dms: bool,
    ) -> Result<impl Stream<Item = Result<MlsGroup<Context>>> + 'static>
    where
        Context::ApiClient: XmtpMlsStreams,
    {
        StreamConversations::new_owned(
            self.context.clone(),
            conversation_type,
            include_duplicate_dms,
            None,
        )
        .await
    }
}

impl<Context> Client<Context>
where
    Context: XmtpSharedContext + 'static,
    Context::ApiClient: XmtpMlsStreams + 'static,
    Context::MlsStorage: 'static,
{
    pub fn stream_conversations_with_callback(
        client: Arc<Client<Context>>,
        conversation_type: Option<ConversationType>,
        mut convo_callback: impl FnMut(Result<MlsGroup<Context>>) + MaybeSend + 'static,
        on_close: impl FnOnce() + MaybeSend + 'static,
        include_duplicate_dms: bool,
    ) -> impl StreamHandle<StreamOutput = Result<()>> {
        let (tx, rx) = oneshot::channel();

        xmtp_common::spawn(Some(rx), async move {
            let stream = match client
                .stream_conversations(conversation_type, include_duplicate_dms)
                .await
            {
                Ok(stream) => stream,
                Err(e) => {
                    tracing::warn!("Failed to create conversation stream, closing: {}", e);
                    on_close();
                    return Ok::<_, super::SubscribeError>(());
                }
            };
            futures::pin_mut!(stream);
            let _ = tx.send(());
            while let Some(convo) = stream.next().await {
                convo_callback(convo)
            }
            tracing::debug!("`stream_conversations` stream ended, dropping stream");
            on_close();
            Ok::<_, super::SubscribeError>(())
        })
    }

    #[tracing::instrument(level = "trace", skip_all)]
    pub async fn stream_all_messages(
        &self,
        conversation_type: Option<ConversationType>,
        consent_state: Option<Vec<ConsentState>>,
    ) -> Result<impl Stream<Item = Result<StoredGroupMessage>> + '_> {
        tracing::debug!(
            inbox_id = self.inbox_id(),
            installation_id = %self.context.installation_id(),
            conversation_type = ?conversation_type,
            "stream all messages"
        );

        StreamAllMessages::new(&self.context, conversation_type, consent_state).await
    }

    #[tracing::instrument(level = "trace", skip_all)]
    pub async fn stream_all_messages_owned(
        &self,
        conversation_type: Option<ConversationType>,
        consent_state: Option<Vec<ConsentState>>,
    ) -> Result<impl Stream<Item = Result<StoredGroupMessage>> + 'static> {
        tracing::debug!(
            inbox_id = self.inbox_id(),
            installation_id = %self.context.installation_id(),
            conversation_type = ?conversation_type,
            "stream all messages"
        );

        StreamAllMessages::new_owned(self.context.clone(), conversation_type, consent_state).await
    }

    pub fn stream_all_messages_with_callback(
        context: Context,
        conversation_type: Option<ConversationType>,
        consent_state: Option<Vec<ConsentState>>,
        mut callback: impl FnMut(Result<StoredGroupMessage>) + MaybeSend + 'static,
        on_close: impl FnOnce() + MaybeSend + 'static,
    ) -> impl StreamHandle<StreamOutput = Result<()>> {
        let (tx, rx) = oneshot::channel();

        xmtp_common::spawn(Some(rx), async move {
            tracing::debug!("stream all messages with callback");
            let stream =
                match StreamAllMessages::new(&context, conversation_type, consent_state).await {
                    Ok(stream) => stream,
                    Err(e) => {
                        tracing::warn!("Failed to create message stream, closing: {}", e);
                        on_close();
                        return Ok::<_, super::SubscribeError>(());
                    }
                };

            futures::pin_mut!(stream);
            let _ = tx.send(());

            while let Some(message) = stream.next().await {
                callback(message)
            }
            tracing::debug!("`stream_all_messages` stream ended, dropping stream");
            on_close();
            Ok::<_, super::SubscribeError>(())
        })
    }

    pub fn stream_consent_with_callback(
        client: Arc<Client<Context>>,
        mut callback: impl FnMut(Result<Vec<StoredConsentRecord>>) + MaybeSend + 'static,
        on_close: impl FnOnce() + MaybeSend + 'static,
    ) -> impl StreamHandle<StreamOutput = Result<()>> {
        let (tx, rx) = oneshot::channel();

        xmtp_common::spawn(Some(rx), async move {
            let receiver = client.local_events.subscribe();
            let stream = receiver.stream_consent_updates();

            futures::pin_mut!(stream);
            let _ = tx.send(());
            while let Some(message) = stream.next().await {
                callback(message)
            }
            tracing::debug!("`stream_consent` stream ended, dropping stream");
            on_close();
            Ok::<_, super::SubscribeError>(())
        })
    }

    pub fn stream_preferences_with_callback(
        client: Arc<Client<Context>>,
        mut callback: impl FnMut(Result<Vec<PreferenceUpdate>>) + MaybeSend + 'static,
        on_close: impl FnOnce() + MaybeSend + 'static,
    ) -> impl StreamHandle<StreamOutput = Result<()>> {
        let (tx, rx) = oneshot::channel();

        xmtp_common::spawn(Some(rx), async move {
            let receiver = client.local_events.subscribe();
            let stream = receiver.stream_preference_updates();

            futures::pin_mut!(stream);
            let _ = tx.send(());
            while let Some(message) = stream.next().await {
                callback(message)
            }
            tracing::debug!("`stream_preferences` stream ended, dropping stream");
            on_close();
            Ok::<_, super::SubscribeError>(())
        })
    }

    pub fn stream_message_deletions_with_callback(
        client: Arc<Client<Context>>,
        mut callback: impl FnMut(Result<DecodedMessage>) + MaybeSend + 'static,
    ) -> impl StreamHandle<StreamOutput = Result<()>> {
        let (tx, rx) = oneshot::channel();

        xmtp_common::spawn(Some(rx), async move {
            let receiver = client.local_events.subscribe();
            let stream = receiver.stream_message_deletions();

            futures::pin_mut!(stream);
            let _ = tx.send(());
            while let Some(message) = stream.next().await {
                callback(message.map(|boxed| *boxed))
            }
            tracing::debug!("`stream_message_deletions` stream ended, dropping stream");
            Ok::<_, super::SubscribeError>(())
        })
    }
}

impl<Context> Client<Context>
where
    Context: XmtpSharedContext + 'static,
    Context::ApiClient: XmtpMlsStreams + 'static,
    Context::MlsStorage: 'static,
    <Context::ApiClient as XmtpMlsStreams>::GroupMessageStream: Unpin,
    <Context::ApiClient as XmtpMlsStreams>::WelcomeMessageStream: Unpin,
{
    #[tracing::instrument(level = "trace", skip_all)]
    #[cfg(any(test, feature = "test-utils"))]
    pub async fn stream_all_messages_owned_with_stats(
        &self,
        conversation_type: Option<ConversationType>,
        consent_state: Option<Vec<ConsentState>>,
    ) -> Result<impl StreamWithStats<Item = Result<StoredGroupMessage>> + 'static> {
        tracing::debug!(
            inbox_id = self.inbox_id(),
            installation_id = %self.context.installation_id(),
            conversation_type = ?conversation_type,
            "stream all messages"
        );

        let stream =
            StreamAllMessages::new_owned(self.context.clone(), conversation_type, consent_state)
                .await?;

        Ok(StreamStatsWrapper::new(stream))
    }
}
