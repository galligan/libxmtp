use super::{
    GroupList, MessagesApiSubscription, ProcessFutureFactory, ProcessMessageFuture, Result,
    StreamGroupMessages, StreamKind,
};
use crate::context::XmtpSharedContext;
use std::borrow::Cow;
use xmtp_common::Event;
use xmtp_macro::log_event;
use xmtp_proto::{
    api_client::XmtpMlsStreams,
    types::{Cursor, GroupId, Topic, TopicCursor},
};

impl<'a, Context> StreamGroupMessages<'a, Context, MessagesApiSubscription<'a, Context::ApiClient>>
where
    Context: XmtpSharedContext + 'a,
    Context::ApiClient: XmtpMlsStreams + 'a,
{
    pub async fn new(context: &'a Context, groups: Vec<GroupId>) -> Result<Self> {
        log_event!(
            Event::StreamOpened,
            context.installation_id(),
            kind = ?StreamKind::Messages
        );
        Self::new_with_factory(
            Cow::Borrowed(context),
            groups,
            ProcessMessageFuture::new(context.clone()),
        )
        .await
    }

    pub async fn from_cow(context: Cow<'a, Context>, groups: Vec<GroupId>) -> Result<Self> {
        Self::new_with_factory(
            context.clone(),
            groups,
            ProcessMessageFuture::new(context.as_ref().clone()),
        )
        .await
    }
}

impl<C> StreamGroupMessages<'static, C, MessagesApiSubscription<'static, C::ApiClient>>
where
    C: XmtpSharedContext + 'static,
    C::ApiClient: XmtpMlsStreams + 'static,
    C::Db: 'static,
{
    pub async fn new_owned(context: C, groups: Vec<GroupId>) -> Result<Self> {
        let f = ProcessMessageFuture::new(context.clone());
        Self::new_with_factory(Cow::Owned(context), groups, f).await
    }
}

impl<'a, C, Factory> StreamGroupMessages<'a, C, MessagesApiSubscription<'a, C::ApiClient>, Factory>
where
    C: XmtpSharedContext + 'a,
    C::ApiClient: XmtpMlsStreams + 'a,
    Factory: ProcessFutureFactory<'a> + 'a,
{
    pub async fn new_with_factory(
        context: Cow<'a, C>,
        groups: Vec<GroupId>,
        factory: Factory,
    ) -> Result<Self> {
        tracing::debug!("setting up messages subscription");
        let api = context.api();

        use xmtp_db::encrypted_store::refresh_state::{EntityKind, QueryRefreshState};
        use xmtp_db::group_message::QueryGroupMessage;

        let db = context.db();
        let cursors_by_group = db.get_last_cursor_for_ids(
            &groups,
            &[EntityKind::ApplicationMessage, EntityKind::CommitMessage],
        )?;

        let seen_cursors_vec = db.messages_newer_than(&cursors_by_group)?;
        let seen_cursors: std::collections::HashSet<_> = seen_cursors_vec.into_iter().collect();

        let mut topic_cursor = TopicCursor::default();
        for group_id in &groups {
            let cursor = cursors_by_group
                .get(group_id.as_slice())
                .cloned()
                .unwrap_or_default();
            topic_cursor.add(Topic::new_group_message(group_id.clone()), cursor);
        }

        let groups_list = GroupList::new(topic_cursor, seen_cursors);

        let subscription = api
            .subscribe_group_messages(&groups.iter().collect::<Vec<_>>())
            .await?;

        Ok(Self {
            inner: subscription,
            context,
            state: Default::default(),
            groups: groups_list,
            got: Default::default(),
            returned: Default::default(),
            add_queue: Default::default(),
            factory,
        })
    }

    #[tracing::instrument(level = "trace", skip(context, new_group), fields(new_group = hex::encode(&new_group)))]
    #[allow(clippy::type_complexity)]
    pub(super) async fn subscribe(
        context: Cow<'a, C>,
        topic_cursor: TopicCursor,
        new_group: Vec<u8>,
    ) -> Result<(
        MessagesApiSubscription<'a, C::ApiClient>,
        Vec<u8>,
        Option<Cursor>,
    )> {
        let stream = context
            .as_ref()
            .api()
            .subscribe_group_messages_with_cursors(&topic_cursor)
            .await?;
        Ok((stream, new_group, None))
    }
}
