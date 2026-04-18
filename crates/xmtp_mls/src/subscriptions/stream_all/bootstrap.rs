use super::{Result, SubscribeError};
use crate::{context::XmtpSharedContext, groups::welcome_sync::WelcomeService};
use xmtp_db::{
    consent_record::ConsentState,
    group::StoredGroup,
    group::{ConversationType, GroupQueryArgs},
    prelude::*,
};
use xmtp_proto::types::GroupId;

pub(super) struct StreamAllBootstrap {
    pub(super) active_conversations: Vec<GroupId>,
    pub(super) sync_groups: Vec<Vec<u8>>,
}

pub(super) async fn load_stream_bootstrap<Context>(
    context: &Context,
    conversation_type: Option<ConversationType>,
    consent_states: Option<Vec<ConsentState>>,
) -> Result<StreamAllBootstrap>
where
    Context: Clone + XmtpSharedContext,
{
    let conn = context.db();
    WelcomeService::new(context).sync_welcomes().await?;

    let groups = conn.find_groups(GroupQueryArgs {
        conversation_type,
        consent_states,
        include_duplicate_dms: true,
        include_sync_groups: conversation_type
            .map(|ct| matches!(ct, ConversationType::Sync))
            .unwrap_or(true),
        ..Default::default()
    })?;

    let sync_groups = groups
        .iter()
        .filter_map(|g| match g {
            StoredGroup {
                conversation_type: ConversationType::Sync,
                ..
            } => Some(g.id.clone()),
            _ => None,
        })
        .collect();
    let active_conversations = groups
        .into_iter()
        // TODO: Create find groups query only for group ID
        .map(|g| GroupId::from(g.id))
        .collect();

    Ok::<_, SubscribeError>(StreamAllBootstrap {
        active_conversations,
        sync_groups,
    })
}
