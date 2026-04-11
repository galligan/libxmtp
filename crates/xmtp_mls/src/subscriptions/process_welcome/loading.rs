use super::Result;
use crate::{
    context::XmtpSharedContext,
    groups::{GroupError, InitialMembershipValidator, MlsGroup, welcome_sync::WelcomeService},
    intents::ProcessIntentError,
};
use xmtp_common::{Retry, retry_async};
use xmtp_db::prelude::*;
use xmtp_proto::types::{Cursor, WelcomeMessage};

pub(super) async fn process_welcome_from_network<Context>(
    context: &Context,
    welcome: &WelcomeMessage,
) -> Result<Option<MlsGroup<Context>>>
where
    Context: XmtpSharedContext,
{
    let welcomes = WelcomeService::new(context.clone());
    let res = retry_async!(
        Retry::default(),
        (async {
            let validator = InitialMembershipValidator::new(context);
            welcomes
                .process_new_welcome(welcome, false, validator)
                .await
        })
    );

    let id = welcome.cursor;
    if let Ok(maybe_group) = res {
        Ok(maybe_group)
    } else if let Err(GroupError::ProcessIntent(ProcessIntentError::WelcomeAlreadyProcessed(_))) =
        res
    {
        load_from_store(context, id)
    } else {
        Err(res.expect_err("Checked for Ok value").into())
    }
}

pub(super) fn load_from_store<Context>(
    context: &Context,
    cursor: Cursor,
) -> Result<Option<MlsGroup<Context>>>
where
    Context: XmtpSharedContext,
{
    let maybe_group = context.db().find_group_by_sequence_id(cursor)?;
    let Some(group) = maybe_group else {
        tracing::warn!(
            welcome_id = %cursor,
            "Already processed welcome not loaded from store (likely pre-existing group or oneshot message)"
        );
        return Ok(None);
    };
    tracing::info!(
        inbox_id = context.inbox_id(),
        group_id = hex::encode(&group.id),
        dm_id = group.dm_id,
        welcome_id = ?group.sequence_id,
        "loading existing group for welcome_id: {:?}",
        group.cursor()
    );
    Ok(Some(MlsGroup::new(
        context.clone(),
        group.id,
        group.dm_id,
        group.conversation_type,
        group.created_at_ns,
    )))
}
