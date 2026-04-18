use xmtp_db::group_message::{ContentType, MsgQueryArgs};
use xmtp_mls_common::group_mutable_metadata::MessageDisappearingSettings;

use crate::{context::XmtpSharedContext, tester};

fn group_update_ids<C>(group: &crate::groups::MlsGroup<C>) -> Vec<Vec<u8>>
where
    C: XmtpSharedContext,
{
    group
        .find_messages(&MsgQueryArgs {
            content_types: Some(vec![ContentType::GroupUpdated]),
            ..Default::default()
        })
        .unwrap()
        .into_iter()
        .map(|message| message.id)
        .collect::<Vec<_>>()
}

#[xmtp_common::test(unwrap_try = true)]
async fn test_disappearing_message_update_message_in_group() {
    tester!(alix);
    tester!(bo);

    let alix_bo_dm = alix.find_or_create_dm(bo.inbox_id(), None).await?;
    let bo_alix_dm = bo.find_or_create_dm(alix.inbox_id(), None).await?;
    let expected_settings = MessageDisappearingSettings::new(10, 20);

    alix_bo_dm
        .update_conversation_message_disappearing_settings(expected_settings)
        .await?;

    alix.sync_all_welcomes_and_groups(None).await?;

    let msgs = alix_bo_dm.find_messages_v2(&Default::default())?;
    assert_eq!(msgs.len(), 4);
    assert_eq!(alix_bo_dm.disappearing_settings()?.unwrap(), expected_settings);

    let primary_update_ids_after_first_sync = group_update_ids(&alix_bo_dm);
    assert_eq!(primary_update_ids_after_first_sync.len(), 4);

    let alix_bo_alix_dm = alix.group(&bo_alix_dm.group_id)?;
    let stitched_msgs = alix_bo_alix_dm.find_messages_v2(&Default::default())?;
    assert_eq!(stitched_msgs.len(), 4);
    let stitched_update_ids_after_first_sync = group_update_ids(&alix_bo_alix_dm);
    assert_eq!(stitched_update_ids_after_first_sync.len(), 4);

    // Replaying stitched DM sync should preserve both the mirrored metadata and the
    // transcript-visible GroupUpdated state instead of reapplying or duplicating it.
    alix.sync_all_welcomes_and_groups(None).await?;

    assert_eq!(alix_bo_dm.disappearing_settings()?.unwrap(), expected_settings);
    assert_eq!(alix_bo_alix_dm.find_messages_v2(&Default::default())?.len(), 4);
    assert_eq!(group_update_ids(&alix_bo_dm), primary_update_ids_after_first_sync);
    assert_eq!(
        group_update_ids(&alix_bo_alix_dm),
        stitched_update_ids_after_first_sync
    );
}
