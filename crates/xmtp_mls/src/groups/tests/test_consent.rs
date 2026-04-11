use diesel::{ExpressionMethods, QueryDsl, RunQueryDsl};
use xmtp_db::prelude::QueryConsentRecord;
use xmtp_db::schema::consent_records::dsl as consent_dsl;
use crate::groups::send_message_opts::SendMessageOpts;
use xmtp_db::consent_record::{ConsentState, ConsentType};

use crate::context::XmtpSharedContext;
use crate::tester;

#[xmtp_common::test(unwrap_try = true)]
async fn test_auto_consent_to_own_group() {
    tester!(alix1);

    tester!(bo);
    let unwanted_bo = bo
        .create_group_with_members(&[alix1.inbox_id()], None, None)
        .await?;

    alix1.sync_welcomes().await?;
    let unwanted = alix1.group(&unwanted_bo.group_id)?;
    // We were added by ourselves, but we did not consent to the group. The group should remain unconsented.
    assert_eq!(unwanted.consent_state()?, ConsentState::Unknown);

    tester!(alix2, from: alix1);
    unwanted_bo
        .send_message(b"hi unwanted group", SendMessageOpts::default())
        .await?;

    alix2.sync_welcomes().await?;
    let unwanted2 = alix2.group(&unwanted.group_id)?;
    assert_eq!(unwanted2.consent_state()?, ConsentState::Unknown);

    let g = alix1.create_group(None, None)?;
    g.send_message(b"hello", SendMessageOpts::default()).await?;
    alix2.sync_welcomes().await?;

    let g2 = alix2.group(&g.group_id)?;
    assert_eq!(g2.consent_state()?, ConsentState::Allowed);
}

#[xmtp_common::test(unwrap_try = true)]
async fn test_dm_consent_falls_back_to_peer_inbox_record() {
    tester!(alix);
    tester!(bo);

    let dm = alix.find_or_create_dm(bo.inbox_id(), None).await?;
    dm.update_consent_state(ConsentState::Denied)?;

    let db = alix.context.db();
    let conversation_id = hex::encode(&dm.group_id);
    let peer_inbox_id = bo.inbox_id().to_string();

    let conversation_record =
        db.get_consent_record(conversation_id.clone(), ConsentType::ConversationId)?;
    let inbox_record = db.get_consent_record(peer_inbox_id.clone(), ConsentType::InboxId)?;

    assert_eq!(
        conversation_record.as_ref().map(|record| record.state),
        Some(ConsentState::Denied)
    );
    assert_eq!(
        inbox_record.as_ref().map(|record| record.state),
        Some(ConsentState::Denied)
    );

    db.raw_query_write(|conn| {
        diesel::delete(
            consent_dsl::consent_records
                .filter(consent_dsl::entity_type.eq(ConsentType::ConversationId))
                .filter(consent_dsl::entity.eq(&conversation_id)),
        )
        .execute(conn)
    })?;

    assert!(
        db.get_consent_record(conversation_id, ConsentType::ConversationId)?
            .is_none(),
        "the explicit DM conversation consent should be absent so the fallback path is exercised"
    );
    assert_eq!(dm.consent_state()?, ConsentState::Denied);
}
