use super::*;
use crate::builder::ClientBuilder;
use crate::groups::send_message_opts::SendMessageOpts;
use crate::tester;
use crate::utils::ClientTester;
use crate::utils::fixtures::{alix, bo};
use futures::StreamExt;
use std::sync::Arc;
use xmtp_cryptography::utils::generate_local_wallet;
use xmtp_db::group::GroupQueryArgs;

#[xmtp_common::timeout(std::time::Duration::from_secs(10))]
#[rstest::rstest]
#[case::two_conversations(2)]
#[case::five_conversations(5)]
#[xmtp_common::test]
#[awt]
async fn stream_welcomes(
    #[future] alix: ClientTester,
    #[future] bo: ClientTester,
    #[case] group_size: usize,
) {
    let mut groups = vec![];
    let mut stream = StreamConversations::new(&bo.context, None, false, None)
        .await
        .unwrap();
    for _ in 0..group_size {
        let alix_bo_group = alix.create_group(None, None).unwrap();
        groups.push(alix_bo_group.group_id.clone());
        alix_bo_group.add_members(&[bo.inbox_id()]).await.unwrap();
    }
    while !groups.is_empty() {
        let bo_received_groups = stream.next().await.unwrap().unwrap();
        let index = groups
            .iter()
            .position(|group_id| bo_received_groups.group_id == *group_id)
            .expect("group must be found");
        groups.remove(index);
    }

    assert!(groups.is_empty(), "Groups must have all been received");
}

#[rstest::rstest]
#[xmtp_common::test(unwrap_try = true)]
async fn test_sync_groups_are_not_streamed() {
    tester!(alix, sync_worker);
    let stream = alix.stream_conversations(None, false).await?;
    futures::pin_mut!(stream);

    tester!(_alix2, from: alix);

    let result =
        xmtp_common::time::timeout(std::time::Duration::from_millis(100), stream.next()).await;
    assert!(result.is_err(), "Sync group should not stream");
}

#[rstest::rstest]
#[case(ConversationType::Dm, "Unexpectedly received a Group")]
#[case(ConversationType::Group, "Unexpectedly received a DM")]
#[xmtp_common::test]
#[cfg_attr(target_arch = "wasm32", ignore)]
async fn test_dm_stream_filter(
    #[case] conversation_type: ConversationType,
    #[case] expected: &str,
) {
    tester!(alix);
    tester!(bo);
    let stream = alix
        .stream_conversations(Some(conversation_type), false)
        .await
        .unwrap();
    futures::pin_mut!(stream);

    alix.find_or_create_dm(bo.inbox_id().to_string(), None)
        .await
        .unwrap();

    let group = alix.create_group(None, None).unwrap();
    group.add_members(&[bo.inbox_id()]).await.unwrap();

    let group = stream.next().await.unwrap();
    let metadata = group.unwrap().metadata().await.unwrap();

    assert_eq!(
        metadata.conversation_type, conversation_type,
        "{}",
        expected
    );
    let result =
        xmtp_common::time::timeout(std::time::Duration::from_millis(100), stream.next()).await;
    assert!(result.is_err(), "should only be one item in the stream");
}

#[rstest::rstest]
#[xmtp_common::test]
async fn test_dm_stream_all_conversation_types() {
    let alix = Arc::new(ClientBuilder::new_test_client(&generate_local_wallet()).await);
    let bo = Arc::new(ClientBuilder::new_test_client(&generate_local_wallet()).await);
    let davon = Arc::new(ClientBuilder::new_test_client(&generate_local_wallet()).await);
    let eri = Arc::new(ClientBuilder::new_test_client(&generate_local_wallet()).await);

    let mut groups = Vec::new();
    let stream = alix.stream_conversations(None, false).await.unwrap();
    futures::pin_mut!(stream);

    alix.find_or_create_dm(davon.inbox_id().to_string(), None)
        .await
        .unwrap();
    let group = stream.next().await.unwrap();
    assert!(group.is_ok());
    groups.push(group.unwrap());

    let dm = eri
        .find_or_create_dm(alix.inbox_id().to_string(), None)
        .await
        .unwrap();
    dm.add_members(&[alix.inbox_id()]).await.unwrap();
    let group = stream.next().await.unwrap();
    assert!(group.is_ok());
    groups.push(group.unwrap());

    let group = alix.create_group(None, None).unwrap();
    group.add_members(&[bo.inbox_id()]).await.unwrap();
    let group = stream.next().await.unwrap();
    assert!(group.is_ok());
    groups.push(group.unwrap());

    assert_eq!(groups.len(), 3);
}

#[xmtp_common::timeout(std::time::Duration::from_secs(10))]
#[rstest::rstest]
#[xmtp_common::test]
async fn test_self_group_creation() {
    tester!(alix);
    tester!(bo);

    let stream = alix
        .stream_conversations(Some(ConversationType::Group), false)
        .await
        .unwrap();
    futures::pin_mut!(stream);

    alix.create_group(None, None).unwrap();
    let _self_group = stream.next().await.unwrap();

    let group = bo.create_group(None, None).unwrap();
    group.add_members(&[alix.inbox_id()]).await.unwrap();
    let _bo_group = stream.next().await.unwrap();

    alix.sync_welcomes().await.unwrap();
    let find_groups_results = alix.find_groups(GroupQueryArgs::default()).unwrap();
    assert_eq!(2, find_groups_results.len());
}

#[xmtp_common::timeout(std::time::Duration::from_secs(5))]
#[rstest::rstest]
#[xmtp_common::test]
async fn test_add_remove_re_add() {
    tester!(alix);
    tester!(bo);

    let alix_group = alix
        .create_group_with_members(&[bo.inbox_id().to_string()], None, None)
        .await
        .unwrap();

    alix_group.remove_members(&[bo.inbox_id()]).await.unwrap();
    bo.sync_welcomes().await.unwrap();
    let stream = bo
        .stream_conversations(Some(ConversationType::Group), false)
        .await
        .unwrap();
    futures::pin_mut!(stream);
    alix_group
        .add_members(&[bo.inbox_id().to_string()])
        .await
        .unwrap();

    let group_result = stream.next().await.unwrap();
    if let Err(error) = group_result {
        panic!("Error streaming group: {:?}", error);
    }
}

#[xmtp_common::timeout(std::time::Duration::from_secs(15))]
#[rstest::rstest]
#[xmtp_common::test]
async fn test_duplicate_dm_not_streamed() {
    let client1 = Arc::new(ClientBuilder::new_test_client(&generate_local_wallet()).await);
    let client2 = Arc::new(ClientBuilder::new_test_client(&generate_local_wallet()).await);

    let mut stream = client1.stream_conversations(None, false).await.unwrap();

    let dm1 = client1
        .find_or_create_dm(client2.inbox_id().to_string(), None)
        .await
        .unwrap();

    let streamed_dm1 = stream.next().await.unwrap();
    assert!(streamed_dm1.is_ok());
    assert_eq!(streamed_dm1.unwrap().group_id, dm1.group_id);

    let dm2 = client2
        .find_or_create_dm(client1.inbox_id().to_string(), None)
        .await
        .unwrap();

    assert_ne!(dm1.group_id, dm2.group_id);

    let result =
        xmtp_common::time::timeout(std::time::Duration::from_millis(100), stream.next()).await;
    assert!(result.is_err(), "Duplicate DM was unexpectedly streamed");
}

#[xmtp_common::timeout(std::time::Duration::from_secs(120))]
#[rstest::rstest]
#[case::five_dms(5)]
#[case::onehundred_dms(100)]
#[xmtp_common::test]
#[awt]
#[cfg_attr(all(feature = "d14n"), ignore)]
async fn test_many_concurrent_dm_invites(#[future] alix: ClientTester, #[case] dms: usize) {
    let alix_inbox_id = Arc::new(alix.inbox_id().to_string());
    let mut clients = vec![];
    for _ in 0..dms {
        let client =
            Arc::new(ClientBuilder::new_test_client_vanilla(&generate_local_wallet()).await);
        clients.push(client);
    }

    let stream = alix.stream_all_messages(None, None).await.unwrap();
    for client in clients.iter().take(dms) {
        xmtp_common::task::spawn({
            let id = alix_inbox_id.clone();
            let c = client.clone();
            async move {
                xmtp_common::time::sleep(std::time::Duration::from_millis(100)).await;
                let dm = c.find_or_create_dm(id.as_ref(), None).await?;
                dm.send_message(b"hi", SendMessageOpts::default()).await?;
                Ok::<_, crate::client::ClientError>(())
            }
        });
    }
    futures::pin_mut!(stream);
    for _ in 0..dms {
        let _welcome = stream.next().await;
    }
}
