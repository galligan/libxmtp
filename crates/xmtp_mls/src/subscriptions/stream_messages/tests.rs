use crate::assert_msg;
use crate::groups::send_message_opts::SendMessageOpts;
use crate::tester;
use futures::stream::StreamExt;
use rstest::*;

#[xmtp_common::timeout(std::time::Duration::from_secs(30))]
#[rstest]
#[xmtp_common::test]
#[cfg_attr(target_arch = "wasm32", ignore)]
async fn test_stream_messages() {
    tester!(alice, with_name: "alice");
    tester!(bob, with_name: "bob");

    let alice_group = alice.create_group(None, None).unwrap();
    tracing::info!("Group Id = [{}]", hex::encode(&alice_group.group_id));

    alice_group.add_members(&[bob.inbox_id()]).await.unwrap();
    let bob_groups = bob.sync_welcomes().await.unwrap();
    let bob_group = bob_groups.first().unwrap();
    alice_group.sync().await.unwrap();

    let stream = alice_group.stream().await.unwrap();
    futures::pin_mut!(stream);
    bob_group
        .send_message(b"hello", SendMessageOpts::default())
        .await
        .unwrap();

    assert_msg!(stream, "hello");

    bob_group
        .send_message(b"hello2", SendMessageOpts::default())
        .await
        .unwrap();
    assert_msg!(stream, "hello2");
}
