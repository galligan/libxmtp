use super::{AvailableArchive, DeviceSyncError, IterWithContent};
use xmtp_archive::BackupMetadata;
use xmtp_common::{NS_IN_DAY, time::now_ns};
use xmtp_db::{group_message::StoredGroupMessage, prelude::*};
use xmtp_proto::xmtp::device_sync::content::{
    DeviceSyncReply as DeviceSyncReplyProto, device_sync_content::Content as ContentProto,
};

pub(crate) fn find_requested_archive_reply(
    conn: &impl DbQuery,
    pin: Option<&str>,
) -> Result<Option<(StoredGroupMessage, DeviceSyncReplyProto)>, DeviceSyncError> {
    let mut offset = 0;

    loop {
        let messages = conn.sync_group_messages_paged(offset, 100)?;
        if messages.is_empty() {
            return Ok(None);
        }

        offset += messages.len() as i64;
        for (msg, content) in messages.iter_with_content() {
            let reply = match (pin, content) {
                (None, ContentProto::Reply(reply)) => reply,
                (Some(pin), ContentProto::Reply(reply)) if reply.request_id == pin => reply,
                _ => continue,
            };

            return Ok(Some((msg, reply)));
        }
    }
}

pub(crate) fn list_available_archives_from_db(
    conn: &impl DbQuery,
    days_cutoff: i64,
) -> Result<Vec<AvailableArchive>, DeviceSyncError> {
    let mut offset = 0;
    let mut result = vec![];
    let cutoff = now_ns() - days_cutoff * NS_IN_DAY;

    'outer: loop {
        let messages = conn.sync_group_messages_paged(offset, 100)?;
        if messages.is_empty() {
            break;
        }

        offset += messages.len() as i64;
        for (msg, content) in messages.iter_with_content() {
            if msg.sent_at_ns < cutoff {
                break 'outer;
            }

            let ContentProto::Reply(reply) = content else {
                continue;
            };

            let Some(metadata) = reply.metadata else {
                tracing::warn!(
                    "Came across a device sync reply message with no metadata. request_id: {}",
                    reply.request_id
                );
                continue;
            };

            result.push(AvailableArchive {
                pin: reply.request_id,
                metadata: BackupMetadata::from_metadata_version_unknown(metadata),
                sent_by_installation: msg.sender_installation_id,
            });
        }
    }

    Ok(result)
}
