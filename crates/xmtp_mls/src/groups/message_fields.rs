use prost::Message;
use xmtp_content_types::ContentCodec;
use xmtp_content_types::delete_message::DeleteMessageCodec;
use xmtp_content_types::reaction::{LegacyReaction, ReactionCodec};
use xmtp_content_types::reply::ReplyCodec;
use xmtp_db::group_message::ContentType;
use xmtp_proto::xmtp::mls::message_contents::{
    EncodedContent,
    content_types::{DeleteMessage, ReactionV2},
};

/// Fields extracted from content of a message that should be stored in the DB.
pub(crate) struct QueryableContentFields {
    pub content_type: ContentType,
    pub version_major: i32,
    pub version_minor: i32,
    pub authority_id: String,
    pub reference_id: Option<Vec<u8>>,
}

impl Default for QueryableContentFields {
    fn default() -> Self {
        Self {
            content_type: ContentType::Unknown,
            version_major: 0,
            version_minor: 0,
            authority_id: String::new(),
            reference_id: None,
        }
    }
}

impl TryFrom<EncodedContent> for QueryableContentFields {
    type Error = prost::DecodeError;

    fn try_from(content: EncodedContent) -> Result<Self, Self::Error> {
        let content_type_id = content.r#type.clone().unwrap_or_default();
        let type_id_str = content_type_id.type_id.clone();

        let reference_id = match (type_id_str.as_str(), content_type_id.version_major) {
            (ReplyCodec::TYPE_ID, 1) => ReplyCodec::decode(content)
                .ok()
                .and_then(|reply| hex::decode(reply.reference).ok()),
            (ReactionCodec::TYPE_ID, major) if major >= 2 => {
                ReactionV2::decode(content.content.as_slice())
                    .ok()
                    .and_then(|reaction| hex::decode(reaction.reference).ok())
            }
            (ReactionCodec::TYPE_ID, _) => LegacyReaction::decode(&content.content)
                .and_then(|legacy_reaction| hex::decode(legacy_reaction.reference).ok()),
            (DeleteMessageCodec::TYPE_ID, DeleteMessageCodec::MAJOR_VERSION) => {
                DeleteMessage::decode(content.content.as_slice())
                    .ok()
                    .and_then(|delete_msg| hex::decode(delete_msg.message_id).ok())
            }
            _ => None,
        };

        Ok(Self {
            content_type: content_type_id.type_id.into(),
            version_major: content_type_id.version_major as i32,
            version_minor: content_type_id.version_minor as i32,
            authority_id: content_type_id.authority_id.to_string(),
            reference_id,
        })
    }
}
