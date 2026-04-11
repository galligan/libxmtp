use super::{
    GroupError, MlsGroup, QueryableContentFields, SendMessageOpts,
    error::DeleteMessageError,
    intents::{QueueIntent, SendMessageIntentData},
    send_message_opts,
};
use crate::{context::XmtpSharedContext, utils::id::calculate_message_id};
use prost::Message;
use xmtp_common::time::now_ns;
use xmtp_configuration::{Originators, SEND_MESSAGE_UPDATE_INSTALLATIONS_INTERVAL_NS};
use xmtp_content_types::ContentCodec;
use xmtp_content_types::delete_message::DeleteMessageCodec;
use xmtp_db::{
    NotFound, Store,
    consent_record::ConsentState,
    group_message::{Deletable, DeliveryStatus, GroupMessageKind, StoredGroupMessage},
    message_deletion::{QueryMessageDeletion, StoredMessageDeletion},
    prelude::QueryGroupMessage,
};
use xmtp_proto::xmtp::mls::message_contents::{
    EncodedContent, PlaintextEnvelope,
    content_types::DeleteMessage,
    plaintext_envelope::{Content, V1},
};

impl<Context> MlsGroup<Context>
where
    Context: XmtpSharedContext,
{
    /// Send a message on this users XMTP [`Client`](crate::client::Client).
    #[cfg_attr(any(test, feature = "test-utils"), tracing::instrument(level = "info", skip_all, fields(who = self.context.inbox_id(), message = %String::from_utf8_lossy(&message[..message.len().min(100)]))))]
    #[cfg_attr(
        not(any(test, feature = "test-utils")),
        tracing::instrument(level = "trace", skip_all)
    )]
    pub async fn send_message(
        &self,
        message: &[u8],
        opts: send_message_opts::SendMessageOpts,
    ) -> Result<Vec<u8>, GroupError> {
        if !self.is_active()? {
            tracing::warn!("Unable to send a message on an inactive group.");
            return Err(GroupError::GroupInactive);
        }

        self.ensure_not_paused().await?;
        let update_interval_ns = Some(SEND_MESSAGE_UPDATE_INSTALLATIONS_INTERVAL_NS);
        self.maybe_update_installations(update_interval_ns).await?;

        // Check for pending proposals and commit them first.
        self.commit_pending_proposals_if_any().await?;

        let message_id =
            self.prepare_message(message, opts, |now| Self::into_envelope(message, now))?;

        self.sync_until_last_intent_resolved().await?;
        self.update_consent_state(ConsentState::Allowed)?;

        Ok(message_id)
    }

    /// Checks for pending MLS proposals and commits them if any exist.
    async fn commit_pending_proposals_if_any(&self) -> Result<(), GroupError> {
        let has_pending = self
            .load_mls_group_with_lock_async(async |openmls_group| {
                Ok::<bool, GroupError>(openmls_group.pending_proposals().next().is_some())
            })
            .await?;

        if has_pending {
            tracing::debug!(
                inbox_id = self.context.inbox_id(),
                group_id = hex::encode(&self.group_id),
                "Found pending proposals, committing before sending message"
            );

            let intent = QueueIntent::commit_pending_proposals().queue(self)?;
            self.sync_until_intent_resolved(intent.id).await?;
        }

        Ok(())
    }

    /// Publish all unpublished messages. This happens by calling `sync_until_last_intent_resolved`
    /// which publishes all pending intents and reads them back from the network.
    #[cfg_attr(any(test, feature = "test-utils"), tracing::instrument(level = "info", fields(who = self.context.inbox_id()), skip(self)))]
    #[cfg_attr(
        not(any(test, feature = "test-utils")),
        tracing::instrument(level = "trace", skip(self))
    )]
    pub async fn publish_messages(&self) -> Result<(), GroupError> {
        self.ensure_not_paused().await?;
        let update_interval_ns = Some(SEND_MESSAGE_UPDATE_INSTALLATIONS_INTERVAL_NS);
        self.maybe_update_installations(update_interval_ns).await?;
        self.sync_until_last_intent_resolved().await?;
        self.update_consent_state(ConsentState::Allowed)?;

        Ok(())
    }

    /// Send a message, optimistically returning the ID of the message before the result of a
    /// message publish.
    pub fn send_message_optimistic(
        &self,
        message: &[u8],
        opts: send_message_opts::SendMessageOpts,
    ) -> Result<Vec<u8>, GroupError> {
        let message_id =
            self.prepare_message(message, opts, |now| Self::into_envelope(message, now))?;
        Ok(message_id)
    }

    /// Prepare a message for later publishing.
    ///
    /// Stores the message locally with `Unpublished` delivery status but does NOT create an intent
    /// to publish. Use `publish_stored_message` to publish later.
    pub fn prepare_message_for_later_publish(
        &self,
        message: &[u8],
        should_push: bool,
    ) -> Result<Vec<u8>, GroupError> {
        let now = now_ns();
        let queryable_content_fields = Self::extract_queryable_content_fields(message);

        let message_id = calculate_message_id(&self.group_id, message, &now.to_string());
        let group_message = StoredGroupMessage {
            id: message_id.clone(),
            group_id: self.group_id.clone(),
            decrypted_message_bytes: message.to_vec(),
            sent_at_ns: now,
            kind: GroupMessageKind::Application,
            sender_installation_id: self.context.installation_id().into(),
            sender_inbox_id: self.context.inbox_id().to_string(),
            delivery_status: DeliveryStatus::Unpublished,
            content_type: queryable_content_fields.content_type,
            version_major: queryable_content_fields.version_major,
            version_minor: queryable_content_fields.version_minor,
            authority_id: queryable_content_fields.authority_id,
            reference_id: queryable_content_fields.reference_id,
            sequence_id: 0,
            originator_id: Originators::APPLICATION_MESSAGES.into(),
            expire_at_ns: None,
            inserted_at_ns: 0,
            should_push,
        };
        group_message.store(&self.context.db())?;

        Ok(message_id)
    }

    /// Publish a previously stored message by ID.
    #[cfg_attr(
        not(any(test, feature = "test-utils")),
        tracing::instrument(level = "trace", skip(self))
    )]
    pub async fn publish_stored_message(&self, message_id: &[u8]) -> Result<(), GroupError> {
        if !self.is_active()? {
            return Err(GroupError::GroupInactive);
        }
        self.ensure_not_paused().await?;

        let message = self
            .context
            .db()
            .get_group_message(message_id)?
            .ok_or_else(|| GroupError::NotFound(NotFound::MessageById(message_id.to_vec())))?;

        if message.delivery_status == DeliveryStatus::Published {
            return Ok(());
        }

        let plain_envelope =
            Self::into_envelope(&message.decrypted_message_bytes, message.sent_at_ns);
        let mut encoded_envelope = vec![];
        plain_envelope.encode(&mut encoded_envelope)?;

        let intent_data: Vec<u8> = SendMessageIntentData::new(encoded_envelope).into();
        QueueIntent::send_message()
            .data(intent_data)
            .should_push(message.should_push)
            .queue(self)?;

        self.maybe_update_installations(Some(SEND_MESSAGE_UPDATE_INSTALLATIONS_INTERVAL_NS))
            .await?;
        self.sync_until_last_intent_resolved().await?;
        self.update_consent_state(ConsentState::Allowed)?;

        Ok(())
    }

    /// Delete a message by its ID. Returns the ID of the deletion message.
    ///
    /// The wire protocol encodes `message_id` as a hex string, while the database stores raw
    /// bytes. This helper bridges between those two forms.
    pub fn delete_message(&self, message_id: Vec<u8>) -> Result<Vec<u8>, GroupError> {
        let conn = self.context.db();

        let original_msg = conn
            .get_group_message(&message_id)?
            .ok_or_else(|| DeleteMessageError::MessageNotFound(hex::encode(&message_id)))?;

        if original_msg.group_id != self.group_id {
            return Err(DeleteMessageError::NotAuthorized.into());
        }

        if conn.is_message_deleted(&message_id)? {
            return Err(DeleteMessageError::MessageAlreadyDeleted.into());
        }

        let sender_inbox_id = self.context.inbox_id();
        let is_sender = original_msg.sender_inbox_id == sender_inbox_id;
        let is_super_admin = self.is_super_admin(sender_inbox_id.to_string())?;

        if !is_sender && !is_super_admin {
            return Err(DeleteMessageError::NotAuthorized.into());
        }

        if !original_msg.kind.is_deletable() || !original_msg.content_type.is_deletable() {
            return Err(DeleteMessageError::NonDeletableMessage.into());
        }

        let delete_msg = DeleteMessage {
            message_id: hex::encode(&message_id),
        };

        let encoded_delete = DeleteMessageCodec::encode(delete_msg)?;
        let mut buf = Vec::new();
        encoded_delete.encode(&mut buf)?;

        let deletion_message_id = self.send_message_optimistic(&buf, SendMessageOpts::default())?;

        let is_super_admin_deletion = !is_sender && is_super_admin;
        let deletion = StoredMessageDeletion {
            id: deletion_message_id.clone(),
            group_id: self.group_id.clone(),
            deleted_message_id: message_id,
            deleted_by_inbox_id: sender_inbox_id.to_string(),
            is_super_admin_deletion,
            deleted_at_ns: now_ns(),
        };

        deletion.store(&conn)?;

        Ok(deletion_message_id)
    }

    pub(crate) fn extract_queryable_content_fields(message: &[u8]) -> QueryableContentFields {
        EncodedContent::decode(message)
            .inspect_err(|_| {
                tracing::debug!("No queryable content fields, msg not formatted as encoded content")
            })
            .and_then(|content| {
                QueryableContentFields::try_from(content).inspect_err(|e| {
                    tracing::debug!(
                        "Failed to convert EncodedContent to QueryableContentFields: {}",
                        e
                    )
                })
            })
            .unwrap_or_default()
    }

    #[tracing::instrument(skip_all, level = "trace")]
    pub(crate) fn prepare_message<F>(
        &self,
        message: &[u8],
        opts: send_message_opts::SendMessageOpts,
        envelope: F,
    ) -> Result<Vec<u8>, GroupError>
    where
        F: FnOnce(i64) -> PlaintextEnvelope,
    {
        let message_id = self.prepare_message_for_later_publish(message, opts.should_push)?;

        let stored_message = self
            .context
            .db()
            .get_group_message(&message_id)?
            .ok_or_else(|| GroupError::NotFound(NotFound::MessageById(message_id.clone())))?;

        let plain_envelope = envelope(stored_message.sent_at_ns);
        let mut encoded_envelope = vec![];
        plain_envelope.encode(&mut encoded_envelope)?;

        let intent_data: Vec<u8> = SendMessageIntentData::new(encoded_envelope).into();
        QueueIntent::send_message()
            .data(intent_data)
            .should_push(stored_message.should_push)
            .queue(self)?;

        Ok(message_id)
    }

    fn into_envelope(encoded_msg: &[u8], idempotency_key: i64) -> PlaintextEnvelope {
        PlaintextEnvelope {
            content: Some(Content::V1(V1 {
                content: encoded_msg.to_vec(),
                idempotency_key: idempotency_key.to_string(),
            })),
        }
    }
}
