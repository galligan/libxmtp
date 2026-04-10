use super::*;

impl<Context> MlsGroup<Context>
where
    Context: XmtpSharedContext,
{
    pub(super) async fn post_process_message(
        &self,
        mls_group: &OpenMlsGroup,
        process_result: Result<MessageIdentifier, GroupMessageProcessingError>,
        envelope: &xmtp_proto::types::GroupMessage,
    ) -> Result<MessageIdentifier, GroupMessageProcessingError> {
        let message = match process_result {
            Ok(m) => {
                self.context.db().prune_icebox()?;
                tracing::info!(
                    "Transaction completed successfully: process for group [{}] envelope cursor[{}]",
                    &envelope.group_id,
                    envelope.cursor
                );
                Ok(m)
            }
            Err(GroupMessageProcessingError::CommitValidation(
                CommitValidationError::ProtocolVersionTooLow(min_version),
            )) => {
                // Instead of updating cursor, mark group as paused
                self.context
                    .db()
                    .set_group_paused(&self.group_id, &min_version)?;
                tracing::warn!(
                    "Group [{}] paused due to minimum protocol version requirement",
                    hex::encode(&self.group_id)
                );
                Err(GroupMessageProcessingError::GroupPaused)
            }
            Err(e) => {
                tracing::info!(
                    "Transaction failed: process for group [{}] envelope cursor [{}] error:[{}]",
                    &envelope.group_id,
                    envelope.cursor,
                    e
                );

                // Do not update the cursor if you have been removed from the group - you may be readded
                // later
                if !e.is_retryable() && mls_group.is_active()
                    && let Err(transaction_error) = self.context.mls_storage().transaction(|conn| {
                    let storage = conn.key_store();
                    let provider = XmtpOpenMlsProviderRef::new(&storage);
                    // TXN-EDGE: non-retryable cursor advancement + failed-commit accounting - unresolved
                    // TODO(rich): Add log_err! macro/trait for swallowing errors
                    if let Err(update_cursor_error) =
                        self.maybe_update_cursor(&storage.db(), envelope)
                    {
                        // We don't need to propagate the error if the cursor fails to update - the worst case is
                        // that the non-retriable error is processed again
                        tracing::error!("Error updating cursor for non-retriable error: {update_cursor_error:?}");
                    } else if envelope.is_commit()
                        && let Err(accounting_error) = mls_group.mark_failed_commit_logged(
                        &provider,
                        envelope.sequence_id(),
                        envelope.message.epoch(),
                        &e,
                    ) {
                        tracing::error!(
                                "Error inserting commit entry for failed commit: {}",
                                accounting_error
                        );
                    }
                    Ok::<(), GroupMessageProcessingError>(())
                }) {
                    tracing::error!("Error post-processing non-retryable error: {transaction_error:?}");
                };

                if let Err(accounting_error) = self
                    .process_group_message_error_for_fork_detection(
                        envelope.sequence_id(),
                        envelope.message.epoch(),
                        &e,
                        mls_group,
                    )
                    .await
                {
                    tracing::error!(
                        "Error trying to log fork detection errors: {}",
                        accounting_error
                    );
                }
                Err(e)
            }
        }?;
        Ok(message)
    }

    #[cfg_attr(
        any(test, feature = "test-utils"),
        tracing::instrument(level = "info", skip_all, fields(who = %self.context.inbox_id()))
    )]
    #[cfg_attr(
        not(any(test, feature = "test-utils")),
        tracing::instrument(level = "trace", skip_all)
    )]
    pub async fn process_messages(&self, messages: Vec<GroupMessage>) -> ProcessSummary {
        let mut summary = ProcessSummary::default();
        for message in messages {
            summary.add_id(message.cursor);

            let result = retry_async!(
                Retry::default(),
                (async { self.process_message(&message, true).await })
            );

            match result {
                Ok(m) => summary.add(m),
                Err(GroupMessageProcessingError::GroupPaused) => {
                    tracing::info!(
                        "Group [{}] is paused, skip syncing remaining messages",
                        hex::encode(&self.group_id),
                    );
                    return summary;
                }
                Err(e) => {
                    let is_retryable = e.is_retryable();
                    let error_message = e.to_string();
                    summary.errored(message.cursor, e);
                    // If the error is retryable we cannot move on to the next message
                    // otherwise you can get into a forked group state.
                    if is_retryable {
                        tracing::info!(
                            error = %error_message,
                            "Aborting message processing for retryable error: {}",
                            error_message
                        );
                        break;
                    }
                }
            }
        }
        summary
    }

    /// Receive messages from the last cursor network and try to process each message
    /// Return all the cursors of the messages we tried to process regardless
    /// if they were successful or not. It is important to return _all_
    /// cursor ids, so that streams do not unintentionally retry O(n^2) messages.
    #[tracing::instrument(skip_all, level = "trace")]
    pub async fn receive(&self) -> Result<ProcessSummary, GroupError> {
        let messages = MlsStore::new(self.context.clone())
            .query_group_messages(&self.group_id)
            .await?;

        let summary = self.process_messages(messages).await;
        Ok(summary)
    }
}
