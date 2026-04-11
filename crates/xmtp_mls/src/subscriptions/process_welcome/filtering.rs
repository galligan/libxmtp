use super::{ProcessWelcomeResult, Result};
use crate::{context::XmtpSharedContext, groups::MlsGroup};
use xmtp_db::{consent_record::ConsentState, group::ConversationType, prelude::*};
use xmtp_proto::types::{Cursor, OriginatorId, SequenceId};

#[derive(Clone)]
pub(super) struct WelcomeFilterConfig {
    conversation_type: Option<ConversationType>,
    include_duplicate_dms: bool,
    consent_states: Option<Vec<ConsentState>>,
}

impl WelcomeFilterConfig {
    pub(super) fn new(
        conversation_type: Option<ConversationType>,
        include_duplicate_dms: bool,
        consent_states: Option<Vec<ConsentState>>,
    ) -> Self {
        Self {
            conversation_type,
            include_duplicate_dms,
            consent_states,
        }
    }

    /// Checks whether a group should be included in the stream based on the current
    /// welcome-processing filter policy.
    async fn should_include_group<Context>(
        &self,
        context: &Context,
        group: &MlsGroup<Context>,
        check_virtual: bool,
    ) -> Result<bool>
    where
        Context: XmtpSharedContext,
    {
        let metadata = group.metadata().await?;

        // Filter out virtual groups only for freshly processed welcomes.
        if check_virtual && metadata.conversation_type.is_virtual() {
            tracing::debug!("Virtual group welcome processed. Skipping stream.");
            return Ok(false);
        }

        if !self.include_duplicate_dms
            && metadata.conversation_type == ConversationType::Dm
            && context.db().has_duplicate_dm(&group.group_id)?
        {
            tracing::debug!("Duplicate DM group detected. Skipping stream.");
            return Ok(false);
        }

        let conversation_type_match = self
            .conversation_type
            .is_none_or(|ct| ct == metadata.conversation_type);
        let consent_state_match = if let Some(ref consent_states) = self.consent_states {
            consent_states.contains(&group.consent_state()?)
        } else {
            true
        };

        Ok(conversation_type_match && consent_state_match)
    }

    /// Applies conversation and consent filtering to a processed welcome result and
    /// converts filtered payloads into the right ignore shape for the caller.
    pub(super) async fn filter_processed<Context>(
        &self,
        context: &Context,
        processed: ProcessWelcomeResult<Context>,
    ) -> Result<ProcessWelcomeResult<Context>>
    where
        Context: XmtpSharedContext,
    {
        match processed {
            ProcessWelcomeResult::New { group, id } => {
                if self.should_include_group(context, &group, true).await? {
                    Ok(ProcessWelcomeResult::New { group, id })
                } else {
                    Ok(ProcessWelcomeResult::IgnoreId { id })
                }
            }
            ProcessWelcomeResult::NewStored {
                group,
                maybe_sequence_id,
                maybe_originator,
            } => {
                if self.should_include_group(context, &group, false).await? {
                    Ok(ProcessWelcomeResult::NewStored {
                        group,
                        maybe_sequence_id,
                        maybe_originator,
                    })
                } else if let Some(id) = maybe_sequence_id
                    && let Some(originator) = maybe_originator
                {
                    Ok(ProcessWelcomeResult::IgnoreId {
                        id: Cursor::new(id as SequenceId, originator as OriginatorId),
                    })
                } else {
                    Ok(ProcessWelcomeResult::Ignore)
                }
            }
            other => Ok(other),
        }
    }
}
