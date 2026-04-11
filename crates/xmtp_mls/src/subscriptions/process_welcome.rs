mod filtering;
mod loading;

use super::Result;
use crate::context::XmtpSharedContext;
use crate::{groups::MlsGroup, subscriptions::WelcomeOrGroup};
use filtering::WelcomeFilterConfig;
use std::collections::HashSet;
use xmtp_db::{consent_record::ConsentState, group::ConversationType};
use xmtp_proto::types::{Cursor, WelcomeMessage};

/// Future for processing `WelcomeorGroup`
pub struct ProcessWelcomeFuture<Context> {
    /// welcome ids in DB and which are already processed
    known_welcome_ids: HashSet<Cursor>,
    /// The libxmtp client
    context: Context,
    /// the welcome or group being processed in this future
    item: WelcomeOrGroup,
    /// Filter policy for conversation type, duplicate DM handling, and consent state.
    filters: WelcomeFilterConfig,
}

pub enum ProcessWelcomeResult<Context> {
    /// New Group and welcome id
    New {
        group: MlsGroup<Context>,
        id: Cursor,
    },
    /// A group we already have/we created that might not have a welcome id
    NewStored {
        group: MlsGroup<Context>,
        maybe_sequence_id: Option<i64>,
        maybe_originator: Option<i64>,
    },
    /// Skip this welcome but add and id to known welcome ids
    IgnoreId { id: Cursor },
    /// Skip this payload
    Ignore,
}

impl<Context> ProcessWelcomeFuture<Context>
where
    Context: XmtpSharedContext,
{
    /// Creates a new `ProcessWelcomeFuture` to handle processing of welcome messages or groups.
    ///
    /// This function initializes the future that will handle the core logic for
    /// processing a welcome message or group identifier. It captures all necessary
    /// context for the asynchronous processing operation.
    ///
    /// # Arguments
    /// * `known_welcome_ids` - Set of already processed welcome IDs for deduplication
    /// * `client` - The client to use for processing and database operations
    /// * `item` - The welcome message or group to process
    /// * `conversation_type` - Optional filter for specific conversation types
    /// * `include_duplicate_dms` - Optional filter to include duplicate dms in the stream
    /// * `consent_states` - Optional filter for specific consent states
    ///
    /// # Returns
    /// * `Result<ProcessWelcomeFuture<C>>` - A new future for processing
    ///
    /// # Errors
    /// Returns an error if initialization fails
    ///
    /// # Example
    pub fn new(
        known_welcome_ids: HashSet<Cursor>,
        context: Context,
        item: WelcomeOrGroup,
        conversation_type: Option<ConversationType>,
        include_duplicate_dms: bool,
        consent_states: Option<Vec<ConsentState>>,
    ) -> Result<ProcessWelcomeFuture<Context>> {
        Ok(Self {
            known_welcome_ids,
            context,
            item,
            filters: WelcomeFilterConfig::new(
                conversation_type,
                include_duplicate_dms,
                consent_states,
            ),
        })
    }
}

/// bulk of the processing for a new welcome/group
impl<Context> ProcessWelcomeFuture<Context>
where
    Context: XmtpSharedContext,
{
    /// Processes a welcome message or group.
    ///
    /// handles new conversation events. It implements different processing paths for welcome
    /// messages versus group identifiers:
    ///
    /// For welcome messages:
    /// 1. Extracts the welcome payload and ID
    /// 2. Checks if the welcome has already been processed (fast path)
    /// 3. If not, triggers network synchronization for the welcome
    /// 4. Loads the resulting group from the database
    ///
    /// For groups:
    /// 1. Validates and loads the group from the database
    /// 2. Captures any associated welcome ID
    ///
    /// Finally, it applies conversation type filtering to determine if the
    /// conversation should be streamed to the client.
    ///
    /// # Returns
    /// * `Result<ProcessWelcomeResult<C>>` - The processing result indicating
    ///   how the welcome/group should be handled
    ///
    /// # Errors
    /// Returns an error if any step in the processing pipeline fails
    ///
    /// # Tracing
    #[tracing::instrument(skip_all)]
    pub async fn process(self) -> Result<ProcessWelcomeResult<Context>> {
        use WelcomeOrGroup::*;
        let process_result = match self.item {
            Welcome(ref welcome) => {
                tracing::debug!("got welcome with id {}", welcome.cursor);
                // try to load it from store first and avoid overhead
                // of processing a welcome & erroring
                // for immediate return, this must stay in the top-level future,
                // to avoid a possible yield on the await in on_welcome.
                if self.known_welcome_ids.contains(&welcome.cursor) {
                    tracing::debug!(
                        "Found existing welcome. Returning from db & skipping processing"
                    );
                    if let Ok(Some(group)) = self.load_from_store(welcome.cursor) {
                        return self
                            .filters
                            .filter_processed(
                                &self.context,
                                ProcessWelcomeResult::New {
                                    group,
                                    id: welcome.cursor,
                                },
                            )
                            .await;
                    }
                }
                tracing::info!(
                    "could not find group for welcome {}, processing",
                    welcome.cursor
                );
                // sync welcome from the network
                if let Some(group) = self.on_welcome(welcome).await? {
                    ProcessWelcomeResult::New {
                        group,
                        id: welcome.cursor,
                    }
                } else {
                    tracing::info!("Oneshot welcome message processed, skipping stream event.");
                    ProcessWelcomeResult::IgnoreId { id: welcome.cursor }
                }
            }
            Group(ref id) => {
                tracing::info!("stream got existing group, pulling from db.");
                let (group, stored_group) = MlsGroup::new_cached(self.context.clone(), id)?;

                ProcessWelcomeResult::NewStored {
                    group,
                    maybe_sequence_id: stored_group.sequence_id,
                    maybe_originator: stored_group.originator_id,
                }
            }
        };
        self.filters
            .filter_processed(&self.context, process_result)
            .await
    }

    /// Processes a new welcome message by syncing with the network.
    ///
    /// This method handles the synchronization of a welcome message with the network,
    /// retrieving the associated group data. The process involves:
    ///
    /// 1. Extracting metadata from the welcome message
    /// 2. Logging the processing attempt
    /// 3. Triggering welcome synchronization with retry logic
    /// 4. Loading the resulting group from the database
    ///
    /// # Arguments
    /// * `welcome` - The welcome message (V1) to process
    ///
    /// # Returns
    /// * `Result<(MlsGroup<Context>, i64)>` - A tuple containing:
    ///   - The MLS group associated with the welcome, if there is one
    ///   - The welcome ID for tracking
    ///
    /// # Errors
    /// Returns an error if synchronization fails or the group cannot be found
    ///
    /// # Note
    /// This function uses retry logic to handle transient network failures
    async fn on_welcome(&self, welcome: &WelcomeMessage) -> Result<Option<MlsGroup<Context>>> {
        tracing::info!(
            welcome_id = %welcome.cursor,
            "Trying to process streamed welcome"
        );
        loading::process_welcome_from_network(&self.context, welcome).await
    }

    /// Load a group from disk by its welcome_id
    fn load_from_store(&self, cursor: Cursor) -> Result<Option<MlsGroup<Context>>> {
        loading::load_from_store(&self.context, cursor)
    }
}
