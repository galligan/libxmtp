use super::{
    GroupError, MlsGroup, build_proposals_enabled_extension, check_proposals_enabled, intents,
    update_required_capabilities_for_proposals,
};
use crate::context::XmtpSharedContext;
use openmls::{
    extensions::{ExtensionType, Extensions},
    group::GroupContext,
    key_packages::KeyPackage,
    prelude::MlsGroup as OpenMlsGroup,
};
use xmtp_configuration::PROPOSAL_SUPPORT_EXTENSION_ID;

impl<Context> MlsGroup<Context>
where
    Context: XmtpSharedContext,
{
    /// Check if all members in the group support the proposal-by-reference flow.
    ///
    /// This checks both:
    /// 1. Leaf node capabilities in the MLS group (via `check_extension_support`)
    /// 2. The latest published key packages for all member installations fetched
    ///    from the network, since leaf nodes may be stale (they aren't updated after
    ///    the first message is sent).
    ///
    /// Returns `true` if all members support proposals, `false` otherwise.
    pub async fn all_members_support_proposals(
        &self,
        mls_group: &OpenMlsGroup,
    ) -> Result<bool, GroupError> {
        let extension_type = ExtensionType::Unknown(PROPOSAL_SUPPORT_EXTENSION_ID);

        // Check leaf nodes in the group first (fast path).
        // If all leaf nodes advertise support, we're done — no network call needed.
        if mls_group.check_extension_support(&[extension_type]).is_ok() {
            return Ok(true);
        }

        // Leaf nodes can be stale (they aren't updated after the first message),
        // so fall back to checking the latest published key packages from the network.
        let installation_ids: Vec<Vec<u8>> = mls_group
            .members()
            .map(|member| member.signature_key)
            .filter(|id| id.as_slice() != self.context.installation_id().as_slice())
            .collect();

        if installation_ids.is_empty() {
            return Ok(true);
        }

        let store = crate::mls_store::MlsStore::new(self.context.clone());
        let key_packages = store
            .get_key_packages_for_installation_ids(installation_ids)
            .await?;

        for result in key_packages.values() {
            match result {
                Ok(verified_kp) => {
                    let capabilities = verified_kp.inner.leaf_node().capabilities();
                    if !capabilities.extensions().contains(&extension_type) {
                        return Ok(false);
                    }
                }
                Err(_) => {
                    return Ok(false);
                }
            }
        }

        Ok(true)
    }

    /// Check if the group has proposals enabled (proposal-by-reference flow).
    ///
    /// This checks if the group context contains the `PROPOSAL_SUPPORT_EXTENSION_ID`
    /// extension with a `ProposalSupport` proto.
    ///
    /// When proposals are enabled on a group:
    /// - Add/remove member operations MUST use proposals
    /// - All members being added MUST support the proposal extension
    /// - Direct commits for membership changes are not allowed
    pub fn proposals_enabled(&self, mls_group: &OpenMlsGroup) -> bool {
        check_proposals_enabled(mls_group.extensions())
    }

    /// Enable proposals on this group (proposal-by-reference flow).
    ///
    /// This sets the `PROPOSAL_SUPPORT_EXTENSION_ID` extension on the group context.
    /// Once enabled:
    /// - All add/remove member operations will use proposals
    /// - All members being added must support proposals
    /// - This cannot be disabled once set
    ///
    /// # Prerequisites
    ///
    /// Before calling this method, ensure all existing members support proposals
    /// by calling `all_members_support_proposals()`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Not all existing members support proposals
    /// - The group context extension update fails
    pub async fn enable_proposals(&self) -> Result<(), GroupError> {
        // Check support AND build extensions in a single lock acquisition to avoid
        // a race where membership changes between the check and the build.
        let new_extensions = self
            .load_mls_group_with_lock_async(async |mls_group| {
                if !self.all_members_support_proposals(&mls_group).await? {
                    return Err(GroupError::ProposalsNotSupported(
                        "Cannot enable proposals: not all members support the proposal extension"
                            .to_string(),
                    ));
                }
                let mut extensions: Extensions<GroupContext> = mls_group.extensions().clone();
                extensions.add_or_replace(build_proposals_enabled_extension())?;
                update_required_capabilities_for_proposals(&mut extensions, true)?;
                Ok(extensions)
            })
            .await?;

        // Queue and publish the GCE proposal
        use openmls::prelude::tls_codec::Serialize;
        let extensions_bytes = new_extensions.tls_serialize_detached()?;

        let intent_data = intents::ProposeGroupContextExtensionsIntentData::new(extensions_bytes);
        let proposal_intent = intents::QueueIntent::propose_group_context_extensions()
            .data(intent_data)
            .queue(self)?;

        self.sync_until_intent_resolved(proposal_intent.id).await?;

        // Re-verify after sync: incoming messages processed during sync may have
        // changed group membership (e.g. a member was added who doesn't support
        // proposals). Abort before committing if support no longer holds.
        let still_supported = self
            .load_mls_group_with_lock_async(async |mls_group| {
                self.all_members_support_proposals(&mls_group).await
            })
            .await?;

        if !still_supported {
            return Err(GroupError::ProposalsNotSupported(
                "Cannot enable proposals: group membership changed and not all members support the proposal extension"
                    .to_string(),
            ));
        }

        // Commit the pending proposals to apply the extension
        let commit_intent = intents::QueueIntent::commit_pending_proposals()
            .data(intents::CommitPendingProposalsIntentData::new())
            .queue(self)?;

        self.sync_until_intent_resolved(commit_intent.id).await?;

        let enabled = self
            .load_mls_group_with_lock_async(async |mls_group| {
                Ok::<bool, GroupError>(self.proposals_enabled(&mls_group))
            })
            .await?;

        if !enabled {
            return Err(GroupError::ProposalsNotSupported(
                "Failed to enable proposals: extension not applied".to_string(),
            ));
        }

        Ok(())
    }

    /// Validate that key packages support the proposal extension.
    ///
    /// This checks if all provided key packages have the `PROPOSAL_SUPPORT_EXTENSION_ID`
    /// in their capabilities, meaning the installations can receive standalone proposals.
    pub fn validate_key_packages_support_proposals(
        &self,
        key_packages: &[KeyPackage],
    ) -> Result<(), GroupError> {
        let extension_type = ExtensionType::Unknown(PROPOSAL_SUPPORT_EXTENSION_ID);

        for kp in key_packages {
            let leaf_node = kp.leaf_node();
            let capabilities = leaf_node.capabilities();

            if !capabilities.extensions().contains(&extension_type) {
                return Err(GroupError::ProposalsNotSupported(
                    "Member does not support proposals: installation cannot receive standalone proposal messages".to_string(),
                ));
            }
        }

        Ok(())
    }
}
