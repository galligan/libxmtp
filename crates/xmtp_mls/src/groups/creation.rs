use super::{
    DmValidationError, GroupError, MetadataPermissionsError, MlsGroup,
    build_dm_mutable_metadata_extension_default, build_dm_protected_metadata_extension,
    build_group_config, build_mutable_metadata_extension_default,
    build_mutable_permissions_extension, build_protected_metadata_extension,
    build_starting_group_membership_extension,
    group_permissions::{GroupMutablePermissions, PolicySet, extract_group_permissions},
    mls_ext::CommitLogStorer,
};
use crate::context::XmtpSharedContext;
use openmls::prelude::{GroupId, MlsGroup as OpenMlsGroup};
use xmtp_common::time::now_ns;
use xmtp_db::{
    Store, StoreOrIgnore,
    consent_record::ConsentState,
    group::{ConversationType, GroupMembershipState, StoredGroup},
};
use xmtp_id::{InboxId, InboxIdRef};
use xmtp_mls_common::{
    group::{DMMetadataOptions, GroupMetadataOptions},
    group_metadata::{DmMembers, extract_group_metadata},
    group_mutable_metadata::GroupMutableMetadata,
};
use xmtp_proto::xmtp::mls::message_contents::OneshotMessage;

impl<Context> MlsGroup<Context>
where
    Context: XmtpSharedContext,
{
    // Create a new group and save it to the DB
    pub(crate) fn create_and_insert(
        context: Context,
        conversation_type: ConversationType,
        permissions_policy_set: PolicySet,
        opts: GroupMetadataOptions,
        oneshot_message: Option<OneshotMessage>,
    ) -> Result<Self, GroupError> {
        assert!(conversation_type != ConversationType::Dm);
        let stored_group = Self::insert(
            &context,
            None,
            GroupMembershipState::Allowed,
            conversation_type,
            permissions_policy_set,
            opts,
            oneshot_message,
        )?;
        let new_group = Self::new_from_arc(
            context.clone(),
            stored_group.id,
            stored_group.dm_id,
            conversation_type,
            stored_group.created_at_ns,
        );

        // Consent state defaults to allowed when the user creates the group
        if !conversation_type.is_virtual() {
            new_group.update_consent_state(ConsentState::Allowed)?;
        }

        Ok(new_group)
    }

    pub(crate) fn insert(
        context: &Context,
        existing_group_id: Option<&[u8]>,
        membership_state: GroupMembershipState,
        conversation_type: ConversationType,
        permissions_policy_set: PolicySet,
        opts: GroupMetadataOptions,
        oneshot_message: Option<OneshotMessage>,
    ) -> Result<StoredGroup, GroupError> {
        assert!(conversation_type != ConversationType::Dm);

        let creator_inbox_id = context.inbox_id();
        let protected_metadata = build_protected_metadata_extension(
            creator_inbox_id,
            conversation_type,
            oneshot_message,
        )?;
        let mutable_metadata =
            build_mutable_metadata_extension_default(creator_inbox_id, opts.clone())?;
        let group_membership = build_starting_group_membership_extension(creator_inbox_id, 0);
        let mutable_permissions = build_mutable_permissions_extension(permissions_policy_set)?;
        let group_config = build_group_config(
            protected_metadata,
            mutable_metadata,
            group_membership,
            mutable_permissions,
        )?;

        let provider = context.mls_provider();
        let mls_group = if let Some(existing_group_id) = existing_group_id {
            // TODO: For groups restored from backup, in order to support queries on metadata such as
            // the group title and description, a stubbed OpenMLS group is created, and later overwritten
            // when a welcome is received.
            OpenMlsGroup::from_backup_stub_logged(
                &provider,
                context.identity(),
                &group_config,
                GroupId::from_slice(existing_group_id),
            )?
        } else {
            OpenMlsGroup::from_creation_logged(&provider, context.identity(), &group_config)?
        };

        let group_id = mls_group.group_id().to_vec();
        // If not an existing group, the creator is a super admin and should publish the commit log
        // Otherwise, for existing groups, we'll never publish the commit log until we receive a welcome message
        let should_publish_commit_log = existing_group_id.is_none();

        let stored_group = StoredGroup::builder()
            .id(group_id.clone())
            .created_at_ns(now_ns())
            .membership_state(membership_state)
            .conversation_type(conversation_type)
            .added_by_inbox_id(context.inbox_id().to_string())
            .message_disappear_from_ns(
                opts.message_disappearing_settings
                    .as_ref()
                    .map(|m| m.from_ns),
            )
            .message_disappear_in_ns(opts.message_disappearing_settings.as_ref().map(|m| m.in_ns))
            .should_publish_commit_log(should_publish_commit_log)
            .build()?;

        stored_group.store_or_ignore(&context.db())?;

        Ok(stored_group)
    }

    // Create a new DM and save it to the DB
    pub(crate) fn create_dm_and_insert(
        context: &Context,
        membership_state: GroupMembershipState,
        dm_target_inbox_id: InboxId,
        opts: DMMetadataOptions,
        existing_group_id: Option<&[u8]>,
    ) -> Result<Self, GroupError> {
        let provider = context.mls_provider();
        let protected_metadata =
            build_dm_protected_metadata_extension(context.inbox_id(), dm_target_inbox_id.clone())?;
        let mutable_metadata = build_dm_mutable_metadata_extension_default(
            context.inbox_id(),
            &dm_target_inbox_id,
            opts.clone(),
        )?;
        let group_membership = build_starting_group_membership_extension(context.inbox_id(), 0);
        let mutable_permissions = PolicySet::new_dm();
        let mutable_permission_extension =
            build_mutable_permissions_extension(mutable_permissions)?;
        let group_config = build_group_config(
            protected_metadata,
            mutable_metadata,
            group_membership,
            mutable_permission_extension,
        )?;

        let mls_group = if let Some(group_id) = existing_group_id {
            OpenMlsGroup::from_backup_stub_logged(
                &provider,
                context.identity(),
                &group_config,
                GroupId::from_slice(group_id),
            )?
        } else {
            OpenMlsGroup::from_creation_logged(&provider, context.identity(), &group_config)?
        };

        let group_id = mls_group.group_id().to_vec();
        let stored_group = StoredGroup::builder()
            .id(group_id.clone())
            .created_at_ns(now_ns())
            .membership_state(membership_state)
            .added_by_inbox_id(context.inbox_id().to_string())
            .message_disappear_from_ns(
                opts.message_disappearing_settings
                    .as_ref()
                    .map(|m| m.from_ns),
            )
            .message_disappear_in_ns(opts.message_disappearing_settings.as_ref().map(|m| m.in_ns))
            .dm_id(Some(
                DmMembers {
                    member_one_inbox_id: dm_target_inbox_id,
                    member_two_inbox_id: context.identity().inbox_id().to_string(),
                }
                .to_string(),
            ))
            .build()?;

        stored_group.store(&context.db())?;
        let new_group = Self::new_from_arc(
            context.clone(),
            group_id.clone(),
            stored_group.dm_id,
            ConversationType::Dm,
            stored_group.created_at_ns,
        );
        // Consent state defaults to allowed when the user creates the group
        new_group.update_consent_state(ConsentState::Allowed)?;
        Ok(new_group)
    }

    // Super admin status is only criteria for whether to publish the commit log for now
    pub(crate) fn check_should_publish_commit_log(
        inbox_id: String,
        mutable_metadata: Option<GroupMutableMetadata>,
    ) -> bool {
        mutable_metadata
            .as_ref()
            .map(|metadata| metadata.is_super_admin(&inbox_id))
            .unwrap_or(false)
    }

    /// Used for testing that dm group validation works as expected.
    ///
    /// See the `test_validate_dm_group` test function for more details.
    #[cfg(test)]
    pub fn create_test_dm_group(
        context: Context,
        dm_target_inbox_id: InboxId,
        custom_protected_metadata: Option<openmls::extensions::Extension>,
        custom_mutable_metadata: Option<openmls::extensions::Extension>,
        custom_group_membership: Option<openmls::extensions::Extension>,
        custom_mutable_permissions: Option<PolicySet>,
        opts: Option<DMMetadataOptions>,
    ) -> Result<Self, GroupError> {
        let provider = context.mls_provider();

        let protected_metadata = custom_protected_metadata.unwrap_or_else(|| {
            build_dm_protected_metadata_extension(context.inbox_id(), dm_target_inbox_id.clone())
                .unwrap()
        });
        let mutable_metadata = custom_mutable_metadata.unwrap_or_else(|| {
            build_dm_mutable_metadata_extension_default(
                context.inbox_id(),
                &dm_target_inbox_id,
                opts.unwrap_or_default(),
            )
            .unwrap()
        });
        let group_membership = custom_group_membership
            .unwrap_or_else(|| build_starting_group_membership_extension(context.inbox_id(), 0));
        let mutable_permissions = custom_mutable_permissions.unwrap_or_else(PolicySet::new_dm);
        let mutable_permission_extension =
            build_mutable_permissions_extension(mutable_permissions)?;

        let group_config = build_group_config(
            protected_metadata,
            mutable_metadata,
            group_membership,
            mutable_permission_extension,
        )?;

        let mls_group =
            OpenMlsGroup::from_creation_logged(&provider, context.identity(), &group_config)?;
        let group_id = mls_group.group_id().to_vec();
        let stored_group = StoredGroup::builder()
            .id(group_id.clone())
            .created_at_ns(now_ns())
            .membership_state(GroupMembershipState::Allowed)
            .added_by_inbox_id(context.inbox_id().to_string())
            .dm_id(Some(
                DmMembers {
                    member_one_inbox_id: context.inbox_id().to_string(),
                    member_two_inbox_id: dm_target_inbox_id,
                }
                .to_string(),
            ))
            .build()?;

        stored_group.store(&context.db())?;
        Ok(Self::new_from_arc(
            context,
            group_id,
            stored_group.dm_id.clone(),
            ConversationType::Dm,
            stored_group.created_at_ns,
        ))
    }
}

pub(crate) trait DmValidationContext {
    fn inbox_id(&self) -> InboxIdRef<'_>;
}

impl<Context> DmValidationContext for Context
where
    Context: XmtpSharedContext,
{
    fn inbox_id(&self) -> InboxIdRef<'_> {
        XmtpSharedContext::inbox_id(self)
    }
}

pub(crate) fn validate_dm_group(
    context: impl DmValidationContext,
    mls_group: &OpenMlsGroup,
    added_by_inbox: &str,
) -> Result<(), MetadataPermissionsError> {
    // Validate dm specific immutable metadata
    let metadata = extract_group_metadata(mls_group.extensions())?;

    // 1) Check if the conversation type is DM
    if metadata.conversation_type != ConversationType::Dm {
        return Err(DmValidationError::InvalidConversationType.into());
    }

    // 2) If `dm_members` is not set, return an error immediately
    let dm_members = match &metadata.dm_members {
        Some(dm) => dm,
        None => {
            return Err(DmValidationError::MustHaveMembersSet.into());
        }
    };

    // 3) If the inbox that added this group is our inbox, make sure that
    //    one of the `dm_members` is our inbox id
    let inbox_id = context.inbox_id();
    if added_by_inbox == inbox_id {
        if !(dm_members.member_one_inbox_id == inbox_id
            || dm_members.member_two_inbox_id == inbox_id)
        {
            return Err(DmValidationError::OurInboxMustBeMember.into());
        }
        return Ok(());
    }

    // 4) Otherwise, make sure one of the `dm_members` is ours, and the other is `added_by_inbox`
    let is_expected_pair = (dm_members.member_one_inbox_id == added_by_inbox
        && dm_members.member_two_inbox_id == inbox_id)
        || (dm_members.member_one_inbox_id == inbox_id
            && dm_members.member_two_inbox_id == added_by_inbox);

    if !is_expected_pair {
        return Err(DmValidationError::ExpectedInboxesDoNotMatch.into());
    }

    // Validate mutable metadata
    let mutable_metadata: GroupMutableMetadata = mls_group.try_into()?;

    // Check if the admin list and super admin list are empty
    if !mutable_metadata.admin_list.is_empty() || !mutable_metadata.super_admin_list.is_empty() {
        return Err(DmValidationError::MustHaveEmptyAdminAndSuperAdmin.into());
    }

    // Validate permissions so no one adds us to a dm that they can unexpectedly add another member to
    // Note: we don't validate mutable metadata permissions, because they don't affect group membership
    let permissions = extract_group_permissions(mls_group)?;
    let expected_permissions = GroupMutablePermissions::new(PolicySet::new_dm());

    if permissions.policies.add_member_policy != expected_permissions.policies.add_member_policy
        && permissions.policies.remove_member_policy
            != expected_permissions.policies.remove_member_policy
        && permissions.policies.add_admin_policy != expected_permissions.policies.add_admin_policy
        && permissions.policies.remove_admin_policy
            != expected_permissions.policies.remove_admin_policy
        && permissions.policies.update_permissions_policy
            != expected_permissions.policies.update_permissions_policy
    {
        return Err(DmValidationError::InvalidPermissions.into());
    }

    Ok(())
}
