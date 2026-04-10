use super::*;

pub(super) async fn calculate_membership_changes_with_keypackages<'a>(
    context: &impl XmtpSharedContext,
    group_id: &[u8],
    new_group_membership: &'a GroupMembership,
    old_group_membership: &'a GroupMembership,
) -> Result<MembershipDiffWithKeyPackages, GroupError> {
    let membership_diff = old_group_membership.diff(new_group_membership);

    let identity = IdentityUpdates::new(&context);
    let mut installation_diff = identity
        .get_installation_diff(
            &context.db(),
            group_id,
            old_group_membership,
            new_group_membership,
            &membership_diff,
        )
        .await?;

    let mut new_installations = Vec::new();
    let mut new_key_packages = Vec::new();
    let mut new_failed_installations = Vec::new();

    if !installation_diff.added_installations.is_empty() {
        get_keypackages_for_installation_ids(
            context,
            installation_diff.added_installations,
            &mut new_installations,
            &mut new_key_packages,
            &mut new_failed_installations,
        )
        .await?;
    }

    let mut failed_installations: HashSet<Vec<u8>> = old_group_membership
        .failed_installations
        .clone()
        .into_iter()
        .chain(new_failed_installations)
        .collect();

    let common: HashSet<_> = failed_installations
        .intersection(&installation_diff.removed_installations)
        .cloned()
        .collect();

    failed_installations.retain(|item| !common.contains(item));

    installation_diff
        .removed_installations
        .retain(|item| !common.contains(item));

    Ok(MembershipDiffWithKeyPackages::new(
        new_installations,
        new_key_packages,
        installation_diff.removed_installations,
        failed_installations.into_iter().collect(),
    ))
}

#[allow(dead_code)]
#[cfg(any(test, feature = "test-utils"))]
async fn inject_failed_installations_for_test(
    key_packages: &mut HashMap<
        Vec<u8>,
        Result<
            xmtp_id::key_package::VerifiedKeyPackageV2,
            xmtp_id::key_package::KeyPackageVerificationError,
        >,
    >,
    failed_installations: &mut Vec<Vec<u8>>,
) {
    use crate::utils::test_mocks_helpers::{
        get_test_mode_malformed_installations, is_test_mode_upload_malformed_keypackage,
    };
    if is_test_mode_upload_malformed_keypackage() {
        let malformed_installations = get_test_mode_malformed_installations();
        key_packages.retain(|id, _| !malformed_installations.contains(id));
        failed_installations.extend(malformed_installations);
    }
}

pub(super) async fn get_keypackages_for_installation_ids(
    context: impl XmtpSharedContext,
    requested_installations: HashSet<Vec<u8>>,
    fetched_installations: &mut Vec<Installation>,
    fetched_key_packages: &mut Vec<KeyPackage>,
    failed_installations: &mut Vec<Vec<u8>>,
) -> Result<(), GroupError> {
    let my_installation_id = context.installation_id().to_vec();
    let store = MlsStore::new(context.clone());
    #[allow(unused_mut)]
    let mut key_packages = store
        .get_key_packages_for_installation_ids(
            requested_installations
                .iter()
                .filter(|installation| my_installation_id.ne(*installation))
                .cloned()
                .collect(),
        )
        .await?;

    #[cfg(any(test, feature = "test-utils"))]
    inject_failed_installations_for_test(&mut key_packages, failed_installations).await;

    for (installation_id, result) in key_packages {
        match result {
            Ok(verified_key_package) => {
                fetched_installations.push(Installation::from_verified_key_package(
                    &verified_key_package,
                )?);
                fetched_key_packages.push(verified_key_package.inner.clone());
            }
            Err(_) => failed_installations.push(installation_id.clone()),
        }
    }

    Ok(())
}

pub(super) fn get_removed_leaf_nodes(
    openmls_group: &mut OpenMlsGroup,
    removed_installations: &HashSet<Vec<u8>>,
) -> Vec<LeafNodeIndex> {
    openmls_group
        .members()
        .filter(|member| removed_installations.contains(&member.signature_key))
        .map(|member| member.index)
        .collect()
}
