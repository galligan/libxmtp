#![recursion_limit = "256"]
#![warn(clippy::unwrap_used)]

pub mod builder;
pub mod client;
pub mod context;
pub mod cursor_store;
mod definitions;
pub mod groups;
pub mod identity;
pub mod identity_updates;
mod intents;
pub mod messages;
pub mod mls_store;
mod mutex_registry;
pub mod registration_visible;
pub mod subscriptions;
pub mod utils;
pub mod worker;
pub use builder::{DeviceSyncMode, ForkRecoveryOpts, ForkRecoveryPolicy};
pub use client::inbox_addresses_with_verifier;
pub use context::{XmtpMlsLocalContext, XmtpSharedContext};
pub use cursor_store::SqliteCursorStore;
pub use definitions::*;
pub use groups::{
    ConversationDebugInfo, MlsGroup, PreconfiguredPolicies, UpdateAdminListType,
    welcome_sync::GroupSyncSummary,
};
pub use identity::IdentityStrategy;
pub use identity_updates::{
    apply_signature_request_with_verifier, get_creation_signature_kind,
    is_member_of_association_state, revoke_installations_with_verifier,
};
pub use messages::decoded_message::{
    DecodedMessage, DecodedMessageMetadata, DeletedBy, Markdown, MessageBody,
    Reply as DecodedReply, Text,
};
pub use registration_visible::{Quorum, VisibilityConfirmationOptions};
pub use subscriptions::SubscribeError;

#[cfg(any(test, feature = "test-utils"))]
pub mod test;
#[cfg(test)]
mod tests;
mod traits;

use crate::groups::GroupError;
pub use client::{Client, Network};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex as TokioMutex;
pub use xmtp_common as common;
pub use xmtp_db as db;
use xmtp_db::{DuplicateItem, StorageError};
pub use xmtp_id::InboxOwner;
pub use xmtp_mls_common as mls_common;
pub use xmtp_proto::api_client::*;

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// A manager for group-specific semaphores
#[derive(Debug)]
pub struct GroupCommitLock {
    // Storage for group-specific semaphores
    locks: Mutex<HashMap<Vec<u8>, Arc<TokioMutex<()>>>>,
}

impl Default for GroupCommitLock {
    fn default() -> Self {
        Self::new()
    }
}
impl GroupCommitLock {
    /// Create a new `GroupCommitLock`
    pub fn new() -> Self {
        Self {
            locks: Mutex::new(HashMap::new()),
        }
    }

    /// Get or create a semaphore for a specific group and acquire it, returning a guard
    pub async fn get_lock_async(&self, group_id: Vec<u8>) -> MlsGroupGuard {
        let lock = {
            let mut locks = self.locks.lock();
            locks
                .entry(group_id)
                .or_insert_with(|| Arc::new(TokioMutex::new(())))
                .clone()
        };

        MlsGroupGuard {
            _permit: lock.lock_owned().await,
        }
    }

    /// Get or create a semaphore for a specific group and acquire it synchronously
    pub fn get_lock_sync(&self, group_id: Vec<u8>) -> Result<MlsGroupGuard, GroupError> {
        let lock = {
            let mut locks = self.locks.lock();
            locks
                .entry(group_id)
                .or_insert_with(|| Arc::new(TokioMutex::new(())))
                .clone()
        };

        // Synchronously acquire the permit
        let permit = lock
            .try_lock_owned()
            .map_err(|_| GroupError::LockUnavailable)?;
        Ok(MlsGroupGuard { _permit: permit })
    }
}
/// A guard that releases the semaphore when dropped
pub struct MlsGroupGuard {
    _permit: tokio::sync::OwnedMutexGuard<()>,
}

#[cfg_attr(not(target_arch = "wasm32"), ctor::ctor)]
#[cfg(all(test, not(target_arch = "wasm32")))]
fn test_setup() {
    xmtp_common::logger();
    let _ = fdlimit::raise_fd_limit();
}
