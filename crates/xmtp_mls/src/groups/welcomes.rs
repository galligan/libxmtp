//! Welcome validation and import surfaces.
//!
//! The concrete welcome-processing logic lives in submodules so membership validation and XMTP
//! payload handling can evolve independently. This top-level module re-exports the pieces that the
//! rest of the group layer treats as the canonical welcome entrypoints.

mod validated_membership;
pub use validated_membership::*;

mod xmtp_welcome;
pub use xmtp_welcome::*;
