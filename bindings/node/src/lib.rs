//! Node.js entrypoint for libxmtp bindings.
//!
//! The napi surface is intentionally organized around a few compatibility
//! boundaries: Rust error translation, JS-friendly stream callbacks, and thin
//! wrappers over the shared Rust client types.

#![recursion_limit = "256"]
#![warn(clippy::unwrap_used)]

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

pub mod builder;
pub mod client;
mod consent_state;
pub mod content_types;
pub mod conversation;
pub mod conversations;
pub mod device_sync;
pub mod hmac_key;
mod identity;
pub mod inbox_id;
mod inbox_state;
mod messages;
mod permissions;
mod signatures;
pub mod stats;
mod streams;
xmtp_common::if_test! {
  pub mod test_utils;
}

use napi::bindgen_prelude::Error;
use xmtp_common::ErrorCode;

/// Wrapper for errors that implement `ErrorCode`.
///
/// This is the Node compatibility layer for surfaced Rust errors. We preserve
/// the machine-readable code in the JS-visible message format rather than
/// exporting Rust error enums directly through napi.
///
/// Format: `[ErrorType::Variant] error message`
///
/// JavaScript usage:
/// ```js
/// try {
///   await client.doSomething();
/// } catch (e) {
///   console.log(e.message); // "[ErrorType::Variant] error message"
/// }
/// ```
#[derive(Debug)]
pub struct ErrorWrapper<E>(pub E)
where
  E: ErrorCode;

impl<T: ErrorCode> std::fmt::Display for ErrorWrapper<T> {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    std::fmt::Display::fmt(&self.0, f)
  }
}

impl<T> From<T> for ErrorWrapper<T>
where
  T: ErrorCode,
{
  fn from(err: T) -> ErrorWrapper<T> {
    ErrorWrapper(err)
  }
}

impl<T: ErrorCode> From<ErrorWrapper<T>> for napi::bindgen_prelude::Error {
  fn from(e: ErrorWrapper<T>) -> napi::bindgen_prelude::Error {
    let code = e.0.error_code();
    Error::from_reason(format!("[{}] {}", code, e.0))
  }
}
