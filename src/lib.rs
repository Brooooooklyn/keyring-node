#![deny(clippy::all)]

pub mod async_entry;
pub mod entry;
mod entry_builder;

#[cfg(target_os = "linux")]
mod linux_credential_builder;
pub mod options;
mod result;
