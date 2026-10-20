#![deny(clippy::all)]

pub mod async_entry;
pub mod entry;
mod entry_builder;
pub mod keytar_compat;

#[cfg(target_os = "linux")]
mod linux_credential_builder;
pub mod options;
mod result;

#[cfg(target_os = "windows")]
mod windows_util;
