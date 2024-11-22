//! This crate provides common util code used in `rustls-mbedcrypto-provider` and `rustls-mbedpki-provider`

// Require docs for public APIs, deny unsafe code, etc.
#![forbid(unsafe_code, unused_must_use)]
#![cfg_attr(not(bench), forbid(unstable_features))]
#![deny(
    clippy::alloc_instead_of_core,
    clippy::clone_on_ref_ptr,
    clippy::std_instead_of_core,
    clippy::use_self,
    clippy::upper_case_acronyms,
    trivial_casts,
    trivial_numeric_casts,
    missing_docs,
    unreachable_pub,
    unused_import_braces,
    unused_extern_crates,
    // unused_qualifications
)]
// Enable documentation for all features on docs.rs
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(bench, feature(test))]
#![cfg_attr(not(test), no_std)]

extern crate alloc;

// This `extern crate` plus the `#![no_std]` attribute changes the default prelude from
// `std::prelude` to `core::prelude`. That forces one to _explicitly_ import (`use`) everything that
// is in `std::prelude` but not in `core::prelude`. This helps maintain no-std support as even
// developers that are not interested in, or aware of, no-std support and / or that never run
// `cargo build --no-default-features` locally will get errors when they rely on `std::prelude` API.
#[cfg(not(test))]
extern crate std;

/// Utility code related to error types: [`mbedtls::Error`] and [`rustls::Error`]
pub mod error;
/// Utility code related to [`mbedtls::hash`] types
pub mod hash;
/// Utility code related to [`mbedtls::pk`] types
pub mod pk;
