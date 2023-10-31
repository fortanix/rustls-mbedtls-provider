/// This build script allows us to enable the `read_buf` language feature only
/// for Rust Nightly.
///
/// - `read_buf`: When building with Rust Nightly, adds support for the unstable
///   `std::io::ReadBuf` and related APIs in `rustls`. This reduces costs from
///   initializing buffers. Will do nothing on non-Nightly releases.

#[cfg_attr(feature = "read_buf", rustversion::not(nightly))]
fn main() {}

#[cfg(feature = "read_buf")]
#[rustversion::nightly]
fn main() {
    println!("cargo:rustc-cfg=read_buf");
}
