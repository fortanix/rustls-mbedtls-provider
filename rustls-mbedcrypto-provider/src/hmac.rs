/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

use crate::log::error;
use alloc::boxed::Box;
use rustls::crypto;

/// HMAC using SHA-256.
pub(crate) static HMAC_SHA256: Hmac = Hmac(&super::hash::MBED_SHA_256);

/// HMAC using SHA-384.
pub(crate) static HMAC_SHA384: Hmac = Hmac(&super::hash::MBED_SHA_384);

pub(crate) struct Hmac(pub(crate) &'static super::hash::Algorithm);

impl crypto::hmac::Hmac for Hmac {
    fn with_key(&self, key: &[u8]) -> Box<dyn crypto::hmac::Key> {
        Box::new(HmacKey(MbedHmacKey::new(self.0, key)))
    }

    fn hash_output_len(&self) -> usize {
        self.0.output_len
    }
}

impl Hmac {
    #[inline]
    pub(crate) fn hash_algorithm(&self) -> &'static super::hash::Algorithm {
        self.0
    }
}

struct HmacKey(MbedHmacKey);

impl crypto::hmac::Key for HmacKey {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> rustls::crypto::hmac::Tag {
        let mut ctx = self.0.starts();
        ctx.update(first);
        for m in middle {
            ctx.update(m);
        }
        ctx.update(last);
        ctx.finish().into()
    }

    fn tag_len(&self) -> usize {
        self.0.hmac_algo.output_len
    }
}

struct MbedHmacKey {
    hmac_algo: &'static super::hash::Algorithm,
    key: Tag,
}

impl MbedHmacKey {
    pub(crate) fn new(hmac_algo: &'static super::hash::Algorithm, key: &[u8]) -> Self {
        Self { hmac_algo, key: Tag::new(key) }
    }

    pub(crate) fn starts(&self) -> MbedHmacContext {
        MbedHmacContext {
            hmac_algo: self.hmac_algo,
            ctx: mbedtls::hash::Hmac::new(self.hmac_algo.hash_type, self.key.as_ref()).expect("input validated"),
        }
    }
}

struct MbedHmacContext {
    hmac_algo: &'static super::hash::Algorithm,
    ctx: mbedtls::hash::Hmac,
}

impl MbedHmacContext {
    /// Since the trait does not provider a way to return error, empty vector is returned when getting error from `mbedtls`.
    pub(crate) fn finish(self) -> Tag {
        let mut out = Tag::with_len(self.hmac_algo.output_len);
        match self.ctx.finish(out.as_mut()) {
            Ok(_) => out,
            Err(_err) => {
                error!("Failed to finish hmac, mbedtls error: {:?}", _err);
                Tag::with_len(0)
            }
        }
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        match self.ctx.update(data) {
            Ok(_) => {}
            Err(_err) => {
                error!("Failed to update hmac, mbedtls error: {:?}", _err);
            }
        }
    }
}

/// A HMAC tag, stored as a value.
#[derive(Clone)]
pub(crate) struct Tag {
    buf: [u8; Self::MAX_LEN],
    used: usize,
}

impl Tag {
    /// Build a tag by copying a byte slice.
    ///
    /// The slice can be up to [`Tag::MAX_LEN`] bytes in length.
    pub(crate) fn new(bytes: &[u8]) -> Self {
        let mut tag = Self { buf: [0u8; Self::MAX_LEN], used: bytes.len() };
        tag.buf[..tag.used].copy_from_slice(bytes);
        tag
    }

    /// Build a tag with given capacity.
    ///
    /// The slice can be up to [`Tag::MAX_LEN`] bytes in length.
    pub(crate) fn with_len(len: usize) -> Self {
        Self { buf: [0u8; Self::MAX_LEN], used: len }
    }

    /// Maximum supported HMAC tag size: supports up to SHA512.
    pub(crate) const MAX_LEN: usize = 64;
}

impl Drop for Tag {
    fn drop(&mut self) {
        mbedtls::zeroize(&mut self.buf)
    }
}

impl AsRef<[u8]> for Tag {
    fn as_ref(&self) -> &[u8] {
        &self.buf[..self.used]
    }
}

impl AsMut<[u8]> for Tag {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.buf[..self.used]
    }
}

impl From<Tag> for rustls::crypto::hmac::Tag {
    fn from(val: Tag) -> Self {
        Self::new(&val.buf[..val.used])
    }
}
