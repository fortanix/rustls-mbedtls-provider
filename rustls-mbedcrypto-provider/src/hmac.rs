/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

use crate::log::error;
use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use rustls::crypto;

/// HMAC using SHA-256.
pub(crate) static HMAC_SHA256: Hmac = Hmac(&super::hash::MBED_SHA_256);

/// HMAC using SHA-384.
pub(crate) static HMAC_SHA384: Hmac = Hmac(&super::hash::MBED_SHA_384);

pub(crate) struct Hmac(&'static super::hash::Algorithm);

impl crypto::hmac::Hmac for Hmac {
    fn with_key(&self, key: &[u8]) -> Box<dyn crypto::hmac::Key> {
        Box::new(HmacKey(MbedHmacKey::new(self.0, key)))
    }

    fn hash_output_len(&self) -> usize {
        self.0.output_len
    }
}

struct HmacKey(MbedHmacKey);

impl crypto::hmac::Key for HmacKey {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> crypto::hmac::Tag {
        let mut ctx = self.0.starts();
        ctx.update(first);
        for m in middle {
            ctx.update(m);
        }
        ctx.update(last);
        crypto::hmac::Tag::new(&ctx.finish())
    }

    fn tag_len(&self) -> usize {
        self.0.hmac_algo.output_len
    }
}

struct MbedHmacKey {
    hmac_algo: &'static super::hash::Algorithm,
    /// use [`crypto::hmac::Tag`] for saving key material, since they have same max size.
    key: crypto::hmac::Tag,
}

impl MbedHmacKey {
    pub(crate) fn new(hmac_algo: &'static super::hash::Algorithm, key: &[u8]) -> Self {
        Self { hmac_algo, key: crypto::hmac::Tag::new(key) }
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
    pub(crate) fn finish(self) -> Vec<u8> {
        let mut out = vec![0u8; self.hmac_algo.output_len];
        match self.ctx.finish(&mut out) {
            Ok(_) => out,
            Err(_err) => {
                error!("Failed to finish hmac, mbedtls error: {:?}", _err);
                vec![]
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
