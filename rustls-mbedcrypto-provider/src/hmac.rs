/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#[cfg(feature = "logging")]
use crate::log::error;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use rustls::crypto;
use std::sync::Mutex;

/// HMAC using SHA-256.
pub(crate) static HMAC_SHA256: Hmac = Hmac(&super::hash::MBED_SHA_256);

/// HMAC using SHA-384.
pub(crate) static HMAC_SHA384: Hmac = Hmac(&super::hash::MBED_SHA_384);

pub(crate) struct Hmac(&'static super::hash::Algorithm);

impl crypto::hmac::Hmac for Hmac {
    fn with_key(&self, key: &[u8]) -> Box<dyn crypto::hmac::Key> {
        Box::new(HmacContext(MbedHmacContext::new(self.0, key)))
    }

    fn hash_output_len(&self) -> usize {
        self.0.output_len
    }
}

struct HmacContext(MbedHmacContext);

impl crypto::hmac::Key for HmacContext {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> crypto::hmac::Tag {
        let mut ctx = MbedHmacContext::new(self.0.hmac_algo, &self.0.key);
        ctx.update(first);
        for m in middle {
            ctx.update(m);
        }
        ctx.update(last);
        crypto::hmac::Tag::new(&ctx.finalize())
    }

    fn tag_len(&self) -> usize {
        self.0.hmac_algo.output_len
    }
}

struct MbedHmacContext {
    state: Arc<Mutex<mbedtls::hash::Hmac>>,
    hmac_algo: &'static super::hash::Algorithm,
    key: Vec<u8>,
}

impl MbedHmacContext {
    pub(crate) fn new(hmac_algo: &'static super::hash::Algorithm, key: &[u8]) -> Self {
        Self {
            hmac_algo,
            state: Arc::new(Mutex::new(
                mbedtls::hash::Hmac::new(hmac_algo.hash_type, key).expect("input validated"),
            )),
            key: key.to_vec(),
        }
    }

    /// Since the trait does not provider a way to return error, empty vector is returned when getting error from `mbedtls`.
    pub(crate) fn finalize(self) -> Vec<u8> {
        match Arc::into_inner(self.state) {
            Some(mutex) => match mutex.into_inner() {
                Ok(ctx) => {
                    let mut out = vec![0u8; self.hmac_algo.output_len];
                    match ctx.finish(&mut out) {
                        Ok(_) => out,
                        Err(_err) => {
                            error!("Failed to finalize hmac, mbedtls error: {:?}", _err);
                            vec![]
                        }
                    }
                }
                Err(_err) => {
                    error!("Failed to get lock, error: {:?}", _err);
                    vec![]
                }
            },
            None => {
                error!("Failed to do Arc::into_inner");
                vec![]
            }
        }
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        match self.state.lock().as_mut() {
            Ok(ctx) => match ctx.update(data) {
                Ok(_) => {}
                Err(_err) => {
                    error!("Failed to update hmac, mbedtls error: {:?}", _err);
                }
            },
            Err(_err) => {
                error!("Failed to get lock, error: {:?}", _err);
            }
        }
    }
}
