use crate::crypto;
use crate::log::error;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use std::sync::Mutex;

pub(crate) static HMAC_SHA256: Hmac = Hmac(&super::hash::MBED_SHA_256);
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
        MbedHmacContext {
            hmac_algo,
            state: Arc::new(Mutex::new(
                mbedtls::hash::Hmac::new(hmac_algo.hash_type, key).expect("input validated"),
            )),
            key: key.to_vec(),
        }
    }

    pub(crate) fn finalize(self) -> Vec<u8> {
        match Arc::into_inner(self.state) {
            Some(mutex) => match mutex.into_inner() {
                Ok(ctx) => {
                    let mut out = vec![0u8; self.hmac_algo.output_len];
                    match ctx.finish(&mut out) {
                        Ok(_) => out,
                        Err(e) => {
                            error!("MbedHmacContext::finalize {:?}", e);
                            vec![]
                        }
                    }
                }
                Err(e) => {
                    error!("MbedHmacContext::finalize {:?}", e);
                    vec![]
                }
            },
            None => {
                error!("MbedHmacContext::finalize Arc::into_inner got None");
                vec![]
            }
        }
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        if data.len() == 0 {
            return;
        }
        match self.state.lock().as_mut() {
            Ok(ctx) => match ctx.update(data) {
                Ok(_) => {}
                Err(e) => {
                    error!("MbedHmacContext::update {:?}, input: {:?}", e, data);
                }
            },
            Err(e) => {
                error!("MbedHmacContext::update {:?}", e);
            }
        }
    }
}
