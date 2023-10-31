use std::sync::Mutex;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use rustls::crypto::hash::{self, HashAlgorithm};

pub(crate) static SHA256: Hash = Hash(&MBED_SHA_256);
pub(crate) static SHA384: Hash = Hash(&MBED_SHA_384);

pub(crate) struct Hash(&'static Algorithm);

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Algorithm {
    pub(crate) hash_algorithm: HashAlgorithm,
    pub(crate) hash_type: mbedtls::hash::Type,
    pub(crate) output_len: usize,
}

pub(crate) static MBED_SHA_256: Algorithm = Algorithm {
    hash_algorithm: HashAlgorithm::SHA256,
    hash_type: mbedtls::hash::Type::Sha256,
    output_len: 256 / 8,
};

pub(crate) static MBED_SHA_384: Algorithm = Algorithm {
    hash_algorithm: HashAlgorithm::SHA384,
    hash_type: mbedtls::hash::Type::Sha384,
    output_len: 384 / 8,
};

impl hash::Hash for Hash {
    fn start(&self) -> Box<dyn hash::Context> {
        Box::new(HashContext(MbedHashContext::new(self.0)))
    }

    fn hash(&self, data: &[u8]) -> hash::Output {
        hash::Output::new(&hash(self.0, data))
    }

    fn algorithm(&self) -> HashAlgorithm {
        self.0.hash_algorithm
    }

    fn output_len(&self) -> usize {
        self.0.output_len
    }
}

struct HashContext(MbedHashContext);

impl hash::Context for HashContext {
    fn fork_finish(&self) -> hash::Output {
        hash::Output::new(&self.0.clone().finalize())
    }

    fn fork(&self) -> Box<dyn hash::Context> {
        Box::new(HashContext(self.0.clone()))
    }

    fn finish(self: Box<Self>) -> hash::Output {
        hash::Output::new(&self.0.finalize())
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data)
    }
}

pub(crate) struct MbedHashContext {
    pub(crate) state: Arc<Mutex<mbedtls::hash::Md>>,
    pub(crate) hash_algo: &'static Algorithm,
}

impl Clone for MbedHashContext {
    fn clone(&self) -> Self {
        let state = self.state.lock().unwrap();
        Self {
            state: Arc::new(Mutex::new(state.clone())),
            hash_algo: self.hash_algo,
        }
    }
}

impl MbedHashContext {
    pub(crate) fn new(hash_algo: &'static Algorithm) -> Self {
        MbedHashContext {
            hash_algo,
            state: Arc::new(Mutex::new(
                mbedtls::hash::Md::new(hash_algo.hash_type).expect("input validated"),
            )),
        }
    }

    pub(crate) fn finalize(self) -> Vec<u8> {
        match Arc::into_inner(self.state) {
            Some(mutex) => match mutex.into_inner() {
                Ok(ctx) => {
                    let mut out = vec![0u8; self.hash_algo.output_len];
                    match ctx.finish(&mut out) {
                        Ok(_) => out,
                        Err(_) => vec![],
                    }
                }
                Err(_) => vec![],
            },
            None => vec![],
        }
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        match self.state.lock().as_mut() {
            Ok(ctx) => {
                let _ = ctx.update(data);
            }
            Err(_) => {}
        }
    }
}

pub(crate) fn hash(hash_algo: &'static Algorithm, data: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; hash_algo.output_len];
    match mbedtls::hash::Md::hash(hash_algo.hash_type, data, &mut out) {
        Ok(_) => out,
        Err(_) => {
            vec![]
        }
    }
}
