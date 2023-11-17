use alloc::vec;
use alloc::vec::Vec;
use mbedtls::hash::Type;
use rustls::SignatureScheme;

/// Returns the size of the message digest given the hash type.
fn hash_size_bytes(hash_type: Type) -> Option<usize> {
    match hash_type {
        Type::None => None,
        Type::Md2 => Some(16),
        Type::Md4 => Some(16),
        Type::Md5 => Some(16),
        Type::Sha1 => Some(160 / 8),
        Type::Sha224 => Some(224 / 8),
        Type::Sha256 => Some(256 / 8),
        Type::Sha384 => Some(384 / 8),
        Type::Sha512 => Some(512 / 8),
        Type::Ripemd => Some(160 / 8), // this is MD_RIPEMD160
    }
}

/// Returns the a ready to use empty [`Vec<u8>`] for the message digest with given hash type.
pub fn buffer_for_hash_type(hash_type: Type) -> Option<Vec<u8>> {
    let size = hash_size_bytes(hash_type)?;
    Some(vec![0; size])
}

/// Helper function to convert rustls [`SignatureScheme`] to mbedtls [`Type`]
pub fn rustls_signature_scheme_to_mbedtls_hash_type(signature_scheme: SignatureScheme) -> Type {
    match signature_scheme {
        SignatureScheme::RSA_PKCS1_SHA1 => Type::Sha1,
        SignatureScheme::ECDSA_SHA1_Legacy => Type::Sha1,
        SignatureScheme::RSA_PKCS1_SHA256 => Type::Sha256,
        SignatureScheme::ECDSA_NISTP256_SHA256 => Type::Sha256,
        SignatureScheme::RSA_PKCS1_SHA384 => Type::Sha384,
        SignatureScheme::ECDSA_NISTP384_SHA384 => Type::Sha384,
        SignatureScheme::RSA_PKCS1_SHA512 => Type::Sha512,
        SignatureScheme::ECDSA_NISTP521_SHA512 => Type::Sha512,
        SignatureScheme::RSA_PSS_SHA256 => Type::Sha256,
        SignatureScheme::RSA_PSS_SHA384 => Type::Sha384,
        SignatureScheme::RSA_PSS_SHA512 => Type::Sha512,
        SignatureScheme::ED25519 => Type::None,
        SignatureScheme::ED448 => Type::None,
        SignatureScheme::Unknown(_) => Type::None,
        _ => Type::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_size_bytes() {
        assert_eq!(hash_size_bytes(Type::None), None);
        assert_eq!(hash_size_bytes(Type::Md2), Some(16));
        assert_eq!(hash_size_bytes(Type::Md4), Some(16));
        assert_eq!(hash_size_bytes(Type::Md5), Some(16));
        assert_eq!(hash_size_bytes(Type::Sha1), Some(20));
        assert_eq!(hash_size_bytes(Type::Sha224), Some(224 / 8));
        assert_eq!(hash_size_bytes(Type::Sha256), Some(256 / 8));
        assert_eq!(hash_size_bytes(Type::Sha384), Some(384 / 8));
        assert_eq!(hash_size_bytes(Type::Sha512), Some(512 / 8));
        assert_eq!(hash_size_bytes(Type::Ripemd), Some(20));
        // Add more test cases if needed
    }

    #[test]
    fn test_buffer_for_hash_type() {
        assert_eq!(buffer_for_hash_type(Type::None), None);
        assert_eq!(buffer_for_hash_type(Type::Md2), Some(vec![0; 16]));
        assert_eq!(buffer_for_hash_type(Type::Md4), Some(vec![0; 16]));
        assert_eq!(buffer_for_hash_type(Type::Md5), Some(vec![0; 16]));
        assert_eq!(buffer_for_hash_type(Type::Sha1), Some(vec![0; 20]));
        assert_eq!(buffer_for_hash_type(Type::Sha224), Some(vec![0; 28]));
        assert_eq!(buffer_for_hash_type(Type::Sha256), Some(vec![0; 32]));
        assert_eq!(buffer_for_hash_type(Type::Sha384), Some(vec![0; 48]));
        assert_eq!(buffer_for_hash_type(Type::Sha512), Some(vec![0; 64]));
        assert_eq!(buffer_for_hash_type(Type::Ripemd), Some(vec![0; 20]));
        // Add more test cases if needed
    }

    #[test]
    fn test_rustls_signature_scheme_to_mbedtls_hash_type() {
        assert_eq!(
            rustls_signature_scheme_to_mbedtls_hash_type(SignatureScheme::RSA_PKCS1_SHA1),
            Type::Sha1
        );
        assert_eq!(
            rustls_signature_scheme_to_mbedtls_hash_type(SignatureScheme::ECDSA_SHA1_Legacy),
            Type::Sha1
        );
        assert_eq!(
            rustls_signature_scheme_to_mbedtls_hash_type(SignatureScheme::RSA_PKCS1_SHA256),
            Type::Sha256
        );
        assert_eq!(
            rustls_signature_scheme_to_mbedtls_hash_type(SignatureScheme::ECDSA_NISTP256_SHA256),
            Type::Sha256
        );
        assert_eq!(
            rustls_signature_scheme_to_mbedtls_hash_type(SignatureScheme::RSA_PKCS1_SHA384),
            Type::Sha384
        );
        assert_eq!(
            rustls_signature_scheme_to_mbedtls_hash_type(SignatureScheme::ECDSA_NISTP384_SHA384),
            Type::Sha384
        );
        assert_eq!(
            rustls_signature_scheme_to_mbedtls_hash_type(SignatureScheme::RSA_PKCS1_SHA512),
            Type::Sha512
        );
        assert_eq!(
            rustls_signature_scheme_to_mbedtls_hash_type(SignatureScheme::ECDSA_NISTP521_SHA512),
            Type::Sha512
        );
        assert_eq!(
            rustls_signature_scheme_to_mbedtls_hash_type(SignatureScheme::RSA_PSS_SHA256),
            Type::Sha256
        );
        assert_eq!(
            rustls_signature_scheme_to_mbedtls_hash_type(SignatureScheme::RSA_PSS_SHA384),
            Type::Sha384
        );
        assert_eq!(
            rustls_signature_scheme_to_mbedtls_hash_type(SignatureScheme::RSA_PSS_SHA512),
            Type::Sha512
        );
        assert_eq!(
            rustls_signature_scheme_to_mbedtls_hash_type(SignatureScheme::ED25519),
            Type::None
        );
        assert_eq!(
            rustls_signature_scheme_to_mbedtls_hash_type(SignatureScheme::ED448),
            Type::None
        );
        assert_eq!(
            rustls_signature_scheme_to_mbedtls_hash_type(SignatureScheme::Unknown(100)),
            Type::None
        );
        // Add more test cases if needed
    }
}
