use mbedtls::pk::Type;
use rustls::SignatureScheme;

/// Helper function to convert [`SignatureScheme`] to [`Type`]
pub fn rustls_signature_scheme_to_mbedtls_pk_type(scheme: &SignatureScheme) -> Option<Type> {
    match scheme {
        SignatureScheme::RSA_PKCS1_SHA1
        | SignatureScheme::RSA_PKCS1_SHA256
        | SignatureScheme::RSA_PKCS1_SHA384
        | SignatureScheme::RSA_PKCS1_SHA512
        | SignatureScheme::RSA_PSS_SHA384
        | SignatureScheme::RSA_PSS_SHA256
        | SignatureScheme::RSA_PSS_SHA512 => Some(Type::Rsa),
        SignatureScheme::ECDSA_SHA1_Legacy
        | SignatureScheme::ECDSA_NISTP256_SHA256
        | SignatureScheme::ECDSA_NISTP384_SHA384
        | SignatureScheme::ECDSA_NISTP521_SHA512 => Some(Type::Ecdsa),
        SignatureScheme::ED25519 => None,
        SignatureScheme::ED448 => None,
        SignatureScheme::Unknown(_) => None,
        _ => None,
    }
}

/// Helper function to convert rustls [`SignatureScheme`] to mbedtls [`mbedtls::pk::Options`]
pub fn rustls_signature_scheme_to_mbedtls_pk_options(signature_scheme: SignatureScheme) -> Option<mbedtls::pk::Options> {
    use mbedtls::pk::Options;
    use mbedtls::pk::RsaPadding;
    // reference: https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.3
    match signature_scheme {
        SignatureScheme::RSA_PKCS1_SHA1 => None,
        SignatureScheme::ECDSA_SHA1_Legacy => None,
        SignatureScheme::ECDSA_NISTP256_SHA256 => None,
        SignatureScheme::ECDSA_NISTP384_SHA384 => None,
        SignatureScheme::ECDSA_NISTP521_SHA512 => None,
        SignatureScheme::RSA_PKCS1_SHA256 | SignatureScheme::RSA_PKCS1_SHA384 | SignatureScheme::RSA_PKCS1_SHA512 => {
            Some(Options::Rsa { padding: RsaPadding::Pkcs1V15 })
        }
        SignatureScheme::RSA_PSS_SHA256 => {
            Some(Options::Rsa { padding: RsaPadding::Pkcs1V21 { mgf: mbedtls::hash::Type::Sha256 } })
        }
        SignatureScheme::RSA_PSS_SHA384 => {
            Some(Options::Rsa { padding: RsaPadding::Pkcs1V21 { mgf: mbedtls::hash::Type::Sha384 } })
        }
        SignatureScheme::RSA_PSS_SHA512 => {
            Some(Options::Rsa { padding: RsaPadding::Pkcs1V21 { mgf: mbedtls::hash::Type::Sha512 } })
        }
        SignatureScheme::ED25519 => None,
        SignatureScheme::ED448 => None,
        SignatureScheme::Unknown(_) => None,
        _ => None,
    }
}

/// Helper function to convert rustls [`SignatureScheme`] to mbedtls [`mbedtls::pk::EcGroupId`]
pub fn rustls_signature_scheme_to_mbedtls_curve_id(signature_scheme: SignatureScheme) -> mbedtls::pk::EcGroupId {
    // reference: https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.3
    use mbedtls::pk::EcGroupId;
    match signature_scheme {
        SignatureScheme::ECDSA_NISTP256_SHA256 => EcGroupId::SecP256R1,
        SignatureScheme::ECDSA_NISTP384_SHA384 => EcGroupId::SecP384R1,
        SignatureScheme::ECDSA_NISTP521_SHA512 => EcGroupId::SecP521R1,
        SignatureScheme::ECDSA_SHA1_Legacy => EcGroupId::None,
        SignatureScheme::RSA_PKCS1_SHA1 => EcGroupId::None,
        SignatureScheme::RSA_PKCS1_SHA256 => EcGroupId::None,
        SignatureScheme::RSA_PKCS1_SHA384 => EcGroupId::None,
        SignatureScheme::RSA_PKCS1_SHA512 => EcGroupId::None,
        SignatureScheme::RSA_PSS_SHA256 => EcGroupId::None,
        SignatureScheme::RSA_PSS_SHA384 => EcGroupId::None,
        SignatureScheme::RSA_PSS_SHA512 => EcGroupId::None,
        SignatureScheme::ED25519 => EcGroupId::None,
        SignatureScheme::ED448 => EcGroupId::None,
        SignatureScheme::Unknown(_) => EcGroupId::None,
        _ => EcGroupId::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rustls_signature_scheme_to_mbedtls_pk_type() {
        let test_data = [
            (
                Some(Type::Rsa),
                vec![
                    SignatureScheme::RSA_PKCS1_SHA1,
                    SignatureScheme::RSA_PKCS1_SHA256,
                    SignatureScheme::RSA_PKCS1_SHA384,
                    SignatureScheme::RSA_PKCS1_SHA512,
                    SignatureScheme::RSA_PSS_SHA384,
                    SignatureScheme::RSA_PSS_SHA256,
                    SignatureScheme::RSA_PSS_SHA512,
                ],
            ),
            (
                Some(Type::Ecdsa),
                vec![
                    SignatureScheme::ECDSA_SHA1_Legacy,
                    SignatureScheme::ECDSA_NISTP256_SHA256,
                    SignatureScheme::ECDSA_NISTP384_SHA384,
                    SignatureScheme::ECDSA_NISTP521_SHA512,
                ],
            ),
            (
                None,
                vec![
                    SignatureScheme::ED25519,
                    SignatureScheme::ED448,
                    SignatureScheme::Unknown(100),
                ],
            ),
        ];

        for pair in &test_data {
            for scheme in &pair.1 {
                assert_eq!(pair.0, rustls_signature_scheme_to_mbedtls_pk_type(scheme));
            }
        }
    }

    #[test]
    fn test_rustls_signature_scheme_to_mbedtls_curve_id() {
        assert_eq!(
            rustls_signature_scheme_to_mbedtls_curve_id(SignatureScheme::ECDSA_NISTP256_SHA256),
            mbedtls::pk::EcGroupId::SecP256R1
        );
        assert_eq!(
            rustls_signature_scheme_to_mbedtls_curve_id(SignatureScheme::ECDSA_NISTP384_SHA384),
            mbedtls::pk::EcGroupId::SecP384R1
        );
        assert_eq!(
            rustls_signature_scheme_to_mbedtls_curve_id(SignatureScheme::ECDSA_NISTP521_SHA512),
            mbedtls::pk::EcGroupId::SecP521R1
        );
        for scheme in [
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
            SignatureScheme::Unknown(123),
        ] {
            assert_eq!(
                rustls_signature_scheme_to_mbedtls_curve_id(scheme),
                mbedtls::pk::EcGroupId::None
            );
        }
    }
}
