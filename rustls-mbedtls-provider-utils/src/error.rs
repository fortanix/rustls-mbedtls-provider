use alloc::{format, sync::Arc};

/// Converts an `mbedtls::Error` into a `rustls::Error`
pub fn mbedtls_err_into_rustls_err(err: mbedtls::Error) -> rustls::Error {
    mbedtls_err_into_rustls_err_with_error_msg(err, "")
}

/// Converts an `mbedtls::Error` into a `rustls::Error`; may include the provided `msg` in the
/// returned error (e.g., if returning a `rustls::Error::General` error).
pub fn mbedtls_err_into_rustls_err_with_error_msg(err: mbedtls::Error, msg: &str) -> rustls::Error {
    match err {
        mbedtls::Error::X509InvalidSignature |
        mbedtls::Error::RsaVerifyFailed => rustls::Error::InvalidCertificate(rustls::CertificateError::BadSignature),

        mbedtls::Error::X509CertUnknownFormat |
        mbedtls::Error::X509BadInputData => rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding),

        // mbedtls::Error::X509AllocFailed |
        mbedtls::Error::X509BufferTooSmall |
        mbedtls::Error::X509CertVerifyFailed |
        mbedtls::Error::X509FatalError |
        mbedtls::Error::X509FeatureUnavailable |
        // mbedtls::Error::X509FileIoError |
        mbedtls::Error::X509InvalidAlg |
        mbedtls::Error::X509InvalidDate |
        mbedtls::Error::X509InvalidExtensions |
        mbedtls::Error::X509InvalidFormat |
        mbedtls::Error::X509InvalidSerial |
        mbedtls::Error::X509InvalidVersion |
        mbedtls::Error::X509SigMismatch |
        mbedtls::Error::X509UnknownOid |
        mbedtls::Error::X509UnknownSigAlg |
        mbedtls::Error::X509UnknownVersion => rustls::Error::InvalidCertificate(rustls::CertificateError::Other(Arc::new(err))),

        mbedtls::Error::X509InvalidName => rustls::Error::InvalidCertificate(rustls::CertificateError::NotValidForName),

        _ => rustls::Error::General(format!("{err}{sep}{msg}", sep = if msg.is_empty() {""} else {"\n"})),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::CertificateError;

    #[test]
    fn test_mbedtls_err_into_rustls_err() {
        assert_eq!(
            mbedtls_err_into_rustls_err(mbedtls::Error::X509InvalidSignature),
            rustls::Error::InvalidCertificate(CertificateError::BadSignature)
        );
        assert_eq!(
            mbedtls_err_into_rustls_err(mbedtls::Error::X509BadInputData),
            rustls::Error::InvalidCertificate(CertificateError::BadEncoding)
        );
        assert_eq!(
            mbedtls_err_into_rustls_err(mbedtls::Error::X509InvalidName),
            rustls::Error::InvalidCertificate(CertificateError::NotValidForName)
        );
    }

    #[test]
    fn test_mbedtls_err_into_rustls_err_with_error_msg() {
        assert_eq!(
            mbedtls_err_into_rustls_err_with_error_msg(mbedtls::Error::X509InvalidSignature, ""),
            rustls::Error::InvalidCertificate(CertificateError::BadSignature)
        );
        assert_eq!(
            mbedtls_err_into_rustls_err_with_error_msg(mbedtls::Error::RsaVerifyFailed, ""),
            rustls::Error::InvalidCertificate(CertificateError::BadSignature)
        );
        assert_eq!(
            mbedtls_err_into_rustls_err_with_error_msg(mbedtls::Error::X509InvalidName, ""),
            rustls::Error::InvalidCertificate(CertificateError::NotValidForName)
        );
        assert_eq!(
            format!(
                "{:?}",
                mbedtls_err_into_rustls_err_with_error_msg(mbedtls::Error::X509UnknownVersion, "")
            ),
            format!(
                "{:?}",
                rustls::Error::InvalidCertificate(CertificateError::Other(Arc::new(mbedtls::Error::X509UnknownVersion)))
            )
        );
        assert_eq!(
            format!(
                "{:?}",
                mbedtls_err_into_rustls_err_with_error_msg(mbedtls::Error::X509InvalidSerial, "Invalid serial number")
            ),
            format!(
                "{:?}",
                rustls::Error::InvalidCertificate(CertificateError::Other(Arc::new(mbedtls::Error::X509InvalidSerial)))
            )
        );
    }
}
