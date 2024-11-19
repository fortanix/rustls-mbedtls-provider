use alloc::{format, sync::Arc};
use mbedtls::error::{codes, Error as ErrMbed};
use rustls::OtherError;

/// Converts an `mbedtls::Error` into a `rustls::Error`
pub fn mbedtls_err_into_rustls_err(err: ErrMbed) -> rustls::Error {
    mbedtls_err_into_rustls_err_with_error_msg(err, "")
}

/// Converts an `mbedtls::Error` into a `rustls::Error`; may include the provided `msg` in the
/// returned error (e.g., if returning a `rustls::Error::General` error).
pub fn mbedtls_err_into_rustls_err_with_error_msg(err: ErrMbed, msg: &str) -> rustls::Error {
    match err {
        ErrMbed::HighLevel(codes::X509InvalidSignature) | ErrMbed::HighLevel(codes::RsaVerifyFailed) => {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadSignature)
        }

        ErrMbed::HighLevel(codes::X509CertUnknownFormat) | ErrMbed::HighLevel(codes::X509BadInputData) => {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        }

        ErrMbed::HighLevel(codes::X509BufferTooSmall)
        | ErrMbed::HighLevel(codes::X509CertVerifyFailed)
        | ErrMbed::HighLevel(codes::X509FatalError)
        | ErrMbed::HighLevel(codes::X509FeatureUnavailable)
        | ErrMbed::HighLevel(codes::X509InvalidAlg)
        | ErrMbed::HighLevel(codes::X509InvalidDate)
        | ErrMbed::HighLevel(codes::X509InvalidExtensions)
        | ErrMbed::HighLevel(codes::X509InvalidFormat)
        | ErrMbed::HighLevel(codes::X509InvalidSerial)
        | ErrMbed::HighLevel(codes::X509InvalidVersion)
        | ErrMbed::HighLevel(codes::X509SigMismatch)
        | ErrMbed::HighLevel(codes::X509UnknownOid)
        | ErrMbed::HighLevel(codes::X509UnknownSigAlg)
        | ErrMbed::HighLevel(codes::X509UnknownVersion) => {
            rustls::Error::InvalidCertificate(rustls::CertificateError::Other(OtherError(Arc::new(err))))
        }

        ErrMbed::HighLevel(codes::X509InvalidName) => {
            rustls::Error::InvalidCertificate(rustls::CertificateError::NotValidForName)
        }

        _ => rustls::Error::General(format!("{err}{sep}{msg}", sep = if msg.is_empty() { "" } else { "\n" })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::CertificateError;

    #[test]
    fn test_mbedtls_err_into_rustls_err() {
        assert_eq!(
            mbedtls_err_into_rustls_err(codes::X509InvalidSignature.into()),
            rustls::Error::InvalidCertificate(CertificateError::BadSignature)
        );
        assert_eq!(
            mbedtls_err_into_rustls_err(codes::RsaVerifyFailed.into()),
            rustls::Error::InvalidCertificate(CertificateError::BadSignature)
        );
        assert_eq!(
            mbedtls_err_into_rustls_err(codes::X509BadInputData.into()),
            rustls::Error::InvalidCertificate(CertificateError::BadEncoding)
        );
        assert_eq!(
            mbedtls_err_into_rustls_err(codes::X509CertUnknownFormat.into()),
            rustls::Error::InvalidCertificate(CertificateError::BadEncoding)
        );
        assert_eq!(
            mbedtls_err_into_rustls_err(codes::X509InvalidName.into()),
            rustls::Error::InvalidCertificate(CertificateError::NotValidForName)
        );
    }

    #[test]
    fn test_mbedtls_err_into_rustls_err_with_error_msg() {
        assert_eq!(
            mbedtls_err_into_rustls_err_with_error_msg(codes::X509InvalidSignature.into(), ""),
            rustls::Error::InvalidCertificate(CertificateError::BadSignature)
        );
        assert_eq!(
            mbedtls_err_into_rustls_err_with_error_msg(codes::CipherAuthFailed.into(), ""),
            rustls::Error::General(String::from("mbedTLS error CipherAuthFailed"))
        );
        assert_eq!(
            mbedtls_err_into_rustls_err_with_error_msg(codes::RsaVerifyFailed.into(), ""),
            rustls::Error::InvalidCertificate(CertificateError::BadSignature)
        );
        assert_eq!(
            mbedtls_err_into_rustls_err_with_error_msg(codes::X509InvalidName.into(), ""),
            rustls::Error::InvalidCertificate(CertificateError::NotValidForName)
        );
        assert_eq!(
            format!(
                "{:?}",
                mbedtls_err_into_rustls_err_with_error_msg(codes::X509UnknownVersion.into(), "")
            ),
            format!(
                "{:?}",
                rustls::Error::InvalidCertificate(CertificateError::Other(OtherError(Arc::new(codes::X509UnknownVersion))))
            )
        );
        assert_eq!(
            format!(
                "{:?}",
                mbedtls_err_into_rustls_err_with_error_msg(codes::X509InvalidSerial.into(), "Invalid serial number")
            ),
            format!(
                "{:?}",
                rustls::Error::InvalidCertificate(CertificateError::Other(OtherError(Arc::new(codes::X509InvalidSerial))))
            )
        );
    }
}
