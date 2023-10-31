use std::sync::Arc;

mod common;
mod tests_common;

pub mod client_cert_verifier;
pub mod server_cert_verifier;

pub use client_cert_verifier::MbedTlsClientCertVerifier;
pub use server_cert_verifier::MbedTlsServerCertVerifier;

pub fn rustls_cert_to_mbedtls_cert(cert: &rustls::Certificate) -> mbedtls::Result<mbedtls::alloc::Box<mbedtls::x509::Certificate>> {
    let cert = mbedtls::x509::Certificate::from_der(&cert.0)?;
    Ok(cert)
}

pub fn mbedtls_err_into_rustls_err(err: mbedtls::Error) -> rustls::Error {
    match err {
        mbedtls::Error::X509CertUnknownFormat |
        mbedtls::Error::X509BadInputData => rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding),
        mbedtls::Error::X509FatalError => rustls::Error::InvalidCertificate(rustls::CertificateError::Other(Arc::new(err))),
        _ => rustls::Error::General(err.to_string()),
    }
}

pub fn mbedtls_err_into_rustls_err_with_error_msg(err: mbedtls::Error, msg: &str) -> rustls::Error {
    match err {
        mbedtls::Error::X509CertUnknownFormat |
        mbedtls::Error::X509BadInputData => rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding),
        mbedtls::Error::X509FatalError => rustls::Error::InvalidCertificate(rustls::CertificateError::Other(Arc::new(err))),
        _ => rustls::Error::General(format!("{err}\n{msg}")),
    }
}