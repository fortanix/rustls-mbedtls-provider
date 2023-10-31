use chrono::NaiveDateTime;

use crate::mbedtls_err_into_rustls_err;

pub fn verify_certificates_active<'a>(
    chain: impl IntoIterator<Item = &'a mbedtls::x509::Certificate>,
    now: NaiveDateTime
) -> Result<(), rustls::Error> {
    fn time_err_to_err(_time_err: mbedtls::x509::InvalidTimeError) -> rustls::Error {
        rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
    }

    for cert in chain.into_iter() {
        let not_after = cert.not_after().map_err(mbedtls_err_into_rustls_err)?
            .try_into().map_err(time_err_to_err)?;
        if now > not_after {
            return Err(rustls::Error::InvalidCertificate(rustls::CertificateError::Expired));
        }
        let not_before = cert.not_before().map_err(mbedtls_err_into_rustls_err)?
            .try_into().map_err(time_err_to_err)?;
        if now < not_before {
            return Err(rustls::Error::InvalidCertificate(rustls::CertificateError::NotValidYet));
        }
    }
    Ok(())
}