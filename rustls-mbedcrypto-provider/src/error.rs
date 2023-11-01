use alloc::format;

pub(crate) fn mbedtls_err_to_rustls_error(err: mbedtls::Error) -> rustls::Error {
    rustls::Error::General(format!("Got mbedtls error: {}", err))
}
