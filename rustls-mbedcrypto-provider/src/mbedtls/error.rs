use alloc::format;

pub(crate) fn mbedtls_err_to_rustls_error_with_msg(
    err: mbedtls::Error,
    msg: &str,
) -> rustls::Error {
    Error::General(format!("Got mbedtls error: {}\n{}", err, msg))
}

pub(crate) fn mbedtls_err_to_rustls_error(err: mbedtls::Error) -> rustls::Error {
    Error::General(format!("Got mbedtls error: {}", err))
}
