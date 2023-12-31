/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

use alloc::sync::Arc;

use rustls::OtherError;

/// Convert a [`mbedtls::Error`] to a [`rustls::Error::Other`] error.
pub(crate) fn mbedtls_err_to_rustls_error(err: mbedtls::Error) -> rustls::Error {
    OtherError(Arc::new(err)).into()
}
