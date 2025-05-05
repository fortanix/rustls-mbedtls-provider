/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

use core::fmt;

use mbedtls::pk::{EcGroupId, ECDSA_MAX_LEN};

/// An ECDH key agreement algorithm.
pub(crate) struct Algorithm {
    pub(crate) group_id: EcGroupId,
    pub(crate) public_key_len: usize,
    pub(crate) max_signature_len: usize,
}

impl fmt::Debug for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Algorithm")
            .field("group_id", &self.group_id)
            .finish()
    }
}

const ELEM_LEN: usize = 32;
const ELEM_AND_SCALAR_LEN: usize = ELEM_LEN;
const ED25519_PUBLIC_KEY_LEN: usize = ELEM_AND_SCALAR_LEN;
const ED25519_SIGNATURE_MAX_LEN: usize = 64;

/// X25519 (ECDH using Curve25519) as described in [RFC 7748].
///
/// Everything is as described in RFC 7748. Key agreement will fail if the
/// result of the X25519 operation is zero; see the notes on the
/// "all-zero value" in [RFC 7748 section 6.1].
///
/// [RFC 7748]: https://tools.ietf.org/html/rfc7748
/// [RFC 7748 section 6.1]: https://tools.ietf.org/html/rfc7748#section-6.1
pub(crate) static X25519: Algorithm = Algorithm {
    group_id: EcGroupId::Curve25519,
    public_key_len: ED25519_PUBLIC_KEY_LEN,
    max_signature_len: ED25519_SIGNATURE_MAX_LEN,
};

/// ECDH using the NSA Suite B
/// P-256 (secp256r1)
/// curve.
///
///  Public keys are encoding in uncompressed form using the
///  Octet-String-to-Elliptic-Curve-Point algorithm in
///  [SEC 1: Elliptic Curve Cryptography, Version 2.0]. Public keys are
///  validated during key agreement according to
///  [NIST Special Publication 800-56A, revision 2] and Appendix B.3 of
///  the NSA\'s [Suite B Implementer\'s Guide to NIST SP 800-56A].
///
///  [SEC 1: Elliptic Curve Cryptography, Version 2.0]:
///      http://www.secg.org/sec1-v2.pdf
///  [NIST Special Publication 800-56A, revision 2]:
///      http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar2.pdf
///  [Suite B Implementer\'s Guide to NIST SP 800-56A]:
///      https://github.com/briansmith/ring/blob/main/doc/ecdh.pdf
pub(crate) static ECDH_P256: Algorithm = Algorithm {
    group_id: EcGroupId::SecP256R1,
    public_key_len: 1 + (2 * 256_usize.div_ceil(8)),
    max_signature_len: ECDSA_MAX_LEN,
};

/// ECDH using the NSA Suite B
/// P-384 (secp384r1)
/// curve.
///
///  Public keys are encoding in uncompressed form using the
///  Octet-String-to-Elliptic-Curve-Point algorithm in
///  [SEC 1: Elliptic Curve Cryptography, Version 2.0]. Public keys are
///  validated during key agreement according to
///  [NIST Special Publication 800-56A, revision 2] and Appendix B.3 of
///  the NSA\'s [Suite B Implementer\'s Guide to NIST SP 800-56A].
///
///  [SEC 1: Elliptic Curve Cryptography, Version 2.0]:
///      http://www.secg.org/sec1-v2.pdf
///  [NIST Special Publication 800-56A, revision 2]:
///      http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar2.pdf
///  [Suite B Implementer\'s Guide to NIST SP 800-56A]:
///      https://github.com/briansmith/ring/blob/main/doc/ecdh.pdf
pub(crate) static ECDH_P384: Algorithm = Algorithm {
    group_id: EcGroupId::SecP384R1,
    public_key_len: 1 + (2 * 384_usize.div_ceil(8)),
    max_signature_len: ECDSA_MAX_LEN,
};

/// ECDH using the NSA Suite B
/// P-521 (secp521r1)
/// curve.
///
///  Public keys are encoding in uncompressed form using the
///  Octet-String-to-Elliptic-Curve-Point algorithm in
///  [SEC 1: Elliptic Curve Cryptography, Version 2.0]. Public keys are
///  validated during key agreement according to
///  [NIST Special Publication 800-56A, revision 2] and Appendix B.3 of
///  the NSA\'s [Suite B Implementer\'s Guide to NIST SP 800-56A].
///
///  [SEC 1: Elliptic Curve Cryptography, Version 2.0]:
///      http://www.secg.org/sec1-v2.pdf
///  [NIST Special Publication 800-56A, revision 2]:
///      http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar2.pdf
///  [Suite B Implementer\'s Guide to NIST SP 800-56A]:
///      https://github.com/briansmith/ring/blob/main/doc/ecdh.pdf
pub(crate) static ECDH_P521: Algorithm = Algorithm {
    group_id: EcGroupId::SecP521R1,
    public_key_len: 1 + (2 * 521_usize.div_ceil(8)),
    max_signature_len: ECDSA_MAX_LEN,
};
