# rustls-mbedtls-provider

This repository will contain code to allow [mbedtls](https://github.com/fortanix/rust-mbedtls) to be used
as the crypto and PKI provider for [rustls](https://github.com/rustls/rustls).

## Crypto provider

Implements following `rustls` traits:

- Hash algorithms through: [`Hash`] + [`Context`]
  - Support: `SHA256`, `SHA384`
- Hmac algorithms through: [`Hmac`] + [`Key`]
  - Support: `HMAC_SHA256`, `HMAC_SHA384`
- key-exchange groups through: [`SupportedKxGroup`] + [`ActiveKeyExchange`]
  - Support: `X25519`, `SECP256R1`, `SECP384R1`, `SECP521R1`
- [`CryptoProvider`]
- Aead algorithms though:[`Tls12AeadAlgorithm`] + [`Tls13AeadAlgorithm`] + [`MessageEncrypter`] + [`MessageDecrypter`]
  - Support: `AES128_GCM`, `AES256_GCM`, `CHACHA20_POLY1305`

Supports following ciphersuites:
- TLS 1.3
  - `TLS13_AES_256_GCM_SHA384`
  - `TLS13_AES_128_GCM_SHA256`
  - `TLS13_CHACHA20_POLY1305_SHA256`
- TLS 1.2
  - `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`
  - `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`
  - `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`
  - `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`
  - `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`
  - `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256`

## PKI provider

Implements [`ClientCertVerifier`](https://docs.rs/rustls/latest/rustls/server/trait.ClientCertVerifier.html) and [`ClientCertVerifier`](https://docs.rs/rustls/latest/rustls/client/trait.ServerCertVerifier.html) traits from `rustls` using mbedtls.

# Contributing

We gratefully accept bug reports and contributions from the community. By
participating in this community, you agree to abide by [Code of
Conduct](./CODE_OF_CONDUCT.md). All contributions are covered under the
Developer's Certificate of Origin (DCO).

## Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I have the right
to submit it under the open source license indicated in the file; or

(b) The contribution is based upon previous work that, to the best of my
knowledge, is covered under an appropriate open source license and I have the
right under that license to submit that work with modifications, whether created
in whole or in part by me, under the same open source license (unless I am
permitted to submit under a different license), as indicated in the file; or

(c) The contribution was provided directly to me by some other person who
certified (a), (b) or (c) and I have not modified it.

(d) I understand and agree that this project and the contribution are public and
that a record of the contribution (including all personal information I submit
with it, including my sign-off) is maintained indefinitely and may be
redistributed consistent with this project or the open source license(s)
involved.

# License

This project is primarily distributed under the terms of the Mozilla Public
License (MPL) 2.0, see [LICENSE](./LICENSE) for details.


[`Hash`]: https://docs.rs/rustls/0.22.0-alpha.3/rustls/crypto/hash/trait.Hash.html
[`Context`]: https://docs.rs/rustls/0.22.0-alpha.3/rustls/crypto/hash/trait.Context.html
[`Hmac`]: https://docs.rs/rustls/0.22.0-alpha.3/rustls/crypto/hmac/trait.Hmac.html
[`Key`]: https://docs.rs/rustls/0.22.0-alpha.3/rustls/crypto/hmac/trait.Key.html
[`SupportedKxGroup`]: https://docs.rs/rustls/0.22.0-alpha.3/rustls/crypto/trait.SupportedKxGroup.html
[`ActiveKeyExchange`]: https://docs.rs/rustls/0.22.0-alpha.3/rustls/crypto/trait.ActiveKeyExchange.html
[`CryptoProvider`]: https://docs.rs/rustls/0.22.0-alpha.3/rustls/crypto/trait.CryptoProvider.html
[`Tls12AeadAlgorithm`]: https://docs.rs/rustls/0.22.0-alpha.3/rustls/crypto/cipher/trait.Tls12AeadAlgorithm.html
[`Tls13AeadAlgorithm`]: https://docs.rs/rustls/0.22.0-alpha.3/rustls/crypto/cipher/trait.Tls13AeadAlgorithm.html
[`MessageEncrypter`]: https://docs.rs/rustls/0.22.0-alpha.3/rustls/crypto/cipher/trait.MessageEncrypter.html
[`MessageDecrypter`]: https://docs.rs/rustls/0.22.0-alpha.3/rustls/crypto/cipher/trait.MessageDecrypter.html
