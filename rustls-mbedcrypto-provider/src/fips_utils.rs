/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

//! This module contains functions only used with `fips` features

use core::fmt;
use std::{borrow::Cow, sync::Arc};

use rustls::OtherError;

#[derive(Debug, Eq, PartialEq)]
pub enum FipsCheckError {
    Mbedtls(mbedtls::Error),
    Other(Cow<'static, str>),
}

impl fmt::Display for FipsCheckError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for FipsCheckError {}

impl From<FipsCheckError> for rustls::Error {
    fn from(value: FipsCheckError) -> Self {
        OtherError(Arc::new(value)).into()
    }
}

#[allow(dead_code)]
pub(crate) mod constants {
    use core::str::FromStr;
    use std::sync::Mutex;
    use std::sync::OnceLock;

    use mbedtls::bignum::Mpi;
    use rustls::NamedGroup;

    /// `q` for FFDHE 2048.
    /// Defined in [RFC 7919 appendix-A.1].
    ///
    /// [RFC 7919 appendix-A.1]: https://datatracker.ietf.org/doc/html/rfc7919#appendix-A.1
    static FFDHE2048_Q: OnceLock<Mutex<Mpi>> = OnceLock::new();
    /// `q` for FFDHE 3072.
    /// Defined in [RFC 7919 appendix-A.2].
    ///
    /// [RFC 7919 appendix-A.2]: https://datatracker.ietf.org/doc/html/rfc7919#appendix-A.2
    static FFDHE3072_Q: OnceLock<Mutex<Mpi>> = OnceLock::new();
    /// `q` for FFDHE 4096.
    /// Defined in [RFC 7919 appendix-A.3].
    ///
    /// [RFC 7919 appendix-A.3]: https://datatracker.ietf.org/doc/html/rfc7919#appendix-A.3
    static FFDHE4096_Q: OnceLock<Mutex<Mpi>> = OnceLock::new();
    /// `q` for FFDHE 6144.
    /// Defined in [RFC 7919 appendix-A.4].
    ///
    /// [RFC 7919 appendix-A.4]: https://datatracker.ietf.org/doc/html/rfc7919#appendix-A.4
    static FFDHE6144_Q: OnceLock<Mutex<Mpi>> = OnceLock::new();
    /// `q` for FFDHE 8192.
    /// Defined in [RFC 7919 appendix-A.5].
    ///
    /// [RFC 7919 appendix-A.5]: https://datatracker.ietf.org/doc/html/rfc7919#appendix-A.5
    static FFDHE8192_Q: OnceLock<Mutex<Mpi>> = OnceLock::new();

    /// Get `q` based on ffdhe group.
    pub(crate) fn get_ffdhe_q(named_group: NamedGroup) -> Option<&'static Mutex<Mpi>> {
        let (to_init, q_str) = match named_group {
            NamedGroup::FFDHE2048 => (&FFDHE2048_Q, FFDHE2048_Q_STR),
            NamedGroup::FFDHE3072 => (&FFDHE3072_Q, FFDHE3072_Q_STR),
            NamedGroup::FFDHE4096 => (&FFDHE4096_Q, FFDHE4096_Q_STR),
            NamedGroup::FFDHE6144 => (&FFDHE6144_Q, FFDHE6144_Q_STR),
            NamedGroup::FFDHE8192 => (&FFDHE8192_Q, FFDHE8192_Q_STR),
            _ => return None,
        };

        Some(to_init.get_or_init(|| {
            let formalized_str = remove_spaces_and_newlines(q_str);
            Mutex::new(Mpi::from_str(&formalized_str).expect("validated"))
        }))
    }

    /// The hexadecimal representation of `q` for FFDHE 2048.
    /// Defined in [RFC 7919 appendix-A.1].
    ///
    /// [RFC 7919 appendix-A.1]: https://datatracker.ietf.org/doc/html/rfc7919#appendix-A.1
    const FFDHE2048_Q_STR: &str = "0x
    7FFFFFFF FFFFFFFF D6FC2A2C 515DA54D 57EE2B10 139E9E78
    EC5CE2C1 E7169B4A D4F09B20 8A3219FD E649CEE7 124D9F7C
    BE97F1B1 B1863AEC 7B40D901 576230BD 69EF8F6A EAFEB2B0
    9219FA8F AF833768 42B1B2AA 9EF68D79 DAAB89AF 3FABE49A
    CC278638 707345BB F15344ED 79F7F439 0EF8AC50 9B56F39A
    98566527 A41D3CBD 5E0558C1 59927DB0 E88454A5 D96471FD
    DCB56D5B B06BFA34 0EA7A151 EF1CA6FA 572B76F3 B1B95D8C
    8583D3E4 770536B8 4F017E70 E6FBF176 601A0266 941A17B0
    C8B97F4E 74C2C1FF C7278919 777940C1 E1FF1D8D A637D6B9
    9DDAFE5E 17611002 E2C778C1 BE8B41D9 6379A513 60D977FD
    4435A11C 30942E4B FFFFFFFF FFFFFFFF";

    /// The hexadecimal representation of `q` for FFDHE 3072.
    /// Defined in [RFC 7919 appendix-A.2].
    ///
    /// [RFC 7919 appendix-A.2]: https://datatracker.ietf.org/doc/html/rfc7919#appendix-A.2
    const FFDHE3072_Q_STR: &str = "0x
    7FFFFFFF FFFFFFFF D6FC2A2C 515DA54D 57EE2B10 139E9E78
    EC5CE2C1 E7169B4A D4F09B20 8A3219FD E649CEE7 124D9F7C
    BE97F1B1 B1863AEC 7B40D901 576230BD 69EF8F6A EAFEB2B0
    9219FA8F AF833768 42B1B2AA 9EF68D79 DAAB89AF 3FABE49A
    CC278638 707345BB F15344ED 79F7F439 0EF8AC50 9B56F39A
    98566527 A41D3CBD 5E0558C1 59927DB0 E88454A5 D96471FD
    DCB56D5B B06BFA34 0EA7A151 EF1CA6FA 572B76F3 B1B95D8C
    8583D3E4 770536B8 4F017E70 E6FBF176 601A0266 941A17B0
    C8B97F4E 74C2C1FF C7278919 777940C1 E1FF1D8D A637D6B9
    9DDAFE5E 17611002 E2C778C1 BE8B41D9 6379A513 60D977FD
    4435A11C 308FE7EE 6F1AAD9D B28C81AD DE1A7A6F 7CCE011C
    30DA37E4 EB736483 BD6C8E93 48FBFBF7 2CC6587D 60C36C8E
    577F0984 C289C938 5A098649 DE21BCA2 7A7EA229 716BA6E9
    B279710F 38FAA5FF AE574155 CE4EFB4F 743695E2 911B1D06
    D5E290CB CD86F56D 0EDFCD21 6AE22427 055E6835 FD29EEF7
    9E0D9077 1FEACEBE 12F20E95 B363171B FFFFFFFF FFFFFFFF";

    /// The hexadecimal representation of `q` for FFDHE 4096.
    /// Defined in [RFC 7919 appendix-A.3].
    ///
    /// [RFC 7919 appendix-A.3]: https://datatracker.ietf.org/doc/html/rfc7919#appendix-A.3
    const FFDHE4096_Q_STR: &str = "0x
    7FFFFFFF FFFFFFFF D6FC2A2C 515DA54D 57EE2B10 139E9E78
    EC5CE2C1 E7169B4A D4F09B20 8A3219FD E649CEE7 124D9F7C
    BE97F1B1 B1863AEC 7B40D901 576230BD 69EF8F6A EAFEB2B0
    9219FA8F AF833768 42B1B2AA 9EF68D79 DAAB89AF 3FABE49A
    CC278638 707345BB F15344ED 79F7F439 0EF8AC50 9B56F39A
    98566527 A41D3CBD 5E0558C1 59927DB0 E88454A5 D96471FD
    DCB56D5B B06BFA34 0EA7A151 EF1CA6FA 572B76F3 B1B95D8C
    8583D3E4 770536B8 4F017E70 E6FBF176 601A0266 941A17B0
    C8B97F4E 74C2C1FF C7278919 777940C1 E1FF1D8D A637D6B9
    9DDAFE5E 17611002 E2C778C1 BE8B41D9 6379A513 60D977FD
    4435A11C 308FE7EE 6F1AAD9D B28C81AD DE1A7A6F 7CCE011C
    30DA37E4 EB736483 BD6C8E93 48FBFBF7 2CC6587D 60C36C8E
    577F0984 C289C938 5A098649 DE21BCA2 7A7EA229 716BA6E9
    B279710F 38FAA5FF AE574155 CE4EFB4F 743695E2 911B1D06
    D5E290CB CD86F56D 0EDFCD21 6AE22427 055E6835 FD29EEF7
    9E0D9077 1FEACEBE 12F20E95 B34F0F78 B737A961 8B26FA7D
    BC9874F2 72C42BDB 563EAFA1 6B4FB68C 3BB1E78E AA81A002
    43FAADD2 BF18E63D 389AE443 77DA18C5 76B50F00 96CF3419
    5483B005 48C09862 36E3BC7C B8D6801C 0494CCD1 99E5C5BD
    0D0EDC9E B8A0001E 15276754 FCC68566 054148E6 E764BEE7
    C764DAAD 3FC45235 A6DAD428 FA20C170 E345003F 2F32AFB5
    7FFFFFFF FFFFFFFF";

    /// The hexadecimal representation of `q` for FFDHE 6144.
    /// Defined in [RFC 7919 appendix-A.4].
    ///
    /// [RFC 7919 appendix-A.4]: https://datatracker.ietf.org/doc/html/rfc7919#appendix-A.4
    const FFDHE6144_Q_STR: &str = "0x
    7FFFFFFF FFFFFFFF D6FC2A2C 515DA54D 57EE2B10 139E9E78
    EC5CE2C1 E7169B4A D4F09B20 8A3219FD E649CEE7 124D9F7C
    BE97F1B1 B1863AEC 7B40D901 576230BD 69EF8F6A EAFEB2B0
    9219FA8F AF833768 42B1B2AA 9EF68D79 DAAB89AF 3FABE49A
    CC278638 707345BB F15344ED 79F7F439 0EF8AC50 9B56F39A
    98566527 A41D3CBD 5E0558C1 59927DB0 E88454A5 D96471FD
    DCB56D5B B06BFA34 0EA7A151 EF1CA6FA 572B76F3 B1B95D8C
    8583D3E4 770536B8 4F017E70 E6FBF176 601A0266 941A17B0
    C8B97F4E 74C2C1FF C7278919 777940C1 E1FF1D8D A637D6B9
    9DDAFE5E 17611002 E2C778C1 BE8B41D9 6379A513 60D977FD
    4435A11C 308FE7EE 6F1AAD9D B28C81AD DE1A7A6F 7CCE011C
    30DA37E4 EB736483 BD6C8E93 48FBFBF7 2CC6587D 60C36C8E
    577F0984 C289C938 5A098649 DE21BCA2 7A7EA229 716BA6E9
    B279710F 38FAA5FF AE574155 CE4EFB4F 743695E2 911B1D06
    D5E290CB CD86F56D 0EDFCD21 6AE22427 055E6835 FD29EEF7
    9E0D9077 1FEACEBE 12F20E95 B34F0F78 B737A961 8B26FA7D
    BC9874F2 72C42BDB 563EAFA1 6B4FB68C 3BB1E78E AA81A002
    43FAADD2 BF18E63D 389AE443 77DA18C5 76B50F00 96CF3419
    5483B005 48C09862 36E3BC7C B8D6801C 0494CCD1 99E5C5BD
    0D0EDC9E B8A0001E 15276754 FCC68566 054148E6 E764BEE7
    C764DAAD 3FC45235 A6DAD428 FA20C170 E345003F 2F06EC81
    05FEB25B 2281B63D 2733BE96 1C29951D 11DD2221 657A9F53
    1DDA2A19 4DBB1264 48BDEEB2 58E07EA6 59C74619 A6380E1D
    66D6832B FE67F638 CD8FAE1F 2723020F 9C40A3FD A67EDA3B
    D29238FB D4D4B488 5C2A9917 6DB1A06C 50077849 1A8288F1
    855F60FF FCF1D137 3FD94FC6 0C1811E1 AC3F1C6D 003BECDA
    3B1F2725 CA595DE0 CA63328F 3BE57CC9 77556011 95140DFB
    59D39CE0 91308B41 05746DAC 23D33E5F 7CE4848D A316A9C6
    6B9581BA 3573BFAF 31149618 8AB15423 282EE416 DC2A19C5
    724FA91A E4ADC88B C66796EA E5677A01 F64E8C08 63139582
    2D9DB8FC EE35C06B 1FEEA547 4D6D8F34 B1534A93 6A18B0E0
    D20EAB86 BC9C6D6A 5207194E 68720732 FFFFFFFF FFFFFFFF";

    /// The hexadecimal representation of `q` for FFDHE 8192.
    /// Defined in [RFC 7919 appendix-A.5].
    ///
    /// [RFC 7919 appendix-A.5]: https://datatracker.ietf.org/doc/html/rfc7919#appendix-A.5
    const FFDHE8192_Q_STR: &str = "0x
    7FFFFFFF FFFFFFFF D6FC2A2C 515DA54D 57EE2B10 139E9E78
    EC5CE2C1 E7169B4A D4F09B20 8A3219FD E649CEE7 124D9F7C
    BE97F1B1 B1863AEC 7B40D901 576230BD 69EF8F6A EAFEB2B0
    9219FA8F AF833768 42B1B2AA 9EF68D79 DAAB89AF 3FABE49A
    CC278638 707345BB F15344ED 79F7F439 0EF8AC50 9B56F39A
    98566527 A41D3CBD 5E0558C1 59927DB0 E88454A5 D96471FD
    DCB56D5B B06BFA34 0EA7A151 EF1CA6FA 572B76F3 B1B95D8C
    8583D3E4 770536B8 4F017E70 E6FBF176 601A0266 941A17B0
    C8B97F4E 74C2C1FF C7278919 777940C1 E1FF1D8D A637D6B9
    9DDAFE5E 17611002 E2C778C1 BE8B41D9 6379A513 60D977FD
    4435A11C 308FE7EE 6F1AAD9D B28C81AD DE1A7A6F 7CCE011C
    30DA37E4 EB736483 BD6C8E93 48FBFBF7 2CC6587D 60C36C8E
    577F0984 C289C938 5A098649 DE21BCA2 7A7EA229 716BA6E9
    B279710F 38FAA5FF AE574155 CE4EFB4F 743695E2 911B1D06
    D5E290CB CD86F56D 0EDFCD21 6AE22427 055E6835 FD29EEF7
    9E0D9077 1FEACEBE 12F20E95 B34F0F78 B737A961 8B26FA7D
    BC9874F2 72C42BDB 563EAFA1 6B4FB68C 3BB1E78E AA81A002
    43FAADD2 BF18E63D 389AE443 77DA18C5 76B50F00 96CF3419
    5483B005 48C09862 36E3BC7C B8D6801C 0494CCD1 99E5C5BD
    0D0EDC9E B8A0001E 15276754 FCC68566 054148E6 E764BEE7
    C764DAAD 3FC45235 A6DAD428 FA20C170 E345003F 2F06EC81
    05FEB25B 2281B63D 2733BE96 1C29951D 11DD2221 657A9F53
    1DDA2A19 4DBB1264 48BDEEB2 58E07EA6 59C74619 A6380E1D
    66D6832B FE67F638 CD8FAE1F 2723020F 9C40A3FD A67EDA3B
    D29238FB D4D4B488 5C2A9917 6DB1A06C 50077849 1A8288F1
    855F60FF FCF1D137 3FD94FC6 0C1811E1 AC3F1C6D 003BECDA
    3B1F2725 CA595DE0 CA63328F 3BE57CC9 77556011 95140DFB
    59D39CE0 91308B41 05746DAC 23D33E5F 7CE4848D A316A9C6
    6B9581BA 3573BFAF 31149618 8AB15423 282EE416 DC2A19C5
    724FA91A E4ADC88B C66796EA E5677A01 F64E8C08 63139582
    2D9DB8FC EE35C06B 1FEEA547 4D6D8F34 B1534A93 6A18B0E0
    D20EAB86 BC9C6D6A 5207194E 67FA3555 1B568026 7B00641C
    0F212D18 ECA8D732 7ED91FE7 64A84EA1 B43FF5B4 F6E8E62F
    05C661DE FB258877 C35B18A1 51D5C414 AAAD97BA 3E499332
    E596078E 600DEB81 149C441C E95782F2 2A282563 C5BAC141
    1423605D 1AE1AFAE 2C8B0660 237EC128 AA0FE346 4E435811
    5DB84CC3 B523073A 28D45498 84B81FF7 0E10BF36 1C137296
    28D5348F 07211E7E 4CF4F18B 286090BD B1240B66 D6CD4AFC
    EADC00CA 446CE050 50FF183A D2BBF118 C1FC0EA5 1F97D22B
    8F7E4670 5D4527F4 5B42AEFF 39585337 6F697DD5 FDF2C518
    7D7D5F0E 2EB8D43F 17BA0F7C 60FF437F 535DFEF2 9833BF86
    CBE88EA4 FBD4221E 84117283 54FA30A7 008F154A 41C7FC46
    6B4645DB E2E32126 7FFFFFFF FFFFFFFF";

    fn remove_spaces_and_newlines(input: &str) -> String {
        input
            .chars()
            .filter(|&c| c != ' ' && c != '\n')
            .collect()
    }

    static FFDHE2048_KEY_PAIR: OnceLock<Mutex<(Mpi, Mpi)>> = OnceLock::new();
    static FFDHE3072_KEY_PAIR: OnceLock<Mutex<(Mpi, Mpi)>> = OnceLock::new();
    static FFDHE4096_KEY_PAIR: OnceLock<Mutex<(Mpi, Mpi)>> = OnceLock::new();
    static FFDHE6144_KEY_PAIR: OnceLock<Mutex<(Mpi, Mpi)>> = OnceLock::new();
    static FFDHE8192_KEY_PAIR: OnceLock<Mutex<(Mpi, Mpi)>> = OnceLock::new();

    /// Get a known FFDHE key pair.
    /// The key pair is loaded from static arbitrary private keys with their corresponding public keys.
    pub(crate) fn get_known_ffdhe_key_pair(named_group: NamedGroup) -> Option<&'static Mutex<(Mpi, Mpi)>> {
        let (cell, sk, pk) = match named_group {
            NamedGroup::FFDHE2048 => (&FFDHE2048_KEY_PAIR, FFDHE2048_SK, FFDHE2048_PK),
            NamedGroup::FFDHE3072 => (&FFDHE3072_KEY_PAIR, FFDHE3072_SK, FFDHE3072_PK),
            NamedGroup::FFDHE4096 => (&FFDHE4096_KEY_PAIR, FFDHE4096_SK, FFDHE4096_PK),
            NamedGroup::FFDHE6144 => (&FFDHE6144_KEY_PAIR, FFDHE6144_SK, FFDHE6144_PK),
            NamedGroup::FFDHE8192 => (&FFDHE8192_KEY_PAIR, FFDHE8192_SK, FFDHE8192_PK),
            _ => return None,
        };
        Some(cell.get_or_init(|| {
            Mutex::new((
                Mpi::from_binary(sk).expect("validated"),
                Mpi::from_binary(pk).expect("validated"),
            ))
        }))
    }

    static FFDHE2048_SK: &[u8] = &[
        0x8d, 0xcc, 0xdf, 0x82, 0x6b, 0x68, 0x34, 0xc1, 0x26, 0x59, 0x63, 0x6d, 0x1e, 0xa6, 0x5a, 0x93, 0xb9, 0x50, 0x67, 0x91,
        0xda, 0xa0, 0xf4, 0x41, 0x38, 0x71, 0x8e, 0xde, 0x09, 0x2e, 0x64, 0x9d, 0xe8, 0x04, 0x66, 0xc8,
    ];
    static FFDHE2048_PK: &[u8] = &[
        0xf7, 0x50, 0xc5, 0x66, 0x7c, 0x43, 0x52, 0x15, 0x52, 0x99, 0xba, 0x2f, 0x8c, 0x87, 0x37, 0x39, 0x11, 0x2a, 0xb4, 0x83,
        0xb1, 0xf2, 0x0c, 0xba, 0x32, 0x73, 0x6e, 0x4f, 0xeb, 0x3d, 0xec, 0x7d, 0x0f, 0x89, 0x4c, 0x21, 0xcc, 0x04, 0x9c, 0x83,
        0xc4, 0x42, 0xb9, 0xc9, 0x87, 0x47, 0xb4, 0xeb, 0xde, 0x61, 0xb1, 0x50, 0xc3, 0xf6, 0xbf, 0x3b, 0x70, 0xb8, 0x39, 0x9b,
        0xff, 0xe4, 0xc1, 0x62, 0x7c, 0x03, 0x89, 0x14, 0x52, 0x3f, 0xe2, 0xf5, 0x1f, 0x7d, 0x75, 0x68, 0xf9, 0xa9, 0xc3, 0xa4,
        0x2c, 0xae, 0x24, 0xaf, 0x7a, 0x0d, 0x75, 0x2c, 0x9d, 0x36, 0x56, 0x68, 0xad, 0xfb, 0x91, 0x14, 0xcc, 0x4f, 0x1c, 0xc2,
        0x0f, 0x74, 0x6f, 0x48, 0x79, 0x94, 0x15, 0xea, 0xac, 0x55, 0x69, 0x09, 0x39, 0x09, 0xb1, 0xf2, 0x4c, 0x80, 0xab, 0x20,
        0x60, 0x03, 0x1f, 0x9e, 0x75, 0x24, 0x2f, 0x74, 0x22, 0xf6, 0x88, 0xf2, 0x8a, 0xd1, 0xfa, 0xf0, 0xd5, 0x8c, 0xdc, 0xa7,
        0x79, 0xd1, 0x16, 0xfb, 0x2a, 0xac, 0xb7, 0x63, 0xf9, 0x11, 0x53, 0x55, 0x99, 0xfb, 0x9c, 0xc2, 0x0f, 0xc6, 0x96, 0x7a,
        0x00, 0x01, 0x32, 0xa9, 0x96, 0x8a, 0x5a, 0x5a, 0x06, 0x42, 0xdf, 0xa9, 0x5f, 0x31, 0x9f, 0xd3, 0x13, 0xe0, 0x6f, 0x9c,
        0xd7, 0xd8, 0x72, 0x42, 0x93, 0x98, 0xe0, 0x59, 0x40, 0xb6, 0x15, 0xe5, 0x08, 0x8e, 0x3d, 0x5f, 0xfc, 0x2d, 0xc1, 0x89,
        0xee, 0x7b, 0xd0, 0xeb, 0x5a, 0xa0, 0xdb, 0xd3, 0x0c, 0x3f, 0x0d, 0xee, 0x14, 0x51, 0xc8, 0x3b, 0x8f, 0xbd, 0xa2, 0xdd,
        0xfb, 0xbd, 0xa1, 0x53, 0x21, 0x0c, 0xed, 0x51, 0xdf, 0xfb, 0xbe, 0xb0, 0xa8, 0xd0, 0x16, 0x77, 0xa8, 0x65, 0x4f, 0xf0,
        0xec, 0x90, 0xc9, 0x4e, 0x9c, 0xcf, 0xe3, 0xb0, 0x77, 0x7b, 0x5e, 0x48, 0x86, 0x5b, 0x09, 0x6f,
    ];

    static FFDHE3072_SK: &[u8] = &[
        0xeb, 0xbe, 0x65, 0x1e, 0x2f, 0xeb, 0xd1, 0xf1, 0x43, 0x20, 0x49, 0x6b, 0x5f, 0x32, 0xbc, 0x4f, 0x45, 0x9e, 0x27, 0x48,
        0xc5, 0xfb, 0xc6, 0x9a, 0xc4, 0xf8, 0x61, 0x8c, 0x14, 0xcc, 0xbb, 0x0c, 0xe3, 0x7c, 0x77, 0x4d, 0x8c, 0x52, 0xb6, 0x9c,
    ];

    static FFDHE3072_PK: &[u8] = &[
        0xde, 0x63, 0x16, 0x98, 0x50, 0x1e, 0x62, 0x31, 0x26, 0x8e, 0xb6, 0x4f, 0xe8, 0x0a, 0x7d, 0xb9, 0x45, 0x97, 0xa8, 0x8f,
        0x6d, 0xe8, 0x26, 0x1c, 0xdb, 0xcf, 0x19, 0xa5, 0x30, 0xab, 0x3e, 0x3a, 0x74, 0x26, 0x91, 0xc8, 0xa2, 0x98, 0x88, 0x24,
        0x4c, 0x01, 0x19, 0x84, 0xcd, 0x30, 0xeb, 0xe9, 0xce, 0x6b, 0x92, 0x91, 0xaa, 0x6f, 0x17, 0x73, 0x23, 0xd2, 0xe3, 0xdd,
        0x44, 0xcc, 0xbd, 0x24, 0xed, 0xf0, 0x98, 0xab, 0x53, 0x0b, 0x9f, 0x3b, 0xa9, 0x03, 0x62, 0x3d, 0x65, 0x0d, 0x03, 0xe5,
        0x2c, 0x55, 0x48, 0x7e, 0x97, 0x94, 0x2a, 0x7f, 0x5b, 0xd2, 0x61, 0xbc, 0x41, 0x9a, 0xb7, 0x31, 0x03, 0x20, 0x7d, 0x0a,
        0x63, 0xe5, 0x6b, 0xdf, 0x19, 0x92, 0xd2, 0x9c, 0xb0, 0xe1, 0xa7, 0x43, 0x89, 0xa0, 0x8e, 0x05, 0xa1, 0xb5, 0x46, 0xa8,
        0x99, 0x98, 0xf0, 0xf2, 0xa8, 0xf9, 0xbd, 0xe6, 0xcc, 0xb1, 0x77, 0x4a, 0xb4, 0x75, 0x9d, 0x6a, 0x61, 0x17, 0xb8, 0xac,
        0xc0, 0x70, 0x4d, 0xa7, 0x03, 0x76, 0x2d, 0x20, 0xcf, 0x55, 0x85, 0xc4, 0xa8, 0x83, 0xe3, 0xe7, 0xe0, 0x39, 0xa1, 0x56,
        0x3d, 0x0e, 0x4f, 0x35, 0x4b, 0xb5, 0xd8, 0xa7, 0x8a, 0xbd, 0x6b, 0xbd, 0xe4, 0xed, 0x13, 0x16, 0xcc, 0x5a, 0x5f, 0x7e,
        0xf2, 0xa7, 0x77, 0x27, 0x1e, 0x6a, 0xe9, 0xd2, 0xdc, 0x6b, 0xd4, 0x66, 0x25, 0x4b, 0x51, 0x01, 0x7e, 0x9d, 0x31, 0x73,
        0x0b, 0xc8, 0xce, 0xae, 0x61, 0x8e, 0xc1, 0xab, 0xc7, 0xed, 0x76, 0xd2, 0xc7, 0x37, 0x05, 0x7e, 0xc2, 0x02, 0x73, 0x93,
        0x09, 0xe4, 0x03, 0x08, 0xea, 0x16, 0x3a, 0x53, 0xe8, 0x51, 0xb7, 0xda, 0xa4, 0xee, 0xc5, 0xba, 0xc4, 0x4a, 0x70, 0x6f,
        0x4f, 0x17, 0xae, 0xa4, 0x97, 0xcf, 0x31, 0x7a, 0x9d, 0xf5, 0x23, 0x36, 0x42, 0x1d, 0x6d, 0xb8, 0x9e, 0x3a, 0x74, 0x34,
        0x32, 0x63, 0x17, 0x57, 0x86, 0x7c, 0x61, 0xcd, 0x67, 0xca, 0xac, 0x41, 0xa4, 0xd9, 0x2c, 0x4c, 0xfc, 0xfd, 0xda, 0xed,
        0x4a, 0x12, 0x6a, 0x1a, 0x05, 0xa5, 0x65, 0xa4, 0xa5, 0xd8, 0x31, 0x59, 0x4c, 0xc9, 0x9e, 0xcc, 0x0d, 0x4f, 0xe5, 0x96,
        0x6f, 0x05, 0x39, 0x4f, 0x6f, 0xf9, 0x60, 0x51, 0x0d, 0xa8, 0x8a, 0xa6, 0x11, 0xdc, 0x32, 0xd7, 0x09, 0x14, 0x36, 0x89,
        0xdd, 0x17, 0xdb, 0x54, 0xda, 0xdc, 0x1a, 0xe1, 0x31, 0xba, 0x74, 0x89, 0xb4, 0xf6, 0xe2, 0xfc, 0x68, 0x06, 0x2d, 0xf7,
        0xd0, 0x8d, 0xdb, 0xfc, 0xdd, 0x56, 0x4a, 0x97, 0xcf, 0x22, 0xc0, 0x35, 0x9f, 0xfe, 0xaf, 0x4f, 0x74, 0x0f, 0x17, 0x6a,
        0xa6, 0x70, 0xc3, 0xd0, 0xec, 0xc4, 0x83, 0x1a, 0x9d, 0x2b, 0x05, 0xd0, 0x11, 0xf3, 0x14, 0x75, 0x14, 0x18, 0xa0, 0x40,
        0x46, 0x6c, 0x8a, 0x67,
    ];

    static FFDHE4096_SK: &[u8] = &[
        0x91, 0x42, 0xd3, 0x3d, 0x99, 0x1f, 0x55, 0xf1, 0x14, 0x2c, 0x1f, 0xc8, 0xad, 0x70, 0xac, 0x62, 0x32, 0x5c, 0xf0, 0x2c,
        0x59, 0x4d, 0x65, 0x56, 0xb5, 0x16, 0x34, 0xcc, 0x6c, 0x44, 0x78, 0x74, 0xa1, 0xf4, 0x2c, 0xbf, 0x8e, 0xa3, 0x61, 0x34,
        0xc0, 0x94, 0xff, 0x8d, 0x7a, 0x6d, 0x4d, 0x9e,
    ];

    static FFDHE4096_PK: &[u8] = &[
        0x67, 0xc4, 0xc7, 0xf1, 0x2f, 0x94, 0x99, 0x7e, 0x47, 0xbe, 0xa1, 0x00, 0x26, 0x90, 0x9c, 0xd7, 0xe3, 0x83, 0x45, 0x49,
        0x76, 0x8f, 0x4b, 0xf0, 0x27, 0x72, 0x7f, 0xed, 0x0c, 0xb6, 0xbb, 0x3c, 0xfc, 0xce, 0x8e, 0x1c, 0x7a, 0xa5, 0x74, 0xdf,
        0x3b, 0x0b, 0x80, 0xed, 0x96, 0x1c, 0x81, 0x12, 0x71, 0x33, 0x22, 0xde, 0x05, 0xad, 0x2b, 0x37, 0x23, 0xd1, 0x9f, 0xf4,
        0xda, 0x91, 0xf9, 0xe0, 0xb8, 0xc5, 0xb6, 0x96, 0xb3, 0x52, 0xb9, 0x67, 0xba, 0x04, 0x5e, 0xab, 0x4e, 0x96, 0xee, 0xcb,
        0xe9, 0xb1, 0xa1, 0x64, 0xd6, 0x8c, 0x4b, 0x4f, 0xe9, 0x79, 0x5f, 0x0f, 0x8e, 0x6d, 0x8b, 0x9d, 0x6a, 0xbc, 0x96, 0x1e,
        0x20, 0x77, 0xd3, 0xe4, 0x45, 0x65, 0xbc, 0x14, 0xc6, 0x13, 0x05, 0x08, 0x1a, 0x2e, 0x95, 0x00, 0xab, 0xa8, 0xa8, 0xe2,
        0xc9, 0x0d, 0x31, 0x19, 0x7a, 0x5a, 0x92, 0x3f, 0x3a, 0x2f, 0x1b, 0xc8, 0xa2, 0x83, 0xc5, 0x3d, 0xab, 0x3a, 0x82, 0x66,
        0x44, 0x6a, 0x19, 0x73, 0x30, 0x5c, 0xb1, 0x01, 0x02, 0x13, 0x45, 0xf5, 0x3f, 0x0c, 0xae, 0xad, 0x10, 0x0a, 0xfb, 0x4e,
        0x48, 0xc9, 0xcd, 0x32, 0xa4, 0x21, 0xfa, 0x80, 0x95, 0x35, 0xd2, 0x7e, 0xe8, 0x96, 0x3e, 0xe5, 0x39, 0x2b, 0xe8, 0x1c,
        0x2e, 0x97, 0x1f, 0xd9, 0xf2, 0x34, 0xf2, 0x15, 0x5f, 0x9e, 0xfc, 0x2b, 0x17, 0x38, 0x00, 0x0e, 0x50, 0x68, 0xf4, 0xbc,
        0xae, 0xbc, 0xb8, 0x85, 0x66, 0x98, 0x66, 0xd3, 0x78, 0x7c, 0x3a, 0x2c, 0x8b, 0x04, 0x6a, 0x18, 0x54, 0x4e, 0x32, 0xb6,
        0xb9, 0xb5, 0xa8, 0x2f, 0xc9, 0x96, 0x66, 0xc1, 0x94, 0xf3, 0xb9, 0xac, 0x60, 0xd7, 0xc8, 0x93, 0xcd, 0xf6, 0xc1, 0x01,
        0x9d, 0x5a, 0x31, 0x6e, 0x11, 0x6b, 0x9a, 0x4a, 0x8d, 0x8e, 0x79, 0x3b, 0x01, 0xe3, 0x1a, 0xa4, 0x53, 0xa4, 0xd2, 0xb2,
        0xa7, 0x03, 0xf7, 0x6f, 0xb7, 0xc1, 0x1d, 0x0a, 0xa1, 0x23, 0xe5, 0x41, 0x30, 0x5b, 0x9e, 0xb8, 0xa5, 0xb3, 0x2a, 0xde,
        0x70, 0x66, 0xf3, 0x7a, 0x64, 0x72, 0x68, 0xb9, 0xe9, 0x25, 0x68, 0xd5, 0xbb, 0xa3, 0xde, 0xd3, 0x8a, 0xdc, 0xf3, 0xfb,
        0x57, 0xee, 0xca, 0x69, 0x84, 0x90, 0x78, 0x80, 0xf4, 0x08, 0xa4, 0xe0, 0x42, 0xa1, 0xaa, 0x77, 0x17, 0xcc, 0x45, 0x32,
        0x70, 0x7f, 0x90, 0x73, 0xc7, 0x9d, 0x50, 0xad, 0xee, 0x30, 0x17, 0x85, 0x90, 0x15, 0x00, 0xeb, 0x1e, 0xbd, 0x9f, 0x72,
        0xd3, 0x35, 0x5b, 0xdf, 0x4a, 0xaa, 0x79, 0x55, 0xfd, 0x81, 0xa3, 0xc2, 0x2d, 0x7e, 0x91, 0xaa, 0x50, 0x5a, 0x40, 0xdd,
        0x09, 0xa4, 0xc8, 0xad, 0x0a, 0x33, 0x37, 0xa0, 0x07, 0x74, 0x2f, 0x90, 0x0d, 0xc0, 0x01, 0xae, 0x00, 0x41, 0x8c, 0xc1,
        0xfc, 0xf0, 0xe2, 0xf5, 0x9d, 0x29, 0x16, 0xbd, 0xd2, 0x47, 0x67, 0xf7, 0x97, 0x48, 0x03, 0x81, 0xf0, 0x5f, 0xd9, 0x63,
        0x74, 0x7d, 0xb6, 0x56, 0xdc, 0xe5, 0x0a, 0xc0, 0x31, 0xd5, 0xff, 0xa9, 0x9a, 0x5b, 0xb6, 0x0b, 0xfe, 0xfc, 0xf4, 0xa5,
        0x00, 0x47, 0x34, 0x70, 0xc4, 0xa6, 0xd4, 0x84, 0x2c, 0x1b, 0x7a, 0xc1, 0x88, 0x5d, 0x69, 0x50, 0xdc, 0x40, 0xc2, 0xdd,
        0x03, 0x12, 0xb6, 0x5b, 0xba, 0x9a, 0xbb, 0xe7, 0xd8, 0xd4, 0xa7, 0x1e, 0xeb, 0xd1, 0x98, 0x58, 0xd0, 0xec, 0xe4, 0xcd,
        0x7b, 0x99, 0x5f, 0xd7, 0x13, 0xe5, 0x9c, 0x3e, 0xc5, 0x02, 0xf2, 0xac, 0xc9, 0x2f, 0x83, 0xd1, 0xb2, 0x78, 0x0f, 0x8b,
        0x1f, 0x8b, 0xa3, 0xc4, 0x3d, 0xc8, 0x40, 0x75, 0x3f, 0xbf, 0x9a, 0x46, 0x11, 0x19, 0xbc, 0x68, 0x8f, 0x61, 0x03, 0x9f,
        0x22, 0x84, 0x4b, 0xc1, 0x78, 0x9d, 0xc9, 0xc3, 0xe3, 0xa8, 0x4c, 0x3c,
    ];
    static FFDHE6144_SK: &[u8] = &[
        0x59, 0x53, 0x7c, 0x5f, 0xd9, 0xb2, 0x51, 0x1a, 0x9f, 0x63, 0xee, 0x4e, 0x36, 0x8e, 0xf1, 0x11, 0x0a, 0x8b, 0x50, 0xf2,
        0x12, 0xb0, 0x53, 0xa5, 0x61, 0x52, 0x42, 0x4f, 0x37, 0x7f, 0x42, 0x05, 0x6d, 0x16, 0x73, 0x3e, 0x5b, 0x89, 0xd0, 0x95,
        0xd8, 0x37, 0x89, 0xc7, 0x11, 0xc1, 0xef, 0x55, 0x76, 0x9a, 0xe3, 0xbe, 0x1b, 0xaf, 0x71, 0x85,
    ];

    static FFDHE6144_PK: &[u8] = &[
        0x9f, 0x91, 0x2b, 0x64, 0x91, 0xad, 0x8a, 0x89, 0x46, 0x99, 0x57, 0xb2, 0x84, 0xf6, 0x3d, 0x53, 0x6d, 0x02, 0xc7, 0x82,
        0x82, 0x18, 0x9c, 0xa5, 0x8e, 0xa1, 0x8a, 0x09, 0x3a, 0x17, 0x34, 0x96, 0x26, 0x78, 0x25, 0xae, 0x84, 0x15, 0xa9, 0x6e,
        0xe8, 0xf4, 0xf4, 0xee, 0x13, 0x9a, 0xe2, 0x27, 0x74, 0xad, 0x86, 0x8f, 0xd8, 0xc2, 0x68, 0x95, 0x39, 0x8e, 0x27, 0xca,
        0x6f, 0xaf, 0x37, 0xe3, 0xd3, 0xb6, 0xbd, 0x45, 0xf8, 0xea, 0xd3, 0x4d, 0xff, 0x37, 0xb3, 0xf4, 0x72, 0xfe, 0xf7, 0x57,
        0x30, 0x95, 0xf9, 0x45, 0x8b, 0xa3, 0xf6, 0x8e, 0x4c, 0xdc, 0x48, 0x91, 0xb8, 0x6a, 0xa5, 0x5f, 0x60, 0xb8, 0x43, 0xdf,
        0xed, 0xc2, 0xd8, 0x38, 0x42, 0x47, 0x47, 0xf2, 0x34, 0xd6, 0xb5, 0xff, 0x18, 0x6d, 0x3c, 0x7f, 0xf9, 0x82, 0x77, 0xb5,
        0x6e, 0x4f, 0x88, 0xec, 0x92, 0x7b, 0x9c, 0x15, 0x79, 0xb8, 0xd8, 0xa7, 0x74, 0x41, 0xeb, 0x94, 0x84, 0x3a, 0x37, 0xdb,
        0x9c, 0x89, 0x93, 0xd2, 0x64, 0xbc, 0x50, 0x40, 0x44, 0xfa, 0x12, 0x91, 0xb1, 0x0a, 0x0a, 0xe4, 0x6b, 0x13, 0xc3, 0x94,
        0x1b, 0xf3, 0x8c, 0x4a, 0xee, 0x21, 0x12, 0x85, 0xe6, 0xbe, 0x0f, 0x67, 0x7d, 0x29, 0x99, 0x67, 0x67, 0x3a, 0xd1, 0x14,
        0x22, 0xd7, 0x5f, 0x05, 0x6e, 0x64, 0x7c, 0xeb, 0xa9, 0xcc, 0xa4, 0x4f, 0x80, 0x42, 0xe6, 0x24, 0x02, 0x3d, 0x63, 0x51,
        0x39, 0x3f, 0x6a, 0x3a, 0xce, 0xc8, 0xa0, 0xba, 0x12, 0xd6, 0x0c, 0xe5, 0x9b, 0x58, 0x24, 0x75, 0xc8, 0x6e, 0xd8, 0xec,
        0xaf, 0xd6, 0xad, 0x9b, 0xcb, 0xda, 0x37, 0x20, 0x40, 0x5d, 0x70, 0x01, 0xe3, 0x34, 0x79, 0x91, 0x57, 0x87, 0x65, 0xce,
        0x66, 0x5f, 0x31, 0xf6, 0xd9, 0xbb, 0x71, 0x5a, 0x84, 0x13, 0x60, 0x40, 0xd3, 0x9e, 0x60, 0x52, 0x57, 0xed, 0x27, 0xb6,
        0x98, 0xcc, 0x63, 0x8c, 0xad, 0xf4, 0x54, 0x99, 0xcc, 0x54, 0x9d, 0xe0, 0x4e, 0xc1, 0x2e, 0xfb, 0x9f, 0x0e, 0xe3, 0x0a,
        0xd1, 0x1a, 0x76, 0x77, 0x75, 0x7a, 0x2b, 0x22, 0xd7, 0x4d, 0x09, 0x67, 0x11, 0xa1, 0x29, 0xbe, 0xfc, 0x69, 0xde, 0xd1,
        0x1e, 0x2d, 0xc5, 0x2f, 0x5c, 0x2e, 0xda, 0xd8, 0x8a, 0x35, 0x05, 0xcc, 0xe5, 0x76, 0xdb, 0x60, 0xf4, 0xcb, 0xbf, 0xe7,
        0x3a, 0xf9, 0xf8, 0x58, 0xe1, 0xbc, 0xe6, 0xea, 0x88, 0x05, 0xc9, 0x15, 0x33, 0x43, 0x71, 0xb0, 0xad, 0xc0, 0x81, 0xe0,
        0x19, 0x0b, 0xd7, 0xb8, 0xf2, 0x95, 0x31, 0x91, 0x83, 0xd8, 0x19, 0x7e, 0x45, 0x01, 0xef, 0x0c, 0xbe, 0xad, 0xd2, 0xa4,
        0x0b, 0x79, 0x9e, 0x18, 0x83, 0x6f, 0xa8, 0xe2, 0x7c, 0x2b, 0x07, 0xd9, 0x26, 0xed, 0xd2, 0x20, 0xd2, 0xf4, 0x54, 0xc8,
        0x80, 0xbf, 0xfa, 0x71, 0x5f, 0xa8, 0x27, 0xc3, 0x1c, 0xba, 0xeb, 0xc0, 0xe2, 0x87, 0xb3, 0x13, 0xf0, 0x18, 0xce, 0xa9,
        0x67, 0x10, 0xa1, 0x0a, 0xff, 0x2e, 0x02, 0xd8, 0x7d, 0x0d, 0xd2, 0x5a, 0x4f, 0x13, 0xb2, 0x82, 0x3d, 0x01, 0x1a, 0x5a,
        0x44, 0xf6, 0xa2, 0x50, 0x30, 0x44, 0x50, 0x78, 0xdb, 0x66, 0x87, 0xa4, 0x0b, 0x9f, 0x2e, 0xfa, 0xc9, 0x83, 0x38, 0x7e,
        0xe9, 0xef, 0xc9, 0xdb, 0x05, 0x92, 0xe9, 0xdb, 0x3a, 0x3c, 0xa9, 0xb6, 0xe1, 0xdd, 0x71, 0x57, 0x4b, 0x93, 0x27, 0xa3,
        0x37, 0x71, 0x2c, 0xce, 0xff, 0xcc, 0xfc, 0x02, 0xef, 0xbf, 0x48, 0x1d, 0x74, 0x90, 0x8e, 0x41, 0x3a, 0x66, 0xf3, 0xf7,
        0x5e, 0x1b, 0xcb, 0x48, 0x42, 0xcf, 0x2d, 0x00, 0xe3, 0x51, 0x5d, 0x5f, 0xe9, 0x33, 0x9c, 0x24, 0x05, 0x97, 0xc2, 0x83,
        0x9b, 0x08, 0x03, 0xb6, 0x04, 0x79, 0x0d, 0xb9, 0x2a, 0xe9, 0x6c, 0x7c, 0xf7, 0x01, 0x77, 0xc4, 0x97, 0xdd, 0x38, 0xdd,
        0xe0, 0x66, 0xd0, 0x41, 0x24, 0x50, 0x6d, 0xec, 0x13, 0x19, 0x13, 0x66, 0x2c, 0xdb, 0x2b, 0x29, 0xa1, 0xfd, 0x55, 0x4f,
        0x95, 0x95, 0x11, 0xa5, 0x1c, 0x68, 0x42, 0x17, 0x57, 0x31, 0x7b, 0xff, 0x69, 0xa5, 0xce, 0x67, 0xd4, 0x02, 0xa0, 0xb3,
        0xd6, 0x29, 0x56, 0xde, 0x24, 0xcc, 0x40, 0xf9, 0xd2, 0x86, 0x5d, 0x07, 0xb4, 0xd7, 0x2b, 0xde, 0xe9, 0x92, 0xd8, 0x31,
        0xb9, 0x9b, 0xd5, 0xfa, 0xbf, 0xbb, 0x14, 0x72, 0xf6, 0xe2, 0x63, 0x4d, 0x4a, 0x43, 0xf9, 0xf4, 0x0b, 0x01, 0x14, 0xc2,
        0x8f, 0x06, 0x77, 0x9f, 0x2b, 0x2e, 0x7e, 0xbe, 0x62, 0xff, 0xfc, 0x87, 0xa9, 0x8f, 0x62, 0x9a, 0x76, 0x48, 0xd8, 0x57,
        0x12, 0xcd, 0x8e, 0x47, 0x07, 0x81, 0x98, 0x0f, 0x96, 0x99, 0x57, 0xf7, 0xd8, 0x2d, 0x37, 0xa8, 0x56, 0xb6, 0x69, 0x2a,
        0x38, 0xd7, 0x8d, 0xa4, 0x8e, 0x5d, 0xb7, 0x2e, 0x5c, 0x68, 0x0e, 0x38, 0x5a, 0xc6, 0xf8, 0x14, 0xb6, 0xfd, 0x4c, 0x25,
        0x61, 0x23, 0xb8, 0x80, 0xae, 0x64, 0xcc, 0x2d, 0x8c, 0x8f, 0x15, 0x44, 0xd5, 0xb6, 0x27, 0x0f, 0x81, 0x8b, 0xfd, 0x8c,
        0x23, 0x47, 0x34, 0x28, 0x5b, 0x8f, 0x74, 0x16, 0x7a, 0x0f, 0x6f, 0x72, 0xdc, 0x71, 0xc9, 0x2b, 0xed, 0xdc, 0x6e, 0x77,
        0xb3, 0xf6, 0xfa, 0x0a, 0xf2, 0xfd, 0x22, 0x27, 0xff, 0xd6, 0xfa, 0x3c, 0x8a, 0xa1, 0xbc, 0x3a, 0x4c, 0x10, 0x5b, 0x83,
        0x02, 0xf9, 0x55, 0xf4, 0xbf, 0xb9, 0x5e, 0x38, 0x60, 0x07, 0x73, 0xdc, 0x5a, 0x48, 0x24, 0x4d, 0xfd, 0xf5, 0xd0, 0x57,
        0xf9, 0x25, 0xcc, 0x2e, 0xe9, 0xea, 0x8d, 0x43, 0x46, 0x66, 0x7b, 0x34, 0x97, 0x01, 0x65, 0xd2, 0xf0, 0x06, 0x87, 0xeb,
        0x1e, 0x7a, 0xe0, 0xaa, 0xef, 0x46, 0x2c, 0xb1,
    ];
    static FFDHE8192_SK: &[u8] = &[
        0x20, 0x8b, 0x62, 0x3b, 0x71, 0x25, 0x5c, 0xa8, 0x86, 0x86, 0xae, 0xca, 0x64, 0x89, 0xe3, 0x4c, 0xba, 0x95, 0xa3, 0xb5,
        0x7e, 0xfa, 0x7e, 0xd8, 0xda, 0xc7, 0x8d, 0xd3, 0xaa, 0x49, 0x7c, 0xc2, 0x95, 0x1c, 0x4d, 0x5b, 0x3a, 0x50, 0x7c, 0x96,
        0xff, 0x22, 0x3a, 0x4b, 0x31, 0xb9, 0x9b, 0x3c, 0xc9, 0x4a, 0x4f, 0x2d, 0xc0, 0xdc, 0x17, 0xe8, 0x46, 0xb3, 0xeb, 0x75,
        0x0c, 0x5b, 0x38, 0x12,
    ];
    static FFDHE8192_PK: &[u8] = &[
        0x54, 0x29, 0x48, 0x93, 0x01, 0x35, 0x1c, 0x37, 0x8c, 0x3f, 0xca, 0x9a, 0x90, 0xd3, 0x23, 0x4c, 0x18, 0xfe, 0x2d, 0xaf,
        0x88, 0x94, 0x73, 0x0d, 0xb8, 0x2c, 0x7c, 0x63, 0xe7, 0x91, 0xe9, 0x2f, 0xa1, 0xa9, 0x1a, 0x49, 0xbe, 0x6d, 0xaf, 0x31,
        0x5c, 0x0f, 0x0c, 0xd2, 0xfc, 0xe0, 0x7f, 0xcd, 0x8c, 0x84, 0x77, 0xb5, 0x4d, 0x8a, 0x03, 0xab, 0x06, 0x38, 0x82, 0x25,
        0x52, 0x1a, 0xa0, 0x80, 0x72, 0x4c, 0x6a, 0xbb, 0xe1, 0x01, 0xf7, 0x01, 0x54, 0xea, 0x3e, 0x6b, 0x81, 0xce, 0x31, 0x98,
        0x3f, 0x33, 0x20, 0xa7, 0x08, 0x9d, 0xe5, 0x81, 0x9e, 0x12, 0x10, 0x89, 0x70, 0x99, 0x09, 0x71, 0xd5, 0x60, 0xbc, 0x05,
        0x20, 0xf8, 0x7e, 0x20, 0xd3, 0x2e, 0x76, 0x34, 0x44, 0x30, 0xe9, 0x8d, 0xd1, 0x57, 0x45, 0xb9, 0xc0, 0x47, 0x02, 0xd5,
        0x4d, 0x7a, 0xd1, 0xd5, 0x94, 0x7a, 0x38, 0xa3, 0xbb, 0xbe, 0xb0, 0xcb, 0xdc, 0xdf, 0x72, 0x72, 0x38, 0xd4, 0x36, 0x57,
        0x79, 0x88, 0x4c, 0xc9, 0x5a, 0xd6, 0x28, 0x39, 0x62, 0x6a, 0x1e, 0x0c, 0xb1, 0x8c, 0x02, 0x1a, 0xf5, 0xc4, 0xcd, 0xff,
        0x4d, 0x2e, 0x5a, 0x62, 0x17, 0xe2, 0xd9, 0xa5, 0x22, 0xd8, 0xd3, 0xcc, 0xd0, 0x86, 0x66, 0x9c, 0x87, 0xd9, 0x37, 0x61,
        0x40, 0xdc, 0xe7, 0x48, 0x28, 0x82, 0x4c, 0xfb, 0x7e, 0x58, 0x36, 0x2e, 0x7e, 0xe3, 0xae, 0xf0, 0x9c, 0x30, 0xb7, 0x75,
        0xda, 0xaa, 0x68, 0x7e, 0xdf, 0xd9, 0x93, 0xbc, 0x61, 0x5a, 0x72, 0xeb, 0xf3, 0x11, 0x4e, 0x4d, 0x7f, 0x41, 0x74, 0x3b,
        0x53, 0x10, 0xc1, 0xdf, 0x13, 0x54, 0xf1, 0x83, 0xc6, 0x37, 0x0d, 0xd4, 0x56, 0xe9, 0x30, 0x3f, 0x36, 0x4f, 0x4f, 0x2f,
        0x0b, 0x23, 0x84, 0xa9, 0x55, 0xf0, 0x05, 0xb8, 0xb5, 0xbb, 0xdd, 0x1d, 0x93, 0xb2, 0xf4, 0xa6, 0x9e, 0x5d, 0x0e, 0x59,
        0x3d, 0x50, 0x1b, 0x21, 0xac, 0x45, 0x7b, 0xe2, 0x08, 0xef, 0xfb, 0x7b, 0x34, 0x6d, 0x2f, 0x86, 0x12, 0xf8, 0x97, 0x37,
        0x79, 0x3c, 0xed, 0x61, 0x6c, 0x96, 0x61, 0xaa, 0x3f, 0x3e, 0x52, 0xb2, 0x7c, 0x8f, 0x0d, 0xba, 0x04, 0xd1, 0x90, 0x96,
        0x4c, 0xd6, 0x46, 0x4a, 0xc5, 0x3e, 0x8c, 0xed, 0x0b, 0x22, 0xc7, 0x04, 0x6b, 0x9c, 0x24, 0x91, 0xf3, 0x8f, 0xe9, 0xa9,
        0xde, 0xf6, 0x37, 0x19, 0xf0, 0x34, 0xd9, 0xee, 0xb9, 0xdc, 0xd0, 0x78, 0xaa, 0x12, 0xb8, 0x60, 0x51, 0xe4, 0xef, 0x6a,
        0x2a, 0x0e, 0xf1, 0x2c, 0x0d, 0xe8, 0xe0, 0x6e, 0xc7, 0xdf, 0xe0, 0x98, 0x22, 0x0e, 0xbf, 0x61, 0x23, 0x69, 0xb3, 0x76,
        0x67, 0x4c, 0xd0, 0xe3, 0x3d, 0xe3, 0xbe, 0x5f, 0x41, 0x16, 0x6f, 0xb5, 0x7b, 0x32, 0xf9, 0x98, 0xf9, 0x14, 0xf3, 0x06,
        0x3b, 0x58, 0xf3, 0xe2, 0x1a, 0x41, 0x8e, 0x68, 0x71, 0xb2, 0x82, 0xf4, 0x0b, 0x9a, 0x06, 0x34, 0x74, 0x85, 0xba, 0x88,
        0xae, 0x7c, 0xa1, 0x26, 0xe7, 0xa1, 0xc7, 0xe4, 0xd2, 0x66, 0xf8, 0x06, 0x46, 0x45, 0xc8, 0x9e, 0x55, 0x4f, 0xc9, 0x60,
        0xe2, 0x9e, 0xe9, 0xf1, 0xf7, 0x5e, 0x1b, 0x35, 0x9e, 0x0e, 0x39, 0x10, 0xfb, 0xb9, 0xb9, 0xd0, 0x22, 0xdd, 0x41, 0xc8,
        0x5b, 0x14, 0xd0, 0x89, 0x4b, 0x48, 0x46, 0x47, 0x17, 0x93, 0x0e, 0x6d, 0x09, 0x9f, 0x5a, 0xfa, 0xdf, 0x37, 0x86, 0x7d,
        0x5c, 0xde, 0x90, 0x46, 0x76, 0xf6, 0x7f, 0xa9, 0x7c, 0xd8, 0x29, 0x80, 0xfa, 0x43, 0x83, 0xff, 0xb6, 0x3b, 0x26, 0x2f,
        0x3c, 0x92, 0xd5, 0x8f, 0x6c, 0x74, 0x2c, 0xba, 0x01, 0x94, 0x95, 0xcb, 0x4e, 0x71, 0x7b, 0xfb, 0x25, 0x04, 0x3a, 0x5f,
        0xa9, 0x0f, 0x0f, 0xdb, 0x97, 0xe4, 0xb3, 0x09, 0x9a, 0x23, 0x52, 0x5d, 0xa8, 0x87, 0x64, 0xda, 0xd0, 0xe9, 0x24, 0xdd,
        0xc3, 0x7c, 0xf0, 0xbc, 0xe1, 0x32, 0x2f, 0xd6, 0x7b, 0x5e, 0x0f, 0x14, 0x29, 0x84, 0x4f, 0xef, 0x98, 0x08, 0xb0, 0x73,
        0x82, 0xac, 0xab, 0x5a, 0x93, 0xcf, 0x53, 0xc2, 0xef, 0xbf, 0x8e, 0x1d, 0xbf, 0x78, 0xb9, 0x0c, 0x15, 0x78, 0xc2, 0x07,
        0xbd, 0xea, 0xdb, 0x85, 0xc8, 0xc3, 0x6d, 0x97, 0x52, 0x5f, 0xbb, 0x8b, 0x1d, 0x67, 0xda, 0x2c, 0xb2, 0xd7, 0x31, 0xda,
        0x92, 0xbb, 0x1d, 0x99, 0xc3, 0xfd, 0x14, 0xc7, 0x1c, 0xda, 0xc5, 0x4c, 0x5d, 0x72, 0x8f, 0x1a, 0x9d, 0x47, 0x86, 0x67,
        0x38, 0xf4, 0xee, 0xd6, 0x6a, 0x10, 0xc0, 0x88, 0xbb, 0xa8, 0x67, 0x95, 0x4b, 0x48, 0x20, 0xf2, 0x7f, 0x1c, 0xef, 0x15,
        0xde, 0x0d, 0x6a, 0xe0, 0xbe, 0x64, 0xe1, 0x7b, 0x1d, 0xda, 0x8a, 0xcf, 0x4a, 0xb5, 0xb8, 0xef, 0x2a, 0xaf, 0x81, 0xa3,
        0x7e, 0xb7, 0x90, 0x46, 0x14, 0xad, 0x76, 0x05, 0x55, 0x18, 0xec, 0x13, 0x9b, 0x8e, 0xd2, 0x02, 0xda, 0x11, 0xdd, 0xc2,
        0xb0, 0x5c, 0x16, 0xba, 0x8f, 0xc3, 0x85, 0xc3, 0x1a, 0xf7, 0xe2, 0xeb, 0x77, 0x46, 0x9e, 0xf8, 0xe0, 0x5a, 0xfd, 0x91,
        0xb2, 0x14, 0x31, 0xd4, 0xac, 0x66, 0xae, 0xd2, 0x16, 0x75, 0xe9, 0x20, 0x05, 0x45, 0xf8, 0x00, 0x50, 0x5d, 0x8d, 0x06,
        0x21, 0x5d, 0x82, 0x39, 0x85, 0x16, 0x44, 0xaa, 0xb5, 0x7d, 0xe3, 0x97, 0x48, 0x14, 0xbd, 0x6e, 0x8d, 0xa6, 0xf7, 0x5b,
        0x1f, 0x37, 0x7c, 0x70, 0x55, 0x98, 0xa5, 0xf4, 0x73, 0x6b, 0x50, 0x70, 0xef, 0xbb, 0x4f, 0x27, 0xa5, 0x24, 0x3e, 0x61,
        0x1f, 0x57, 0x4d, 0xdc, 0xc3, 0x8c, 0xae, 0xb4, 0x61, 0x5e, 0x13, 0x14, 0x19, 0xf6, 0x62, 0xb0, 0xde, 0xf7, 0x65, 0x21,
        0x71, 0xd7, 0x18, 0xd3, 0x6b, 0xbf, 0xbf, 0x08, 0x09, 0x5a, 0x52, 0x86, 0x59, 0xb4, 0x28, 0xa7, 0xe1, 0x32, 0x92, 0xaa,
        0x16, 0xd0, 0x91, 0xe8, 0xf0, 0x2c, 0x26, 0x8f, 0xe1, 0x3d, 0xe0, 0x0b, 0xaa, 0xe5, 0x99, 0x9e, 0x4f, 0x77, 0x80, 0xcd,
        0x08, 0x28, 0x6f, 0x22, 0x1b, 0xb3, 0x5e, 0x8f, 0x6c, 0x40, 0x8e, 0x20, 0x03, 0x86, 0xa7, 0x12, 0x65, 0x67, 0x07, 0xf3,
        0x8f, 0x27, 0xd0, 0xf1, 0x33, 0x02, 0x31, 0x24, 0xa6, 0xde, 0x28, 0x5d, 0x99, 0xbe, 0x74, 0x89, 0x41, 0xa1, 0x21, 0x57,
        0xb7, 0x50, 0x4c, 0xab, 0xde, 0x02, 0x34, 0x56, 0xd5, 0xee, 0x36, 0x6e, 0x22, 0xf0, 0x4c, 0xbf, 0xa9, 0x3c, 0x06, 0x16,
        0x88, 0xd2, 0x42, 0xa1, 0x71, 0xaa, 0x70, 0x8b, 0x34, 0x1e, 0xb7, 0x93, 0x5d, 0x40, 0xb1, 0xde, 0x6b, 0x69, 0x6e, 0x91,
        0x5f, 0xac, 0x8c, 0xdf, 0x8e, 0x33, 0x27, 0xcb, 0x17, 0xb3, 0x36, 0xf1, 0xb6, 0xd0, 0xe6, 0x73, 0x15, 0xde, 0x1c, 0x20,
        0xc0, 0xa0, 0x0a, 0x4d, 0x78, 0x22, 0x49, 0xaf, 0x90, 0x34, 0x7c, 0x64, 0xcf, 0x77, 0x77, 0x1f, 0x2a, 0xdd, 0xe8, 0x47,
        0x0c, 0x23, 0x8e, 0x14, 0xb4, 0xef, 0x7d, 0xc4, 0x21, 0x8c, 0x6b, 0x3c, 0xf1, 0xd3, 0x2e, 0xf3, 0x7d, 0xf5, 0x01, 0x4a,
        0x24, 0xa5, 0x4e, 0x45, 0x48, 0x15, 0xb9, 0x0d, 0xd8, 0x21, 0x38, 0x0c, 0x8f, 0x69, 0x2e, 0xb0, 0x76, 0x7b, 0xf7, 0x12,
        0xf9, 0x48, 0xa5, 0xb1, 0x14, 0x5a, 0xe5, 0xb4, 0x09, 0x6e, 0x9b, 0x26, 0xc3, 0x8c, 0x20, 0x20, 0x86, 0x32, 0xd9, 0xbc,
        0xbd, 0xab, 0x41, 0xda, 0xba, 0x99, 0xad, 0x85, 0x36, 0x3e, 0x37, 0x95, 0x9e, 0xd3, 0xb5, 0x80, 0x47, 0xd3, 0x52, 0x7d,
        0xf4, 0xfc, 0x96, 0xa9, 0xcd, 0x22, 0x53, 0x99, 0x54, 0x37, 0x97, 0x59, 0xc7, 0x10, 0x85, 0x04, 0xe8, 0xd2, 0xda, 0xa5,
        0x71, 0x3c, 0xb4, 0xc8,
    ];
}
