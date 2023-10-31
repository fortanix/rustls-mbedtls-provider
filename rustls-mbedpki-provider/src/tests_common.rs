#![cfg(test)]

use std::{io, ops::{DerefMut, Deref}};

use rustls::{Certificate, PrivateKey, ConnectionCommon, SideData, ClientConnection, ServerConnection};

/// Get a certificate chain from the contents of a pem file
pub fn get_chain(bytes: &[u8]) -> Vec<Certificate> {
    rustls_pemfile::certs(&mut io::BufReader::new(bytes)).unwrap().into_iter()
        .map(Certificate)
        .collect()
}

/// Get a private key from the contents of a pem file
pub fn get_key(bytes: &[u8]) -> PrivateKey {
    PrivateKey(rustls_pemfile::pkcs8_private_keys(&mut io::BufReader::new(bytes)).unwrap().into_iter().next().unwrap())
}

pub fn transfer(
    left: &mut (impl DerefMut + Deref<Target = ConnectionCommon<impl SideData>>),
    right: &mut (impl DerefMut + Deref<Target = ConnectionCommon<impl SideData>>),
) -> usize {
    let mut buf = [0u8; 262144];
    let mut total = 0;

    while left.wants_write() {
        let sz = {
            let into_buf: &mut dyn io::Write = &mut &mut buf[..];
            left.write_tls(into_buf).unwrap()
        };
        total += sz;
        if sz == 0 {
            return total;
        }

        let mut offs = 0;
        loop {
            let from_buf: &mut dyn io::Read = &mut &buf[offs..sz];
            offs += right.read_tls(from_buf).unwrap();
            if sz == offs {
                break;
            }
        }
    }

    total
}

pub fn do_handshake_until_error(
    client: &mut ClientConnection,
    server: &mut ServerConnection,
) -> Result<(), rustls::Error> {
    while server.is_handshaking() || client.is_handshaking() {
        transfer(client, server);
        server
            .process_new_packets()?;
        transfer(server, client);
        client
            .process_new_packets()?;
    }
    Ok(())
}