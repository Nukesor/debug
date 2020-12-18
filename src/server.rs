use std::{
    fs::File,
    io::{BufReader, Cursor},
    sync::Arc,
};

use anyhow::{anyhow, Context, Error, Result};
use async_std::{net::TcpListener, path::PathBuf};
use async_tls::TlsAcceptor;
use log::LevelFilter;
use rustls::{
    internal::pemfile::certs, internal::pemfile::rsa_private_keys, Certificate, PrivateKey,
    ServerConfig,
};
use simplelog::{Config, SimpleLogger};

#[async_std::main]
async fn main() -> Result<()> {
    // Init logger
    SimpleLogger::init(LevelFilter::Debug, Config::default()).unwrap();

    // Listen on localhost
    let address = "127.0.0.1:6969";
    let tcp_listener = TcpListener::bind(address).await?;
    let tls_acceptor = get_tls_listener()?;

    // Accept connection and start TLS session

    loop {
        let (stream, _) = tcp_listener
            .accept()
            .await
            .context("Client failed to connect early.")?;

        // Poll incoming connections.
        let _stream = match tls_acceptor.accept(stream).await {
            Ok(stream) => stream,
            Err(err) => {
                println!("Failed connecting to client: {:?}", err);
                continue;
            }
        };
    }

    Ok(())
}

/// Configure the server using rusttls.
/// A TLS server needs a certificate and a fitting private key.
/// On top of that, we require authentication via client certificates.
/// We need to trust our own CA for that to work.
pub fn get_tls_listener() -> Result<TlsAcceptor> {
    // Initialize our cert store with our own CA.
    let mut root_store = rustls::RootCertStore::empty();
    let mut ca = load_ca(PathBuf::from("./certs/ca-cert.pem"))?;
    root_store
        .add_pem_file(&mut ca)
        .map_err(|_| anyhow!("Failed to add CA to client root store."))?;

    // Only trust clients with a valid certificate of our own CA.
    let client_auth_only = rustls::AllowAnyAuthenticatedClient::new(root_store);
    let mut config = ServerConfig::new(client_auth_only);

    // Set the mtu to 1500, since we might have non-local communication.
    config.mtu = Some(1500);

    // Set the server-side key and certificate that should be used for any communication
    let certs = load_certs(PathBuf::from("./certs/server-cert.pem"))?;
    let mut keys = load_keys(PathBuf::from("./certs/server-key.pem"))?;
    config
        // set this server to use one cert together with the loaded private key
        .set_single_cert(certs, keys.remove(0))
        .map_err(|err| Error::new(err))
        .context("Failed to set single certificate for daemon.")?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Load the passed certificates file
fn load_certs(path: PathBuf) -> Result<Vec<Certificate>> {
    certs(&mut BufReader::new(File::open(path)?))
        .map_err(|_| anyhow!("Failed to parse daemon certificate."))
}

/// Load the passed keys file
fn load_keys(path: PathBuf) -> Result<Vec<PrivateKey>> {
    rsa_private_keys(&mut BufReader::new(File::open(path)?))
        .map_err(|_| anyhow!("Failed to parse daemon key."))
}

fn load_ca(path: PathBuf) -> Result<Cursor<Vec<u8>>> {
    let file = std::fs::read(path).map_err(|_| anyhow!("Failed to read CA file."))?;
    Ok(Cursor::new(file))
}
