use std::{
    fs::File,
    io::{BufReader, Cursor},
    sync::Arc,
};

use anyhow::{anyhow, Context, Error, Result};
use async_std::{net::TcpStream, path::PathBuf};
use async_tls::TlsConnector;
use log::LevelFilter;
use rustls::{
    internal::pemfile::certs, internal::pemfile::rsa_private_keys, Certificate, ClientConfig,
    PrivateKey,
};
use simplelog::{Config, SimpleLogger};

#[async_std::main]
async fn main() -> Result<()> {
    // Init logger
    SimpleLogger::init(LevelFilter::Debug, Config::default()).unwrap();

    // Connect to localhost
    let address = "127.0.0.1:6969";
    let tcp_stream = TcpStream::connect(&address).await.context(format!(
        "Failed to connect to on {}. Did you start it?",
        &address
    ))?;

    // Get the configured rustls TlsConnector
    let tls_connector = get_tls_connector()
        .await
        .context("Failed to initialize TLS Connector")?;

    // Initialize the TLS layer
    let stream = tls_connector
        .connect("pueue.local", tcp_stream)
        .await
        .context("Failed to initialize TLS stream")?;

    Ok(())
}

/// Initialize our client [TlsConnector].
/// 1. Trust our own CA. ONLY our own CA.
/// 2. Set the client certificate and key
pub async fn get_tls_connector() -> Result<TlsConnector> {
    let mut config = ClientConfig::new();

    // Trust server-certificates signed with our own CA.
    let mut ca = load_ca(PathBuf::from("./certs/ca-cert.pem"))?;
    config
        .root_store
        .add_pem_file(&mut ca)
        .map_err(|_| anyhow!("Failed to add CA to client root store."))?;

    // Set the client-side key and certificate that should be used for any communication
    let certs = load_certs(PathBuf::from("./certs/client-cert.pem"))?;
    let mut keys = load_keys(PathBuf::from("./certs/client-key.pem"))?;
    config
        // set this server to use one cert together with the loaded private key
        .set_single_client_cert(certs, keys.remove(0))
        .map_err(|err| Error::new(err))
        .context("Failed to set single certificate for daemon.")?;

    config.enable_sni = false;

    Ok(TlsConnector::from(Arc::new(config)))
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
