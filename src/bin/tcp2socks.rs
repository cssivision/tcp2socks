use std::io;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use tcp2socks::args::parse_args;

#[tokio::main]
async fn main() -> io::Result<()> {
    env_logger::init();
    let config = parse_args("tcp2socks").unwrap();
    log::info!("config: {}", serde_json::to_string_pretty(&config).unwrap());
    let local_addr: SocketAddr = config
        .local_addr
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid local address"))?;
    let server_addr: SocketAddr = config
        .server_addr
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid server address"))?;

    let listener = TcpListener::bind(local_addr).await?;
    loop {
        let (socket, addr) = listener.accept().await?;
        log::debug!("remote address: {}", addr);
        let host = config.host.clone();
        let port = config.port;
        tokio::spawn(async move {
            if let Err(err) = tunnel(socket, host, port, server_addr).await {
                log::error!("proxy fail: {}", err);
            }
        });
    }
}
// Create a TCP connection to server_addr, build a tunnel between the connection and
// the incoming connection.
async fn tunnel(
    mut incoming: TcpStream,
    host: String,
    port: u16,
    server_addr: SocketAddr,
) -> io::Result<()> {
    let mut server = timeout(CONNECT_TIMEOUT, TcpStream::connect(server_addr)).await??;
    handshake(&mut server, CONNECT_TIMEOUT, host, port).await?;
    let (n1, n2) = copy_bidirectional(&mut incoming, &mut server).await?;
    log::debug!("client wrote {} bytes and received {} bytes", n1, n2);
    Ok(())
}

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

fn other(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, msg)
}

pub mod v5 {
    pub const VERSION: u8 = 5;
    pub const METH_NO_AUTH: u8 = 0;
    pub const CMD_CONNECT: u8 = 1;
    pub const TYPE_IPV4: u8 = 1;
    pub const TYPE_IPV6: u8 = 4;
    pub const TYPE_DOMAIN: u8 = 3;
    pub const REPLY_SUCESS: u8 = 0;
}

async fn handshake(conn: &mut TcpStream, dur: Duration, host: String, port: u16) -> io::Result<()> {
    let fut = async move {
        log::trace!("write socks5 version and auth method");
        let n_meth_auth: u8 = 1;
        conn.write_all(&[v5::VERSION, n_meth_auth, v5::METH_NO_AUTH])
            .await?;
        let buf1 = &mut [0u8; 2];

        log::trace!("read server socks version and mthod");
        conn.read_exact(buf1).await?;
        if buf1[0] != v5::VERSION {
            return Err(other("unknown version"));
        }
        if buf1[1] != v5::METH_NO_AUTH {
            return Err(other("unknow auth method"));
        }

        log::trace!("write socks5 version and command");
        conn.write_all(&[v5::VERSION, v5::CMD_CONNECT, 0u8]).await?;

        log::trace!("write address type and address");
        // write address
        let (address_type, mut address_bytes) = if let Ok(addr) = IpAddr::from_str(&host) {
            match addr {
                IpAddr::V4(v) => (v5::TYPE_IPV4, v.octets().to_vec()),
                IpAddr::V6(v) => (v5::TYPE_IPV6, v.octets().to_vec()),
            }
        } else {
            let domain_len = host.len() as u8;
            let mut domain_bytes = vec![domain_len];
            domain_bytes.extend_from_slice(&host.into_bytes());
            (v5::TYPE_DOMAIN, domain_bytes)
        };
        conn.write_all(&[address_type]).await?;
        address_bytes.extend_from_slice(&port.to_be_bytes());
        conn.write_all(&address_bytes).await?;

        log::trace!("read server response");
        let mut resp = vec![0u8; 4 + address_bytes.len()];
        conn.read_exact(&mut resp).await?;

        Ok(())
    };
    timeout(dur, fut).await?
}
