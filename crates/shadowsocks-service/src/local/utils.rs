//! Shadowsocks Local Utilities

use std::{io, net::SocketAddr, time::Duration};

use log::{debug, error, info, trace, warn};
use shadowsocks::{
    config::ServerConfig,
    relay::{socks5::Address, tcprelay::utils::copy_encrypted_bidirectional},
};
use tokio::{
    io::{copy_bidirectional, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time,
};

use crate::local::net::AutoProxyIo;
use crate::local::net::tcp::auto_proxy_stream::DebugStatus;
use crate::me_debug;

pub(crate) async fn establish_tcp_tunnel<P, S>(
    svr_cfg: &ServerConfig,
    plain: &mut P,
    shadow: &mut S,
    peer_addr: SocketAddr,
    target_addr: &Address,
) -> io::Result<()>
where
    P: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + AutoProxyIo + Unpin + DebugStatus,
{
    if shadow.is_proxied() {
        info!(
            "established tcp tunnel {} <-> {} through sever {} (outbound: {})",
            peer_addr,
            target_addr,
            svr_cfg.tcp_external_addr(),
            svr_cfg.addr()
        );
    } else {
        return establish_tcp_tunnel_bypassed(plain, shadow, peer_addr, target_addr).await;
    }



    // https://github.com/shadowsocks/shadowsocks-rust/issues/232
    //
    // Protocols like FTP, clients will wait for servers to send Welcome Message without sending anything.
    //
    // Wait at most 500ms, and then sends handshake packet to remote servers.
    {

        // Check if socket is still connected
        if let Err(e) = verify_connection(shadow, "Proxied shadow").await {
            error!("Proxied shadow socket is not connected after establishment: {}", e);
            return Err(e);
        }

        let mut buffer = [0u8; 8192];

        // match time::timeout(Duration::from_millis(500), plain.read(&mut buffer)).await {
        match time::timeout(Duration::from_millis(500), plain.read(&mut buffer)).await {
            Ok(Ok(0)) => {
                // EOF. Just terminate right here.
                return Ok(());
            }
            Ok(Ok(n)) => {

                // Send the first packet.
                // shadow.write_all(&buffer[..n]).await?;
                // Send the first packet
                debug!("Received {} bytes from client, forwarding to server", n);

                // Verify again before write
                if let Err(e) = verify_connection(shadow, "Proxied shadow (before write)").await {

                    error!("Proxied shadow socket disconnected before first write: {}", e);
                    return Err(e);
                }

                shadow.write_all(&buffer[..n]).await?;
                debug!("Successfully wrote initial data to server");
            }
            Ok(Err(err)) => {
                error!("Failed to read from client stream: {}", err);
                return Err(err);
            }
            Err(_) => {
                // let _ = shadow.write(&[]).await?;
                //
                // me_debug!(
                //     "tcp tunnel {} -> {} (proxied) sent handshake without data",
                //     peer_addr,
                //     target_addr
                // );
                // Timeout. Send handshake to server.
                debug!("Timeout waiting for client data, sending empty handshake");

                // Verify again before handshake
                if let Err(e) = verify_connection(shadow, "Proxied shadow (before handshake)").await {
                    error!("Proxied shadow socket disconnected before handshake: {}", e);
                    return Err(e);
                }

                let _ = shadow.write(&[]).await?;
                debug!("Successfully sent empty handshake");

                me_debug!(
                    "tcp tunnel {} -> {} (proxied) sent handshake without data",
                    peer_addr,
                    target_addr
                );
            }
        }
    }

    match copy_encrypted_bidirectional(svr_cfg.method(), shadow, plain).await {
        Ok((wn, rn)) => {
            me_debug!( // trace!
                "tcp tunnel {} <-> {} (proxied) closed, L2R {} bytes, R2L {} bytes",
                peer_addr,
                target_addr,
                rn,
                wn
            );
        }
        Err(err) => {
            me_debug!( // trace!
                "tcp tunnel {} <-> {} (proxied) closed with error: {}",
                peer_addr,
                target_addr,
                err
            );
        }
    }

    Ok(())
}

// pub(crate) async fn establish_tcp_tunnel_bypassed<P, S>(
//     plain: &mut P,
//     shadow: &mut S,
//     peer_addr: SocketAddr,
//     target_addr: &Address,
// ) -> io::Result<()>
// where
//     P: AsyncRead + AsyncWrite + Unpin,
//     S: AsyncRead + AsyncWrite + Unpin,
// {
//     debug!("established tcp tunnel {} <-> {} bypassed", peer_addr, target_addr);
//
//     match copy_bidirectional(plain, shadow).await {
//         Ok((rn, wn)) => {
//             trace!(
//                 "tcp tunnel {} <-> {} (bypassed) closed, L2R {} bytes, R2L {} bytes",
//                 peer_addr,
//                 target_addr,
//                 rn,
//                 wn
//             );
//         }
//         Err(err) => {
//             warn!(
//                 "tcp tunnel {} <-> {} (bypassed) closed with error: {}",
//                 peer_addr,
//                 target_addr,
//                 err
//             );
//         }
//     }
//
//     Ok(())
// }

pub(crate) async fn establish_tcp_tunnel_bypassed<P, S>(
    plain: &mut P,
    shadow: &mut S,
    peer_addr: SocketAddr,
    target_addr: &Address,
) -> io::Result<()>
where
    P: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    debug!("establishing tcp tunnel {} <-> {} bypassed", peer_addr, target_addr);

    // Verify shadow socket connectivity by attempting a zero-byte write
    // This can detect disconnected sockets without affecting the data stream
    match shadow.write(&[]).await {
        Ok(_) => {
            info!("shadow socket appears connected for {} <-> {}", peer_addr, target_addr);
        }
        Err(e) => {
            error!(
                "shadow socket verification failed for {} <-> {}: {}",
                peer_addr, target_addr, e
            );
            return Err(e);
        }
    }

    // Also check if we can perform a zero-byte write on the plain socket
    match plain.write(&[]).await {
        Ok(_) => {
            info!("plain socket appears connected for {} <-> {}", peer_addr, target_addr);
        }
        Err(e) => {
            error!(
                "plain socket verification failed for {} <-> {}: {}",
                peer_addr, target_addr, e
            );
            return Err(e);
        }
    }

    // Proceed with bidirectional copy if socket checks passed
    debug!("established tcp tunnel {} <-> {} bypassed, proceeding with data transfer", peer_addr, target_addr);

    match copy_bidirectional(plain, shadow).await {
        Ok((rn, wn)) => {
            trace!(
                "tcp tunnel {} <-> {} (bypassed) closed, L2R {} bytes, R2L {} bytes",
                peer_addr,
                target_addr,
                rn,
                wn
            );
        }
        Err(err) => {
            error!(
                "tcp tunnel {} <-> {} (bypassed) closed with error: {}",
                peer_addr,
                target_addr,
                err
            );
        }
    }

    Ok(())
}


pub async fn verify_connection<S>(socket: &mut S, description: &str) -> io::Result<()>
where
    S: AsyncWrite + Unpin + DebugStatus,
{
    debug!(" <><><><><> {}", socket.debug());
    // Try a zero-byte write to check if the socket is connected
    // This doesn't send any actual data but will fail if the socket is disconnected
    match socket.write(&[]).await {
        Ok(_) => {
            debug!("++++++++ {} socket verified as connected", description);
            Ok(())
        }
        Err(e) => {
            error!("-------- {} socket verification failed: {}", description, e);
            Err(e)
        }
    }
}

#[cfg(unix)]
fn get_socket_fd<T: std::os::unix::io::AsRawFd>(socket: &T) -> Option<i32> {
    use std::os::unix::io::AsRawFd;
    Some(socket.as_raw_fd())
}

#[cfg(unix)]
fn is_socket_connected(fd: i32) -> bool {
    unsafe {
        let mut addr: libc::sockaddr_storage = std::mem::zeroed();
        let mut addr_len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;

        if libc::getpeername(fd, &mut addr as *mut _ as *mut libc::sockaddr, &mut addr_len) < 0 {
            let err = std::io::Error::last_os_error();
            error!("Socket fd {} is not connected: {}", fd, err);
            false
        } else {
            true
        }
    }
}
