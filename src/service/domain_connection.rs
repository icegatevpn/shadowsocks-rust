
use async_channel::Receiver;
use cfg_if::cfg_if;
use log::{debug, };
use tracing::{error};
use uuid::Uuid;
use shadowsocks_service::shadowsocks::manager::domain_command::DomainCommand;
cfg_if! {
    if #[cfg(unix)] {
        use tokio::net::UnixDatagram;
        use std::path::{Path};
    } else {
        use tokio::net::UdpSocket;
        use std::net::SocketAddr;
        use std::io;
        use log::warn;
    }
}

pub async fn connect_domain_socket(
    receiver: Receiver<DomainCommand>,
    server_path: &str,
) -> std::io::Result<Receiver<DomainCommand>> {
    #[cfg(unix)]
    let client_path = format!("/tmp/ss-client-{}", Uuid::new_v4());

    #[cfg(unix)]
    let socket = {
        // Unix implementation using UnixDatagram

        let client_pathbuf = Path::new(&client_path).to_path_buf();

        // Remove the socket file if it exists
        if client_pathbuf.exists() {
            std::fs::remove_file(&client_pathbuf)?;
        }

        // Bind to our named path
        let socket = UnixDatagram::bind(&client_path)?;

        // Connect to the server
        socket.connect(server_path)?;
        socket
    };
    #[cfg(not(unix))]
    let socket = {
        warn!("Unix domain sockets not supported on this platform. \
        Using UDP socket instead. this is Experimental.");

        // Create a UDP socket bound to localhost
        let socket = UdpSocket::bind("127.0.0.1:0").await?;

        // Parse server address (assuming format like "127.0.0.1:PORT")
        let server_addr: SocketAddr = "127.0.0.1:8888".parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        socket.connect(server_addr).await?;
        socket
    };

    // Create a channel for responses
    let (response_tx, response_rx) = async_channel::unbounded();

    // Spawn a task to handle communication
    let mut buf = vec![0; 4096];
    tokio::spawn(async move {
        loop {
            // Handle incoming commands from the receiver
            match receiver.recv().await {
                Ok(command) => {
                    debug!("<<<< Received command: {:?}", command);
                    if let Err(e) = socket.send(command.to_bytes()
                        .expect("failed to parse command")
                        .as_slice()).await {
                        eprintln!("Failed to send command: {}", e);
                        continue;
                    }
                    debug!("<<<< Sent command ....");
                    // Wait for response
                    match socket.recv(&mut buf).await {
                        Ok(n) => {
                            if let Ok(response) = String::from_utf8(buf[..n].to_vec()) {
                                let dm = DomainCommand::from_string(&response)
                                    .expect(&format!("Failed to parse DomainCommand: {}", response));
                                debug!("<<< Received response: {}", dm);
                                if response_tx.send(dm).await.is_err() {
                                    break;
                                }
                            }
                        }
                        Err(e) => eprintln!("Failed to receive response: {}", e),
                    }
                    debug!("<<<< Got response!!");
                }
                Err(e) => {
                    error!("<<<< Failed to receive command: {}", e);
                    break
                },
            }
        }

        // Clean up the socket file when done
        #[cfg(unix)]
        let _ = std::fs::remove_file(&client_path);
    });

    Ok(response_rx)
}
