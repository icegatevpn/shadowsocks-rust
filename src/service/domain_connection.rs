use std::path::{PathBuf};
use tokio::net::UnixDatagram;
use async_channel::Receiver;
use log::debug;
use uuid::Uuid;

pub fn connect_domain_socket(
    receiver: Receiver<String>,
    server_path: &str,
) -> std::io::Result<Receiver<String>> {
    // Create a unique path for our client socket
    let client_path = format!("/tmp/ss-client-{}", Uuid::new_v4());
    let client_pathbuf = PathBuf::from(&client_path);

    // Remove the socket file if it exists
    if client_pathbuf.exists() {
        std::fs::remove_file(&client_pathbuf)?;
    }

    // Bind to our named path
    let socket = UnixDatagram::bind(&client_path)?;

    // Connect to the server
    socket.connect(server_path)?;

    // Create a channel for responses
    let (response_tx, response_rx) = async_channel::unbounded();

    // Spawn a task to handle communication
    let mut buf = vec![0; 4096];
    tokio::spawn(async move {
        loop {
            // Handle incoming commands from the receiver
            match receiver.recv().await {
                Ok(command) => {
                    if let Err(e) = socket.send(command.as_bytes()).await {
                        eprintln!("Failed to send command: {}", e);
                        continue;
                    }

                    // Wait for response
                    match socket.recv(&mut buf).await {
                        Ok(n) => {
                            if let Ok(response) = String::from_utf8(buf[..n].to_vec()) {
                                debug!("Received response: {}", response);
                                if response_tx.send(response).await.is_err() {
                                    break;
                                }
                            }
                        }
                        Err(e) => eprintln!("Failed to receive response: {}", e),
                    }
                }
                Err(_) => break,
            }
        }

        // Clean up the socket file when done
        let _ = std::fs::remove_file(&client_path);
    });

    Ok(response_rx)
}
