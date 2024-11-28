use axum::{
    extract::State,
    routing::{get, post},
    Router,
    Json,
    response::IntoResponse,
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::Arc,
};
use log::{debug, warn};
use tokio::{
    net::UnixDatagram,
    sync::{Mutex, oneshot, mpsc},
    time::{timeout, Duration},
};
use tokio::time::sleep;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
struct ManagerCommand {
    command: String,
}

#[derive(Debug, Serialize)]
struct ApiResponse {
    success: bool,
    message: String,
    data: Option<String>,
}

const MAX_RESPONSE_SIZE: usize = 4096;
const COMMAND_TIMEOUT_SECS: u64 = 5;

const MAX_RETRIES: u8 = 3;
const RETRY_DELAY_MS: u64 = 500;

#[derive(Clone)]
struct AppState {
    command_tx: mpsc::Sender<(String, oneshot::Sender<String>)>,
}

async fn connect_with_retry(socket_path: &str) -> Result<UnixDatagram, std::io::Error> {
    let mut last_error = None;

    for attempt in 1..=MAX_RETRIES {
        match UnixDatagram::unbound() {
            Ok(socket) => {
                match socket.connect(socket_path) {
                    Ok(()) => {
                        println!("Successfully connected to socket on attempt {}", attempt);
                        return Ok(socket);
                    }
                    Err(e) => {
                        println!("Failed to connect on attempt {}: {}", attempt, e);
                        last_error = Some(e);
                    }
                }
            }
            Err(e) => {
                println!("Failed to create socket on attempt {}: {}", attempt, e);
                last_error = Some(e);
            }
        }

        if attempt < MAX_RETRIES {
            println!("Waiting {}ms before retry...", RETRY_DELAY_MS);
            sleep(Duration::from_millis(RETRY_DELAY_MS)).await;
        }
    }

    Err(last_error.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            "Failed to connect to socket after all retries",
        )
    }))
}

async fn socket_listener(
    socket_path: String,
    mut command_rx: mpsc::Receiver<(String, oneshot::Sender<String>)>,
) {

    // wait a second for the socket to spin up before we try to connect
    sleep(Duration::from_millis(1000)).await;
    // Create response channels map - stores the oneshot senders
    let response_channels = Arc::new(Mutex::new(
        HashMap::<String, oneshot::Sender<String>>::new()
    ));
    let response_channels_clone = response_channels.clone();

    // let (recv_socket, send_socket) = UnixDatagram::pair().expect("Failed to create socket pair");

    // Create socket for receiving
    let recv_socket = UnixDatagram::unbound().expect("Failed to create receive socket");
    recv_socket.connect(&socket_path).expect("Failed to connect receive socket");
    // let recv_socket = connect_with_retry(&socket_path).expect("Failed to connect receive socket");

    // Create socket for sending
    let send_socket = UnixDatagram::unbound().expect("Failed to create send socket");
    send_socket.connect(&socket_path).expect("Failed to connect send socket");
    // let send_socket = connect_with_retry(&socket_path).expect("Failed to connect send socket");



    // Spawn receiver task
    tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_RESPONSE_SIZE];
        loop {
            warn!("LISTENING to {}.......", socket_path);
            match recv_socket.recv(&mut buf).await {
                Ok(n) => {
                    warn!("Received {} bytes from {}", n, socket_path);
                    if let Ok(response) = String::from_utf8(buf[..n].to_vec()) {
                        println!("Received response: {}", response);
                        // Parse response to extract command ID
                        // if let Some((id, message)) = response.split_once('\n') {
                            let id = "ONE".to_string();
                            let mut channels = response_channels_clone.lock().await;
                            if let Some(sender) = channels.remove(id.trim()) {
                                // Now correctly using the oneshot sender
                                if let Err(e) = sender.send(response.trim().to_string()) {
                                    eprintln!("Failed to send response through channel: {}", e);
                                }
                            }
                        // }
                    }
                }
                Err(e) => {
                    eprintln!("Error receiving from socket: {}", e);
                }
            }
        }
    });

    // Handle incoming commands
    while let Some((command, response_tx)) = command_rx.recv().await {
        let id = "ONE".to_string();//Uuid::new_v4().to_string();
        // let command_with_id = format!("{}\n{}", id, command);

        {
            let mut channels = response_channels.lock().await;
            channels.insert(id.clone(), response_tx);

            if let Err(e) = send_socket.send(command.as_bytes()).await {
                eprintln!("Failed to send command: {}", e);
                channels.remove(&id);
            }
        }
    }
}

async fn handle_command(
    State(state): State<AppState>,
    Json(payload): Json<ManagerCommand>,
) -> impl IntoResponse {
    let (tx, rx) = oneshot::channel();

    let closed = state.command_tx.is_closed();
    debug!("handle_command: {:?}, is closed: {:?}", payload.command, closed);

    match state.command_tx.send((payload.command, tx)).await {
        Ok(_) => {
            match timeout(Duration::from_secs(COMMAND_TIMEOUT_SECS), rx).await {
                Ok(Ok(response)) => (
                    StatusCode::OK,
                    Json(ApiResponse {
                        success: true,
                        message: "Command executed successfully".to_string(),
                        data: Some(response),
                    }),
                ),
                Ok(Err(_)) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ApiResponse {
                        success: false,
                        message: "Response channel closed".to_string(),
                        data: None,
                    }),
                ),
                Err(_) => (
                    StatusCode::GATEWAY_TIMEOUT,
                    Json(ApiResponse {
                        success: false,
                        message: format!("Timeout waiting for response after {} seconds", COMMAND_TIMEOUT_SECS),
                        data: None,
                    }),
                ),
            }
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                success: false,
                message: "Failed to send command to socket listener".to_string(),
                data: None,
            }),
        ),
    }
}

pub async fn run_web_service(manager_socket_path: String) {
    // Create channel for commands
    let (command_tx, command_rx) = mpsc::channel(32);

    // Spawn the socket listener
    tokio::spawn(socket_listener(manager_socket_path, command_rx));

    // Create shared state
    let state = AppState {
        command_tx,
    };

    // Create router
    let app = Router::new()
        .route("/health", get(health_check))
        .route("/command", post(handle_command))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080")
        .await
        .expect("Failed to bind to port 8080");

    println!("Web service listening on http://127.0.0.1:8080");

    axum::serve(listener, app)
        .await
        .expect("Web service failed");
}

async fn health_check() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(ApiResponse {
            success: true,
            message: "Service is healthy".to_string(),
            data: None,
        }),
    )
}