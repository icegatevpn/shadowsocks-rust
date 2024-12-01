use crate::service::domain_connection::connect_domain_socket;
use async_channel::{unbounded, Receiver, RecvError, SendError, Sender};
use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use futures::SinkExt;
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use std::io::{Error, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::{collections::HashMap, sync::Arc};
use std::future::Future;
use std::str::Bytes;
use tokio::time::sleep;
use tokio::{
    net::UnixDatagram,
    sync::{mpsc, oneshot, Mutex},
    time::{timeout, Duration},
};
use tokio::time::error::Elapsed;
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

// Structure to track pending requests
struct PendingRequest {
    response_sender: oneshot::Sender<String>,
    command_id: String,
}

#[derive(Clone)]
struct AppState {
    command_tx: Sender<(String, String)>, // (command, command_id)
    pending_requests: Arc<Mutex<HashMap<String, oneshot::Sender<String>>>>,
}

async fn socket_listener(
    socket_path: String,
    mut command_rx: Receiver<(String, String)>,
    pending_requests: Arc<Mutex<HashMap<String, oneshot::Sender<String>>>>,
) {
    let mut from_socket: Option<Receiver<String>> = None;
    let mut socket_sender: Option<Sender<String>> = None;

    while from_socket.is_none() {
        let (to_domain, domain_receiver) = unbounded();
        match connect_domain_socket(domain_receiver, &socket_path) {
            Ok(ds) => {
                from_socket = Some(ds);
                socket_sender = Some(to_domain)
            }
            Err(e) => {
                warn!("Nope: {:?} sleep....", e);
                tokio::time::sleep(Duration::from_millis(1000)).await;
            }
        }
    }
    debug!("Domain connection established for {:?}", socket_path);
    let socket_receiver = from_socket.unwrap();
    let sender = socket_sender.unwrap();

    tokio::spawn({
        let pending_requests = pending_requests.clone();
        async move {
            while let Ok((command, command_id)) = command_rx.recv().await {
                // if let Err(e) = sender.send(format!("{},{}", command_id, command)).await {
                if let Err(e) = sender.send(command).await {
                    error!("Failed to send command to socket: {}", e);
                    // Clean up the pending request if send fails
                    let mut requests = pending_requests.lock().await;
                    if let Some(response_sender) = requests.remove(&command_id) {
                        let _ = response_sender.send("Failed to send command to socket".to_string());
                    }
                }
            }
        }
    });

    // Spawn response handler
    tokio::spawn(async move {
        while let Ok(response) = socket_receiver.recv().await {
            let command_id = "ONE".to_string();
            let response_data = response;

            let mut requests = pending_requests.lock().await;
            if let Some(sender) = requests.remove(&command_id) {
                if sender.send(response_data).is_err() {
                    error!("Failed to send response to request handler");
                }
            }
        }
    });
}

async fn handle_command(State(state): State<AppState>, Json(payload): Json<ManagerCommand>) -> impl IntoResponse {
    let (response_tx, response_rx) = oneshot::channel();
    let command_id = "ONE".to_string(); //Uuid::new_v4().to_string();

    // Store the response channel
    {
        let mut pending_requests = state.pending_requests.lock().await;
        pending_requests.insert(command_id.clone(), response_tx);
    }

    match state.command_tx.send((payload.command, command_id.clone())).await {
        Ok(_) => match timeout(Duration::from_secs(COMMAND_TIMEOUT_SECS), response_rx).await {
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
        },
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

async fn send_command(
    state: &AppState,
    command: String,
    timeout_secs: u64,
) -> (StatusCode, String) {
    let (response_tx, response_rx) = oneshot::channel();
    let command_id = "ONE".to_string();// = Uuid::new_v4().to_string();

    // Store the response channel
    {
        let mut pending_requests = state.pending_requests.lock().await;
        pending_requests.insert(command_id.clone(), response_tx);
    }

    let result = state.command_tx.send((command, command_id.clone())).await;

    // Clean up callback on completion
    let cleanup = || async {
        let mut pending_requests = state.pending_requests.lock().await;
        pending_requests.remove(&command_id);
    };

    match result {
        Ok(_) => match timeout(Duration::from_secs(timeout_secs), response_rx).await {
            Ok(Ok(response)) => {
                cleanup().await;
                (StatusCode::OK, response)
            }
            _ => {
                cleanup().await;
                (StatusCode::INTERNAL_SERVER_ERROR, "Command failed or timed out".to_string())
            }
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to send command".to_string(),
        ),
    }
}
async fn cmd_custom(State(state): State<AppState>, command: String) -> impl IntoResponse {
    send_command(&state, command, COMMAND_TIMEOUT_SECS).await
}

// Macro to generate command handler functions
macro_rules! make_command_handler {
    ($name:ident, $cmd:expr) => {
        async fn $name(State(state): State<AppState>) -> impl IntoResponse {
            send_command(&state, $cmd.to_string(), COMMAND_TIMEOUT_SECS).await
        }
    };
    // Variant with custom timeout
    ($name:ident, $cmd:expr, $timeout:expr) => {
        async fn $name(State(state): State<AppState>) -> impl IntoResponse {
            send_command(&state, $cmd.to_string(), $timeout).await
        }
    };
}

make_command_handler!(cmd_list, "list");
make_command_handler!(cmd_ping, "ping");

pub async fn run_web_service(manager_socket_path: String, host_name: String) {
    // Create channel for commands
    let (command_tx, command_rx) = unbounded();
    let pending_requests = Arc::new(Mutex::new(HashMap::new()));

    tokio::spawn(socket_listener(
        manager_socket_path,
        command_rx,
        pending_requests.clone(),
    ));

    // Create shared state
    let state = AppState {
        command_tx,
        pending_requests,
    };

    // Create router
    let app = Router::new()
        .route("/health", get(health_check))
        .route("/command", post(handle_command))
        .route("/list", get(cmd_list))
        .route("/ping", get(cmd_ping))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(host_name.clone())
        .await
        .expect("Failed to bind to port 8080");

    info!("Web service listening on http://{}",host_name);

    axum::serve(listener, app).await.expect("Web service failed");
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
