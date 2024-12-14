use crate::service::domain_connection::connect_domain_socket;
use crate::service::key_generator::generate_key;
use async_channel::{unbounded, Receiver, Sender};
use axum::extract::{Path as AxPath, Path};
use axum::routing::{delete, put};
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use shadowsocks::manager::protocol::AddUser;
use shadowsocks_service::mysql_db::Database;
use shadowsocks_service::shadowsocks;
use shadowsocks_service::url_generator::generate_ssurl;
use std::{collections::HashMap, fmt, sync::Arc};
use tokio::{
    sync::{oneshot, Mutex},
    time::{timeout, Duration},
};

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

#[derive(Debug, Deserialize)]
struct RenameRequest {
    name: String,
}

// todo: maybe future usage
// #[derive(Debug, Serialize)]
// struct Metrics {
//     bytes_transferred_by_user_id: HashMap<String, i64>,
// }

const COMMAND_TIMEOUT_SECS: u64 = 5;

#[derive(Debug, Deserialize)]
struct GenerateKeyRequest {
    // method: String,
    #[serde(default)]
    method: Option<String>,
}

#[derive(Clone)]
struct AppState {
    command_tx: Sender<(String, String)>,
    pending_requests: Arc<Mutex<HashMap<String, oneshot::Sender<String>>>>,
    db: Arc<Mutex<Database>>,
}

async fn socket_listener(
    socket_path: String,
    command_rx: Receiver<(String, String)>,
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
    // This is just a placeholder for a possible uuid to send to the socket and
    // monitor for the return uuid. That would require additional work on the socket
    let command_id = "ONE".to_string();

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

async fn send_command(state: &AppState, command: String, timeout_secs: u64) -> (StatusCode, String) {
    let (response_tx, response_rx) = oneshot::channel();
    let command_id = "ONE".to_string(); // = Uuid::new_v4().to_string();

    // Store the response channel
    {
        let mut pending_requests = state.pending_requests.lock().await;
        pending_requests.insert(command_id.clone(), response_tx);
    }
    info!("Sending command to socket {}", command);
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
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Command failed or timed out".to_string(),
                )
            }
        },
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Failed to send command".to_string()),
    }
}
#[allow(dead_code)]
async fn cmd_custom(State(state): State<AppState>, command: String) -> impl IntoResponse {
    send_command(&state, command, COMMAND_TIMEOUT_SECS).await
}

/* POST Body content with json like so:
   {"server_port":8387,"users":[
       {"name":"user666","password":"a5b/0RGhOFvLKONeELya+nstg0S+O+Jn2T5x59AbFrM="}]
   }
*/
async fn add_user(State(state): State<AppState>, command: String) -> impl IntoResponse {
    let config: AddUser = serde_json::from_str(&command).expect("json parse failed");
    let new_command = format!("addu:{}", config);

    debug!("Command: {:?}", new_command);
    send_command(&state, new_command, COMMAND_TIMEOUT_SECS).await
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

pub async fn run_web_service(
    manager_socket_path: String,
    host_name: String,
    url_key: String,
    db: Arc<Mutex<Database>>,
) {
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
        db,
    };

    async fn get_access_key(State(state): State<AppState>, Path(id): Path<String>) -> impl IntoResponse {
        let db = state.db.lock().await;
        let user_and_url = db
            .list_users_with_url(true, Some(id.parse().unwrap()))
            .map_err(|e| ApiError::DatabaseError(e.to_string()))
            .expect("Failed to list users");

        let (user, (method, url)) = user_and_url.first().unwrap();

        (
            StatusCode::OK,
            Json(AccessKey {
                id: Some(user.id.unwrap_or(0).to_string()),
                name: Some(user.name.clone()),
                password: Some(user.key.clone()),
                port: Some(user.server_port),
                method: Some(method.clone()),
                access_url: url.clone(),
            }),
        )
    }

    async fn remove_access_key(State(state): State<AppState>, Path(id): Path<String>) -> impl IntoResponse {
        let mut db = state.db.lock().await;
        let num_users = db.remove_user(id.parse().unwrap()).expect("Failed to remove user");
        (StatusCode::OK, num_users)
    }

    // todo: maybe future usage
    // async fn get_metrics(
    //     State(_): State<AppState>,
    // ) -> impl IntoResponse {
    //     // This would need to be implemented to track actual bytes transferred
    //     let metrics = Metrics {
    //         bytes_transferred_by_user_id: HashMap::new(),
    //     };
    //
    //     (StatusCode::OK, Json(metrics))
    // }

    async fn rename_access_key(
        State(state): State<AppState>,
        Path(id): Path<String>,
        Json(req): Json<RenameRequest>,
    ) -> impl IntoResponse {
        let db = state.db.lock().await;
        let num_removed = db
            .rename_user(id.parse().unwrap(), &req.name)
            .expect("Failed to rename key");
        (StatusCode::OK, format!("Renamed keys: {:?}", num_removed))
    }

    // Create router
    let app = Router::new()
        // .route(&format!({}"/health", url_key), get(health_check))
        .route(&format!("/{}/health", url_key), get(health_check))
        .route(&format!("/{}/command",url_key), post(handle_command))
        .route(&format!("/{}/list", url_key), get(cmd_list))
        .route(&format!("/{}/ping", url_key), get(cmd_ping))
        .route(&format!("/{}/add_user", url_key), post(add_user))
        .route(&format!("/{}/generate_key", url_key), post(generate_cipher_key_post))
        .route(&format!("/{}/generate_key", url_key), get(generate_cipher_key))
        .route(&format!("/{}/generate_key/:method", url_key), get(generate_cipher_key))
        .route(&format!("/{}/url/:user_id", url_key), get(generate_ssurl_handler))

        // Add new REST API endpoints
        .route(&format!("/{}/access-keys", url_key), get(list_access_keys))
        .route(&format!("/{}/access-keys", url_key), post(create_access_key))
        .route(&format!("/{}/access-keys/:id", url_key), get(get_access_key))
        .route(&format!("/{}/access-keys/:id", url_key), delete(remove_access_key))
        .route(&format!("/{}/access-keys/:id/name", url_key), put(rename_access_key))
        // .route("/metrics/transfer", get(get_metrics))
        .with_state(state);

    // let addr = format!("{}:{}", host_name, url_key);
    let listener = tokio::net::TcpListener::bind(host_name.clone())
        .await
        .expect(&format!("Failed to bind to {}", host_name));

    info!("Web service listening on http://{}/{}", host_name, url_key);

    axum::serve(listener, app).await.expect("Web service failed");
}
// Add new REST API types
// Error handling
#[derive(Debug)]
#[allow(dead_code)]
pub enum ApiError {
    // Socket/connection related errors
    SocketConnectionFailed(std::io::Error),
    SocketSendFailed(String),
    SocketReceiveFailed(String),
    SocketTimeout,

    // Command related errors
    CommandFailed(String),
    InvalidCommand(String),

    // Database related errors
    DatabaseError(String),

    // Request/response related errors
    InvalidRequest(String),
    ResponseParseError(String),

    // Authentication/authorization errors
    Unauthorized(String),
    Forbidden(String),

    // General errors
    InternalError(String),
    NotFound(String),
}
#[derive(Serialize)]
struct ErrorResponse {
    success: bool,
    message: String,
    error_code: String,
}
impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApiError::SocketConnectionFailed(err) => write!(f, "Socket connection failed: {}", err),
            ApiError::SocketSendFailed(msg) => write!(f, "Failed to send to socket: {}", msg),
            ApiError::SocketReceiveFailed(msg) => write!(f, "Failed to receive from socket: {}", msg),
            ApiError::SocketTimeout => write!(f, "Socket operation timed out"),
            ApiError::CommandFailed(msg) => write!(f, "Command execution failed: {}", msg),
            ApiError::InvalidCommand(msg) => write!(f, "Invalid command: {}", msg),
            ApiError::DatabaseError(msg) => write!(f, "Database error: {}", msg),
            ApiError::InvalidRequest(msg) => write!(f, "Invalid request: {}", msg),
            ApiError::ResponseParseError(msg) => write!(f, "Failed to parse response: {}", msg),
            ApiError::Unauthorized(msg) => write!(f, "Unauthorized: {}", msg),
            ApiError::Forbidden(msg) => write!(f, "Forbidden: {}", msg),
            ApiError::InternalError(msg) => write!(f, "Internal server error: {}", msg),
            ApiError::NotFound(msg) => write!(f, "Not found: {}", msg),
        }
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status_code, error_code) = match &self {
            ApiError::SocketConnectionFailed(_) => (StatusCode::SERVICE_UNAVAILABLE, "SOCKET_CONNECTION_FAILED"),
            ApiError::SocketSendFailed(_) => (StatusCode::INTERNAL_SERVER_ERROR, "SOCKET_SEND_FAILED"),
            ApiError::SocketReceiveFailed(_) => (StatusCode::INTERNAL_SERVER_ERROR, "SOCKET_RECEIVE_FAILED"),
            ApiError::SocketTimeout => (StatusCode::GATEWAY_TIMEOUT, "SOCKET_TIMEOUT"),
            ApiError::CommandFailed(_) => (StatusCode::BAD_REQUEST, "COMMAND_FAILED"),
            ApiError::InvalidCommand(_) => (StatusCode::BAD_REQUEST, "INVALID_COMMAND"),
            ApiError::DatabaseError(_) => (StatusCode::INTERNAL_SERVER_ERROR, "DATABASE_ERROR"),
            ApiError::InvalidRequest(_) => (StatusCode::BAD_REQUEST, "INVALID_REQUEST"),
            ApiError::ResponseParseError(_) => (StatusCode::INTERNAL_SERVER_ERROR, "RESPONSE_PARSE_ERROR"),
            ApiError::Unauthorized(_) => (StatusCode::UNAUTHORIZED, "UNAUTHORIZED"),
            ApiError::Forbidden(_) => (StatusCode::FORBIDDEN, "FORBIDDEN"),
            ApiError::InternalError(_) => (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR"),
            ApiError::NotFound(_) => (StatusCode::NOT_FOUND, "NOT_FOUND"),
        };

        let error_response = ErrorResponse {
            success: false,
            message: self.to_string(),
            error_code: error_code.to_string(),
        };

        (status_code, Json(error_response)).into_response()
    }
}
// Helper trait for converting other error types to ApiError
pub trait IntoApiError {
    #[allow(dead_code)]
    fn into_api_error(self) -> ApiError;
}
// Implementation for std::io::Error
impl IntoApiError for std::io::Error {
    fn into_api_error(self) -> ApiError {
        ApiError::SocketConnectionFailed(self)
    }
}
// Implementation for String
impl IntoApiError for String {
    fn into_api_error(self) -> ApiError {
        ApiError::InternalError(self)
    }
}
// Implementation for &str
impl IntoApiError for &str {
    fn into_api_error(self) -> ApiError {
        ApiError::InternalError(self.to_string())
    }
}
#[derive(Debug, Serialize)]
struct AccessKeyListResponse {
    access_keys: Vec<AccessKey>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AccessKey {
    id: Option<String>,
    name: Option<String>,
    password: Option<String>,
    port: Option<u16>,
    method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    access_url: Option<String>,
}
// Add new REST API handlers

async fn create_access_key(State(state): State<AppState>) -> impl IntoResponse {
    let mut db = state.db.lock().await;

    // Generate a random key
    let password = generate_key(DEFAULT_CIPHER_METHOD).expect("Failed to generate key");
    let servers = db.list_servers(true).expect("Failed to list servers");
    let server = servers.first().expect("No server found");

    // Create new user
    let (user, url) = db
        .add_user(
            format!("user_{}", chrono::Utc::now().timestamp()),
            password.clone(),
            server.port,
            true,
        )
        .expect("failed to add New User");

    
    // todo add new user to server config!!  (socket command addu ?????)

    (
        StatusCode::OK,
        Json(AccessKey {
            id: Some(user.id.unwrap_or(0).to_string()),
            name: Some(user.name),
            password: Some(user.key),
            port: Some(user.server_port),
            method: Some(DEFAULT_CIPHER_METHOD.to_string()),
            access_url: url,
        }),
    )
}
async fn list_access_keys(State(state): State<AppState>) -> impl IntoResponse {
    //Result<Json<AccessKeyListResponse>> {
    debug!("List access keys....");
    let db = state.db.lock().await;

    let users = db
        .list_users_with_url(true, None)
        .map_err(|e| ApiError::DatabaseError(e.to_string()))
        .expect("Failed to list users");

    let access_keys = users
        .into_iter()
        .map(|(user, (method, url))| AccessKey {
            id: Some(user.id.unwrap_or(0).to_string()),
            name: Some(user.name),
            password: Some(user.key),
            port: Some(user.server_port),
            method: Some(method),
            access_url: url,
        })
        .collect();

    (StatusCode::OK, Json(AccessKeyListResponse { access_keys }))
}

async fn generate_ssurl_handler(State(state): State<AppState>, user_id: Option<AxPath<i64>>) -> impl IntoResponse {
    let user_id = user_id.map(|m| m.0).unwrap_or_else(|| -1);

    let db = state.db.lock().await;
    if let Ok(params) = db.build_ssurl_params_from_user_id(user_id, "oops") {
        match generate_ssurl(
            &params.server_address,
            params.server_port,
            &params.method,
            &params.password,
            params.name.as_deref(),
        ) {
            Ok(url) => (
                StatusCode::OK,
                Json(ApiResponse {
                    success: true,
                    message: "SS URL generated successfully".to_string(),
                    data: Some(url),
                }),
            ),
            Err(err) => (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    success: false,
                    message: err.to_string(),
                    data: None,
                }),
            ),
        }
    } else {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: "Missing UserID".to_string(),
                data: None,
            }),
        )
    }
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

const DEFAULT_CIPHER_METHOD: &str = "2022-blake3-aes-256-gcm";

async fn generate_cipher_key(method: Option<AxPath<String>>) -> impl IntoResponse {
    debug!("generate cipher_key method: {:?}", method);
    // Use the provided method or fall back to default
    let method = method.map(|m| m.0).unwrap_or_else(|| DEFAULT_CIPHER_METHOD.to_string());

    match generate_key(&method) {
        Ok(key) => (
            StatusCode::OK,
            Json(ApiResponse {
                success: true,
                message: format!("Key generated successfully using method: {}", method),
                data: Some(key),
            }),
        ),
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: err.to_string(),
                data: None,
            }),
        ),
    }
}
async fn generate_cipher_key_post(Json(payload): Json<GenerateKeyRequest>) -> impl IntoResponse {
    let method = payload.method.as_deref().unwrap_or(DEFAULT_CIPHER_METHOD);
    match generate_key(method) {
        Ok(key) => (
            StatusCode::OK,
            Json(ApiResponse {
                success: true,
                message: format!("Key generated successfully using method: {}", method),
                data: Some(key),
            }),
        ),
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: err.to_string(),
                data: None,
            }),
        ),
    }
}
