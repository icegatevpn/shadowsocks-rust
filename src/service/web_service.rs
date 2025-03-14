use crate::service::domain_connection::connect_domain_socket;
use crate::service::key_generator::generate_key;
use async_channel::{unbounded, Receiver, Sender};
use axum::extract::{Path as AxPath, Path, Request};
use axum::routing::{delete, put};
use axum::{extract::State, http::StatusCode, response::{IntoResponse, Response}, routing::{get, post}, Json, Router};
#[cfg(feature = "manager")]
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use shadowsocks::manager::domain_command::DomainCommand;
use shadowsocks::manager::protocol::AddUser;
#[cfg(feature = "database")]
use shadowsocks_service::mysql_db::Database;
use shadowsocks_service::shadowsocks;
use shadowsocks_service::url_generator::generate_ssurl;
use std::{collections::HashMap, fmt, sync::Arc};
use std::net::IpAddr;
use futures::TryFutureExt;
use tokio::{
    sync::{oneshot, Mutex},
    time::{timeout, Duration},
};
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

#[derive(Debug, Deserialize)]
struct RenameRequest {
    name: String,
}
#[derive(Debug, Deserialize)]
struct CreateAccessKeyRequest {
    name: Option<String>,
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
    command_tx: Sender<DomainCommand>,
    pending_requests: Arc<Mutex<HashMap<Uuid, oneshot::Sender<String>>>>,
    #[cfg(feature = "database")]
    db: Arc<Mutex<Database>>,
}

async fn socket_listener(
    socket_path: String,
    command_rx: Receiver<DomainCommand>,
    pending_requests: Arc<Mutex<HashMap<Uuid, oneshot::Sender<String>>>>,
) {
    let mut from_socket: Option<Receiver<DomainCommand>> = None;
    let mut socket_sender: Option<Sender<DomainCommand>> = None;

    while from_socket.is_none() {
        let (to_domain, domain_receiver) = unbounded();
        match connect_domain_socket(domain_receiver, &socket_path).await {
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
            while let Ok(command) = command_rx.recv().await {
                debug!("Sending command to socket: {:?}", &command.command);
                if let Err(e) = sender.send(command.clone()).await {
                    error!("Failed to send command to socket: {}", e);
                    // Clean up the pending request if send fails
                    let mut requests = pending_requests.lock().await;
                    if let Some(response_sender) = requests.remove(&command.id) {
                        let _ = response_sender.send("Failed to send command to socket".to_string());
                    }
                }
            }
        }
    });

    // Spawn response handler
    tokio::spawn(async move {
        while let Ok(response) = socket_receiver.recv().await {
            let mut requests = pending_requests.lock().await;
            if let Some(sender) = requests.remove(&response.id) {
                if sender.send(response.response.unwrap_or("Error".to_string())).is_err() {
                    error!("Failed to send response to request handler");
                }
            } else {
                error!("no pending requests to listen for!!!");
            }
        }
    });
}

async fn handle_command(State(state): State<AppState>, Json(payload): Json<ManagerCommand>) -> impl IntoResponse {
    let (response_tx, response_rx) = oneshot::channel();
    let command = DomainCommand::new(&payload.command);

    // Store the response channel
    {
        let mut pending_requests = state.pending_requests.lock().await;
        pending_requests.insert(command.id, response_tx);
    }

    match state.command_tx.send(command).await {
        Ok(_) => match timeout(Duration::from_secs(COMMAND_TIMEOUT_SECS), response_rx).await {
            Ok(Ok(_)) => (
                StatusCode::OK,
                json_api_message(true, "Command executed successfully".to_string()),
            ),
            Ok(Err(_)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                json_api_message(false, "Response channel closed".to_string()),
            ),
            Err(_) => (
                StatusCode::GATEWAY_TIMEOUT,
                json_api_message(
                    false,
                    format!("Timeout waiting for response after {} seconds", COMMAND_TIMEOUT_SECS),
                ),
            ),
        },
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            json_api_message(false, "Failed to send command to socket listener".to_string()),
        ),
    }
}

async fn send_command(state: &AppState, command: DomainCommand, timeout_secs: u64) -> (StatusCode, String) {
    let (response_tx, response_rx) = oneshot::channel();
    // Store the response channel
    {
        let mut pending_requests = state.pending_requests.lock().await;
        pending_requests.insert(command.id, response_tx);
    }
    info!("Sending command to socket {:?}", command);
    let result = state.command_tx.send(command.clone()).await;

    match result {
        Ok(_) => match timeout(Duration::from_secs(timeout_secs), response_rx).await {
            Ok(Ok(response)) => {
                debug!("Received response from socket {:?}", response);
                (StatusCode::OK, response)
            }
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Command failed or timed out".to_string(),
            ),
        },
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Failed to send command".to_string()),
    }
}
#[allow(dead_code)]
async fn cmd_custom(State(state): State<AppState>, command: String) -> impl IntoResponse {
    send_command(&state, DomainCommand::new(&command), COMMAND_TIMEOUT_SECS).await
}

/*
    POST Body content with json like so:
    {"server_port":8387,"users":[
        {"name":"user666","password":"a5b/0RGhOFvLKONeELya+nstg0S+O+Jn2T5x59AbFrM="}]
    }
*/
async fn add_user(State(state): State<AppState>, command: String) -> impl IntoResponse {
    let config: AddUser = serde_json::from_str(&command).expect("json parse failed");
    let new_command = DomainCommand::new(&format!("addu:{}", config));

    debug!("Command: {:?}", new_command);
    send_command(&state, new_command, COMMAND_TIMEOUT_SECS).await
}

#[cfg(feature = "database")]
async fn remove_user(State(state): State<AppState>, Path(key): Path<String>) -> impl IntoResponse {
    debug!("remove user:: Command: {:?}", key);
    let uid = key;
    let db = state.db.lock().await;
    let user = match db.get_user_by_id(uid.parse().unwrap()) {
        Ok(Some(user)) => user,
        Ok(None) => {
            return (StatusCode::NOT_FOUND, Json(format!("User with id {} not found", uid)));
        }
        Err(e) => {
            error!("Database error when fetching user: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(format!("Failed to fetch user: {}", e)),
            );
        }
    };
    let new_command = DomainCommand::new(&format!("removeu:{}", user.key));

    debug!("<<<<< Command: {:?}", new_command);
    let (status, response) = send_command(&state, new_command, COMMAND_TIMEOUT_SECS).await;

    (status, Json(response))
}
#[cfg(not(feature = "database"))]
async fn remove_user(State(state): State<AppState>, key: Option<AxPath<String>>) -> impl IntoResponse {
    warn!("remove_user, not implemented with no database");
}

// Macro to generate command handler functions
macro_rules! make_command_handler {
    ($name:ident, $cmd:expr) => {
        async fn $name(State(state): State<AppState>) -> impl IntoResponse {
            send_command(
                &state,
                DomainCommand::new(&$cmd.to_string()),
                COMMAND_TIMEOUT_SECS,
            )
            .await
        }
    };
    // Variant with custom timeout
    ($name:ident, $cmd:expr, $timeout:expr) => {
        async fn $name(State(state): State<AppState>) -> impl IntoResponse {
            send_command(&state, DomainCommand(&$cmd.to_string()), $timeout).await
        }
    };
}

make_command_handler!(cmd_list, &"list");
make_command_handler!(cmd_ping, &"ping");

fn json_api_message(success: bool, msg: String) -> Json<ApiResponse> {
    Json(ApiResponse {
        success,
        message: msg,
        data: None,
    })
}

pub async fn run_web_service(
    manager_socket_path: String,
    host_name: String,
    random_url_key: String,
    #[cfg(feature = "database")]
    db: Arc<Mutex<Database>>,
) {
    let url_key = random_url_key;

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
        #[cfg(feature = "database")]
        db,
    };

    #[cfg(feature = "database")]
    async fn get_access_key(State(state): State<AppState>, Path(id): Path<String>) -> impl IntoResponse {
        let db = state.db.lock().await;
        let user_and_url = db
            .list_users_with_url(true, Some(id.parse().unwrap()))
            .map_err(|e| ApiError::DatabaseError(e.to_string()))
            .expect("Failed to list users");

        let (user, (method, url, srv_key)) = user_and_url.first().unwrap();
        let passkey = if method.contains("2022") {
            Some(format!("{}:{}", srv_key, user.key).to_string())
        } else {
            Some(user.key.clone())
        };
        (
            StatusCode::OK,
            Json(AccessKey {
                id: Some(user.id.unwrap_or(0).to_string()),
                name: Some(user.name.clone()),
                password: passkey,
                port: Some(user.server_port),
                method: Some(method.clone()),
                access_url: url.clone(),
            }),
        )
    }
    #[cfg(not(feature = "database"))]
    async fn get_access_key(State(_): State<AppState>, Path(_): Path<String>) -> impl IntoResponse {
        warn!("get_access_key, not implemented with no database");
    }

    #[cfg(feature = "database")]
    async fn remove_access_key(State(state): State<AppState>, Path(id): Path<String>) -> impl IntoResponse {
        let mut db = state.db.lock().await;

        // First get the user details before removal
        let user = match db.get_user_by_id(id.parse().unwrap()) {
            Ok(Some(user)) => user,
            Ok(None) => {
                return (StatusCode::NOT_FOUND, Json(format!("User with id {} not found", id)));
            }
            Err(e) => {
                error!("Database error when fetching user: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(format!("Failed to fetch user: {}", e)),
                );
            }
        };

        // Format the remove user command for the socket
        let command = DomainCommand::new(&format!("removeu: {}\n", user.key));
        debug!("Sending remove user command to socket: {}", command);

        // Send command to socket and await response  // todo, this failed!!
        let (status, response) = send_command(&state, command, COMMAND_TIMEOUT_SECS).await;

        if status != StatusCode::OK {
            error!("Failed to remove user from ss-manager: {}", response);
            return (
                status,
                Json(format!("Failed to remove user from ss-manager: {}", response)),
            );
        }

        // If socket removal was successful, remove from database
        match db.remove_user(id.parse().unwrap()) {
            Ok(affected_rows) => {
                if affected_rows > 0 {
                    (
                        StatusCode::OK,
                        Json(format!("User successfully removed from both ss-manager and database")),
                    )
                } else {
                    (StatusCode::NOT_FOUND, Json(format!("User not found in database")))
                }
            }
            Err(e) => {
                error!("Failed to remove user from database: {}", e);
                // Note: At this point the user has been removed from ss-manager but not from the database
                // You might want to add some reconciliation logic here
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(format!("Failed to remove user from database: {}", e)),
                )
            }
        }
    }
    #[cfg(not(feature = "database"))]
    async fn remove_access_key(State(state): State<AppState>, Path(id): Path<String>) -> impl IntoResponse {
        warn!("remove_access_key, not implemented with no database");
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

    #[cfg(feature = "database")]
    async fn rename_access_key(
        State(state): State<AppState>,
        Path(id): Path<String>,
        Json(req): Json<RenameRequest>,
    ) -> impl IntoResponse {
        // todo updates config, not updating Database!!
        let db = state.db.lock().await;
        // First get the user's current details
        let user = match db.get_user_by_id(id.parse().unwrap()) {
            Ok(Some(user)) => user,
            Ok(None) => {
                return (
                    StatusCode::NOT_FOUND,
                    json_api_message(false, format!("User with id {} not found", id)),
                )
            }
            Err(e) => {
                error!("Database error when fetching user: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    json_api_message(false, format!("Failed to fetch user: {}", e)),
                );
            }
        };
        let old_name = user.name.clone();
        // Next remove the existing user from the service add db with the DomainCommand removeu
        let remove_command = DomainCommand::new(&format!("removeu:{}", user.key));
        let (status, response) = send_command(&state, remove_command, COMMAND_TIMEOUT_SECS).await;

        if status != StatusCode::OK {
            error!("Failed to remove user from ss-manager during rename: {}", response);
            return (
                status,
                json_api_message(
                    false,
                    format!("Failed to remove existing user configuration: {}", response),
                ),
            );
        }
        // Then Create AddUser struct for re-adding with new name
        let add_user = AddUser {
            server_port: user.server_port as u16,
            users: vec![shadowsocks::manager::protocol::ServerUserConfig {
                name: req.name.clone(), // Use the new name
                password: user.key.clone(),
            }],
        };
        // Add the user back with the new name, the addu domain command adds the user to the db
        // and the UserManager config
        let add_command = DomainCommand::new(&format!("addu:{}", add_user));
        let (status, response) = send_command(&state, add_command, COMMAND_TIMEOUT_SECS).await;
        if status != StatusCode::OK {
            error!("Failed to add user back to ss-manager during rename: {}", response);
            return (
                status,
                json_api_message(false, format!("Failed to add user with new name: {}", response)),
            );
        }

        // If service update succeeded, update the database
        match db.rename_user(id.parse().unwrap(), &req.name) {
            Ok(_) => (
                StatusCode::OK,
                json_api_message(
                    true,
                    format!("Renamed access key from {:?} to {:?}", old_name, req.name),
                ),
            ),
            Err(e) => {
                error!("Database error when renaming user: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    json_api_message(false, format!("Failed to update database: {}", e)),
                )
            }
        }
    }
    #[cfg(not(feature = "database"))]
    async fn rename_access_key(
        State(_): State<AppState>,
        Path(_): Path<String>,
        Json(_): Json<RenameRequest>,
    ) {
        warn!("rename_access_key, not implemented with no database");
    }

    // Create router
    let app = Router::new()
        // .route(&format!({}"/health", url_key), get(health_check))
        .route(&format!("/{}/health", url_key), get(health_check))
        .route(&format!("/{}/command",url_key), post(handle_command))
        .route(&format!("/{}/list", url_key), get(cmd_list))
        .route(&format!("/{}/ping", url_key), get(cmd_ping))
        .route(&format!("/{}/add_user", url_key), post(add_user))
        .route(&format!("/{}/remove_user/{{key}}", url_key), post(remove_user))
        .route(&format!("/{}/generate_key", url_key), post(generate_cipher_key_post))
        .route(&format!("/{}/generate_key", url_key), get(generate_cipher_key))
        .route(&format!("/{}/generate_key/{{method}}", url_key), get(generate_cipher_key))
        .route(&format!("/{}/url/{{user_id}}", url_key), get(generate_ssurl_handler))

        // Add new REST API endpoints
        .route(&format!("/{}/access-keys", url_key), get(list_access_keys))
        .route(&format!("/{}/access-keys", url_key), post(create_access_key))
        .route(&format!("/{}/access-keys/{{id}}", url_key), get(get_access_key))
        .route(&format!("/{}/access-keys/{{id}}", url_key), delete(remove_access_key))
        .route(&format!("/{}/access-keys/{{id}}/name", url_key), put(rename_access_key))
        // .route("/metrics/transfer", get(get_metrics))
        .with_state(state);

    // let listener = tokio::net::TcpListener::bind(host_name.clone())
    let default_ip = [0, 0, 0, 0];
    let ip = IpAddr::from(default_ip);
    let port = host_name.split(":").last().unwrap_or("8080");
    let bind_address = format!("{}:{}", ip, port);
    let listener = tokio::net::TcpListener::bind(&bind_address)
        .await
        .expect(&format!("Failed to bind to {}", &bind_address));

    let msg = format!("Web service listening on http://{}/{}", host_name, url_key);
    info!("{}", msg);

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
impl IntoApiError for std::io::Error {
    fn into_api_error(self) -> ApiError {
        ApiError::SocketConnectionFailed(self)
    }
}
impl IntoApiError for String {
    fn into_api_error(self) -> ApiError {
        ApiError::InternalError(self)
    }
}
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

#[cfg(feature = "database")]
async fn create_access_key(
    State(state): State<AppState>,
    payload: Json<CreateAccessKeyRequest>,
) -> impl IntoResponse {
    let mut db = state.db.lock().await;
    // Get name from payload or generate default
    let key_name = payload.name.clone().unwrap_or_else(|| format!("user_{}", chrono::Utc::now().timestamp()));
    // let key_name = match payload {
    //     Some(ref req) => &req.name.clone().unwrap_or_else(|| format!("user_{}", chrono::Utc::now().timestamp())),
    //     None => &format!("user_{}", chrono::Utc::now().timestamp()),
    // };
    // Generate a random key
    let password = generate_key(DEFAULT_CIPHER_METHOD).expect("Failed to generate key");
    let servers = db.list_servers(true).expect("Failed to list servers");
    let server = servers.first().expect("No server found");

    // Create new user in database
    let (user, url) = db
        .add_user(
            key_name.to_string(),
            password.clone(),
            server.port,
            true,
        )
        .expect("failed to add New User");

    // Create AddUser struct for socket communication
    let add_user = AddUser {
        server_port: server.port as u16,
        users: vec![shadowsocks::manager::protocol::ServerUserConfig {
            name: user.name.clone(),
            password: user.key.clone(),
        }],
    };

    // Convert AddUser to string command format
    let command = DomainCommand::new(&format!("addu:{}", add_user));
    debug!("Sending add user command to socket: {}", command);

    // Send command to socket and await response
    let (status, response) = send_command(&state, command, COMMAND_TIMEOUT_SECS).await;

    if status != StatusCode::OK {
        error!("Failed to add user to ss-manager: {}", response);
        // Rollback database changes if socket communication failed
        if let Err(err) = db.remove_user(user.id.unwrap()) {
            error!("Failed to rollback user creation: {}", err);
        }
        // Return error with same type structure as success case
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(AccessKey {
                id: None,
                name: None,
                password: None,
                port: None,
                method: None,
                access_url: None,
            }),
        );
    }

    let passkey = if server.method.contains("2022") {
        Some(format!("{}:{}", server.key, user.key).to_string())
    } else {
        Some(user.key.clone())
    };

    (
        StatusCode::OK,
        Json(AccessKey {
            id: Some(user.id.unwrap_or(0).to_string()),
            name: Some(user.name),
            password: passkey,
            port: Some(user.server_port),
            method: Some(DEFAULT_CIPHER_METHOD.to_string()),
            access_url: url,
        }),
    )
}

#[cfg(not(feature = "database"))]
async fn create_access_key(State(_): State<AppState>) -> impl IntoResponse {
    warn!("create_access_key, not implemented with no database");
}

#[cfg(feature = "database")]
async fn list_access_keys(State(state): State<AppState>) -> impl IntoResponse {
    let db = state.db.lock().await;

    let users = db
        .list_users_with_url(true, None)
        .map_err(|e| ApiError::DatabaseError(e.to_string()))
        .expect("Failed to list users");

    let access_keys = users
        .into_iter()
        .map(|(user, (method, url, srv_key))| {
            let passkey = if method.contains("2022") {
                Some(format!("{}:{}", srv_key, user.key).to_string())
            } else {
                Some(user.key)
            };
            AccessKey {
                id: Some(user.id.unwrap_or(0).to_string()),
                name: Some(user.name),
                password: passkey,
                port: Some(user.server_port),
                method: Some(method),
                access_url: url,
            }
        })
        .collect();

    (StatusCode::OK, Json(AccessKeyListResponse { access_keys }))
}
#[cfg(not(feature = "database"))]
async fn list_access_keys(State(_): State<AppState>) -> impl IntoResponse {
    warn!("list_access_keys, not implemented with no database");
}
//Path(user_id): Path<i64>
//
#[cfg(feature = "database")]
// async fn generate_ssurl_handler(State(state): State<AppState>, user_id: Option<AxPath<i64>>) -> impl IntoResponse {
async fn generate_ssurl_handler(State(state): State<AppState>, Path(user_id): Path<i64>) -> impl IntoResponse {
    let user_id = user_id;//user_id.map(|m| m.0).unwrap_or_else(|| -1);

    let db = state.db.lock().await;
    if let Ok(params) = db.build_ssurl_params_from_user_id(user_id, "oops") {
        match generate_ssurl(
            &params.server_address,
            params.server_port,
            &params.method,
            &params.password,
            params.name.as_deref(),
        ) {
            Ok(_) => (
                StatusCode::OK,
                json_api_message(true, "SS URL generated successfully".to_string()),
            ),
            Err(err) => (StatusCode::BAD_REQUEST, json_api_message(false, err.to_string())),
        }
    } else {
        (
            StatusCode::BAD_REQUEST,
            json_api_message(false, "Missing UserID".to_string()),
        )
    }
}
#[cfg(not(feature = "database"))]
async fn generate_ssurl_handler(State(state): State<AppState>, user_id: Option<AxPath<i64>>) -> impl IntoResponse {
    warn!("generate_ssurl_handler, not implemented with no database");
}
async fn health_check() -> impl IntoResponse {
    (StatusCode::OK, json_api_message(true, "Service is healthy".to_string()))
}

const DEFAULT_CIPHER_METHOD: &str = "2022-blake3-aes-256-gcm";
async fn generate_cipher_key(Path(method): Path<String>) -> impl IntoResponse {
    debug!("generate cipher_key method: {:?}", method);
    // Use the provided method or fall back to default

    match generate_key(&method) {
        Ok(_) => (
            StatusCode::OK,
            json_api_message(true, format!("Key generated successfully using method: {}", method)),
        ),
        Err(err) => (StatusCode::BAD_REQUEST, json_api_message(false, err.to_string())),
    }
}

async fn generate_cipher_key_post(Json(payload): Json<GenerateKeyRequest>) -> impl IntoResponse {
    let method = payload.method.as_deref().unwrap_or(DEFAULT_CIPHER_METHOD);
    match generate_key(method) {
        Ok(_) => (
            StatusCode::OK,
            json_api_message(true, format!("Key generated successfully using method: {}", method)),
        ),
        Err(err) => (StatusCode::BAD_REQUEST, json_api_message(false, err.to_string())),
    }
}
