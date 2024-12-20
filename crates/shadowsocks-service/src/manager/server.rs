//! Shadowsocks Manager server

#[cfg(unix)]
use std::path::PathBuf;
use std::{collections::HashMap, io, net::SocketAddr, sync::Arc, time::Duration};
use bytes::Bytes;
use log::{error, info, trace, warn, debug};
use shadowsocks::{
    config::{Mode, ServerConfig, ServerType, ServerUser, ServerUserManager},
    context::{Context, SharedContext},
    crypto::CipherKind,
    dns_resolver::DnsResolver,
    manager::{
        datagram::ManagerSocketAddr,
        protocol::{
            self, AddRequest, AddResponse, ErrorResponse, ListResponse, ManagerRequest, PingResponse, RemoveRequest,
            RemoveResponse, ServerUserConfig, StatRequest,
        },
    },
    net::{AcceptOpts, ConnectOpts},
    plugin::PluginConfig,
    ManagerListener, ServerAddr,
};
use tokio::sync::mpsc::UnboundedSender;
use tokio::{sync::Mutex, task::JoinHandle, time};
use shadowsocks::manager::domain_command::DomainCommand;
use shadowsocks::manager::protocol::{AddUserRequest, AddUserResponse, CommandResponse, ManagerProtocol, RemoveUserRequest, RemoveUserResponse};
use crate::{
    acl::AccessControl,
    config::{ManagerConfig, ManagerServerHost, ManagerServerMode, SecurityConfig},
    net::FlowStat,
    server::ServerBuilder};
use crate::mysql_db::Database;

enum ServerInstanceMode {
    Builtin {
        flow_stat: Arc<FlowStat>,
        abortable: JoinHandle<io::Result<()>>,
    },

    #[cfg(unix)]
    Standalone { flow_stat: u64 },
}


struct ServerInstance {
    mode: ServerInstanceMode,
    svr_cfg: ServerConfig,
    tcp_user_manager_sender: Option<UnboundedSender<ServerUserManager>>,
    udp_user_manager_sender: Option<UnboundedSender<ServerUserManager>>
}

impl Drop for ServerInstance {
    fn drop(&mut self) {
        #[allow(irrefutable_let_patterns)]
        if let ServerInstanceMode::Builtin { ref abortable, .. } = self.mode {
            warn!("<< aborting SERVER ALSO!! {:?}", abortable.is_finished());
            abortable.abort();
        }
    }
}

impl ServerInstance {
    fn flow_stat(&self) -> u64 {
        match self.mode {
            ServerInstanceMode::Builtin { ref flow_stat, .. } => flow_stat.tx() + flow_stat.rx(),
            #[cfg(unix)]
            ServerInstanceMode::Standalone { flow_stat } => flow_stat,
        }
    }

    fn update_user_manager(&mut self, manager:&ServerUserManager) {
        self.svr_cfg.set_user_manager(manager.clone());
        self.udp_user_manager_sender.clone().unwrap().send(manager.clone()).unwrap();
        self.tcp_user_manager_sender.clone().unwrap().send(manager.clone()).unwrap();
    }
}

/// Manager server builder
pub struct ManagerBuilder {
    context: SharedContext,
    svr_cfg: ManagerConfig,
    connect_opts: ConnectOpts,
    accept_opts: AcceptOpts,
    udp_expiry_duration: Option<Duration>,
    udp_capacity: Option<usize>,
    acl: Option<Arc<AccessControl>>,
    ipv6_first: bool,
    security: SecurityConfig,
}

impl ManagerBuilder {
    /// Create a new manager server builder from configuration
    pub fn new(svr_cfg: ManagerConfig) -> ManagerBuilder {
        ManagerBuilder::with_context(svr_cfg, Context::new_shared(ServerType::Server))
    }

    /// Create a new manager server builder with context and configuration
    pub(crate) fn with_context(svr_cfg: ManagerConfig, context: SharedContext) -> ManagerBuilder {
        ManagerBuilder {
            context,
            svr_cfg,
            connect_opts: ConnectOpts::default(),
            accept_opts: AcceptOpts::default(),
            udp_expiry_duration: None,
            udp_capacity: None,
            acl: None,
            ipv6_first: false,
            security: SecurityConfig::default(),
        }
    }

    /// Set `ConnectOpts`
    pub fn set_connect_opts(&mut self, opts: ConnectOpts) {
        self.connect_opts = opts;
    }

    /// Set `AcceptOpts`
    pub fn set_accept_opts(&mut self, opts: AcceptOpts) {
        self.accept_opts = opts;
    }

    /// Set UDP association's expiry duration
    pub fn set_udp_expiry_duration(&mut self, d: Duration) {
        self.udp_expiry_duration = Some(d);
    }

    /// Set total UDP associations to be kept in one server
    pub fn set_udp_capacity(&mut self, c: usize) {
        self.udp_capacity = Some(c);
    }

    /// Get the manager's configuration
    pub fn config(&self) -> &ManagerConfig {
        &self.svr_cfg
    }

    /// Get customized DNS resolver
    pub fn set_dns_resolver(&mut self, resolver: Arc<DnsResolver>) {
        let context = Arc::get_mut(&mut self.context).expect("cannot set DNS resolver on a shared context");
        context.set_dns_resolver(resolver)
    }

    /// Set access control list
    pub fn set_acl(&mut self, acl: Arc<AccessControl>) {
        self.acl = Some(acl);
    }

    /// Try to connect IPv6 addresses first if hostname could be resolved to both IPv4 and IPv6
    pub fn set_ipv6_first(&mut self, ipv6_first: bool) {
        self.ipv6_first = ipv6_first;
    }

    /// Set security config
    pub fn set_security_config(&mut self, security: SecurityConfig) {
        self.security = security;
    }

    /// Build the manager server instance
    pub async fn build(self) -> io::Result<Manager> {
        let listener = ManagerListener::bind(&self.context, &self.svr_cfg.addr).await?;
        Ok(Manager {
            context: self.context,
            servers: Mutex::new(HashMap::new()),
            svr_cfg: self.svr_cfg,
            connect_opts: self.connect_opts,
            accept_opts: self.accept_opts,
            udp_expiry_duration: self.udp_expiry_duration,
            udp_capacity: self.udp_capacity,
            acl: self.acl,
            ipv6_first: self.ipv6_first,
            security: self.security,
            listener,
        })
    }
}

/// Manager server
pub struct Manager {
    context: SharedContext,
    servers: Mutex<HashMap<u16, ServerInstance>>,
    svr_cfg: ManagerConfig,
    connect_opts: ConnectOpts,
    accept_opts: AcceptOpts,
    udp_expiry_duration: Option<Duration>,
    udp_capacity: Option<usize>,
    acl: Option<Arc<AccessControl>>,
    ipv6_first: bool,
    security: SecurityConfig,
    listener: ManagerListener,
}

impl Manager {
    /// Manager server's configuration
    pub fn manager_config(&self) -> &ManagerConfig {
        &self.svr_cfg
    }

    /// Manager server's listen address
    pub fn local_addr(&self) -> io::Result<ManagerSocketAddr> {
        self.listener.local_addr()
    }

    /// Start serving
    pub async fn run(mut self, mut database: Option<&mut Arc<Mutex<Database>>>) -> io::Result<()> {
        let local_addr = self.listener.local_addr()?;
        info!("shadowsocks manager server listening on {}", local_addr);

        loop {
            let (req, peer_addr) = match self.listener.recv_from().await {
                Ok(r) => {
                    debug!("received a manager config: {:?}", r);
                    r
                },
                Err(err) => {
                    error!("manager recv_from error: {}", err);
                    continue;
                }
            };

            debug!("received {:?} from {:?}", req, peer_addr);

            match req {
                ManagerRequest::Command(ref req) => {
                    debug!("received a manager command: {:?}", req);
                    let uuid = req.id;
                    let response = match req.command.as_deref() {
                        Some("list") => {
                            String::from_utf8(self.handle_list().await.to_bytes()?)
                        }
                        Some("ping") => {
                            String::from_utf8(self.handle_ping().await.to_bytes()?)
                        }
                        Some(thing) => {
                            // Handle removeu config object
                            if thing.starts_with("removeu") {
                                let parts = thing.split(":").collect::<Vec<&str>>();
                                let key = parts[1].trim();
                                let ru = RemoveUserRequest { key: key.to_owned() };
                                let response = self.handle_remove_user(&ru).await?;
                                debug!("received remove user response: {:?}", response);
                                String::from_utf8(response.to_bytes()?)
                            // Handle addu config object
                            } else if thing.starts_with("addu")  {
                                // let parts = thing.split(":").collect::<Vec<&str>>();
                                if let Some((_, config)) = thing.split_once(':') {
                                    let config = serde_json::from_slice(config.as_bytes())?;
                                    let au = AddUserRequest { config };
                                    let response = self.handle_add_user(&au).await?;
                                    debug!("received add user response: {:?}", response);
                                    String::from_utf8(response.to_bytes()?)
                                } else {
                                    warn!("Failed to split addu command: {}", thing);
                                    Ok(format!("Not implemented for {}", thing))
                                }
                            } else {
                                warn!("received unrecognized command: {}", thing);
                                Ok(format!("Not implemented for {}", thing))
                            }
                        }
                        None => {
                            Ok("Not implemented".to_string())
                        }
                    };
                    let res_str = response.map_err(|_|"Error ???").unwrap();
                    let response = DomainCommand::from_response(&res_str, uuid);
                    let resp = CommandResponse(response);
                    let _ = self.listener.send_to(&resp, &peer_addr).await;
                }
                ManagerRequest::Add(ref req) => match self.handle_add(req).await {
                    Ok(rsp) => {
                        let _ = self.listener.send_to(&rsp, &peer_addr).await;
                    }
                    Err(err) => {
                        error!("add server_port: {} failed, error: {}", req.server_port, err);
                        let rsp = ErrorResponse(err);
                        let _ = self.listener.send_to(&rsp, &peer_addr).await;
                    }
                },
                ManagerRequest::Remove(ref req) => {
                    let rsp = self.handle_remove(req).await;
                    let _ = self.listener.send_to(&rsp, &peer_addr).await;
                }
                ManagerRequest::List(..) => {
                    let rsp = self.handle_list().await;
                    match self.listener.send_to(&rsp, &peer_addr).await {
                        Ok(_) => {}
                        Err(e) => {
                            warn!("failed to send list response: {:?}", e);
                        }
                    }
                }
                ManagerRequest::Ping(..) => {
                    let rsp = self.handle_ping().await;
                    let _ = self.listener.send_to(&rsp, &peer_addr).await;
                }
                ManagerRequest::AddUser(ref req) => match self.handle_add_user(req).await {
                    Ok(a) => {
                        match self.listener.send_to(&a, &peer_addr).await {
                            Ok(_) => {
                                // Added to config, add to database
                                if let Some(ref mut db) = database {
                                    let mut guard = db.lock().await;
                                    if let Ok(_) = guard.add_or_update_users(&req.config) {
                                        debug!("add user success!");
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("failed to send AddUser response: {:?}", e);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("added user failed: {}", e);
                    }
                }
                ManagerRequest::Stat(ref stat) => self.handle_stat(stat).await,

                ManagerRequest::RemoveUser(ref req) => match self.handle_remove_user(req).await {
                    Ok(r) => {
                        warn!("<<<<<< removed user: {:?}", r);
                    }
                    Err(e) => {
                        warn!("<<<<<< removed user failed: {}", e);
                    }
                }
            }
        }
    }

    /// Add a server programmatically
    pub async fn add_server(&self, svr_cfg: ServerConfig) {
        match self.svr_cfg.server_mode {
            ManagerServerMode::Builtin => {
                trace!("built-in server mode");
                self.add_server_builtin(svr_cfg).await
            },
            #[cfg(unix)]
            ManagerServerMode::Standalone => {
                trace!("standalone server mode");
                self.add_server_standalone(svr_cfg).await
            },
        }
    }

    async fn add_server_builtin(&self, svr_cfg: ServerConfig) {
        // Each server should use a separate Context, but shares
        //
        // * AccessControlList
        // * DNS Resolver
        let mut server_builder = ServerBuilder::new(svr_cfg.clone());

        server_builder.set_connect_opts(self.connect_opts.clone());
        server_builder.set_accept_opts(self.accept_opts.clone());
        server_builder.set_dns_resolver(self.context.dns_resolver().clone());

        if let Some(d) = self.udp_expiry_duration {
            server_builder.set_udp_expiry_duration(d);
        }

        if let Some(c) = self.udp_capacity {
            server_builder.set_udp_capacity(c);
        }

        if let Some(ref acl) = self.acl {
            server_builder.set_acl(acl.clone());
        }

        if self.ipv6_first {
            server_builder.set_ipv6_first(self.ipv6_first);
        }

        server_builder.set_security_config(&self.security);

        let server_port = server_builder.server_config().addr().port();
        let mut servers = self.servers.lock().await;
        match servers.get(&server_port) {
            Some(sss) => {
                match &sss.mode {
                    ServerInstanceMode::Builtin { flow_stat: _, abortable} => {
                        warn!("Aborting SERVER!!");
                        abortable.abort();
                        // actually aborting the server can take a second or more, this
                        // assures us that it's done.
                        while !abortable.is_finished() {
                            trace!("waiting ...");
                            time::sleep(Duration::from_millis(500)).await;
                        }
                    }
                    #[cfg(unix)]
                    ServerInstanceMode::Standalone { .. } => {}
                }
            }
            None => {}
        }
        // Close existed server
        if let Some(v) = servers.remove(&server_port) {
            info!(
                "closed managed server listening on {}, inbound address {}",
                v.svr_cfg.addr(),
                v.svr_cfg.tcp_external_addr()
            );
        }

        let flow_stat = server_builder.flow_stat();
        let (server, (
            tcp_user_sender,
            udp_user_sender
        )) = match server_builder.build().await {
            Ok(s) => s,
            Err(err) => {
                error!("failed to start server ({}), error: {}", svr_cfg.addr(), err);
                return;
            }
        };

        let abortable = tokio::spawn(async move {
            server.run().await
        });

        if let Some(um) = svr_cfg.user_manager() {
            if let Some(ref sender) = tcp_user_sender {
                sender.send(um.to_owned()).unwrap();
            }
            if let Some(ref sender) = udp_user_sender {
                sender.send(um.to_owned()).unwrap();
            }
        }

        servers.insert(
            server_port,
            ServerInstance {
                mode: ServerInstanceMode::Builtin { flow_stat, abortable },
                svr_cfg,
                tcp_user_manager_sender: tcp_user_sender,
                udp_user_manager_sender: udp_user_sender,
            }
        );
    }

    #[cfg(unix)]
    fn server_pid_path(&self, port: u16) -> PathBuf {
        let pid_file_name = format!("shadowsocks-server-{port}.pid");
        let mut pid_path = self.svr_cfg.server_working_directory.clone();
        pid_path.push(&pid_file_name);
        pid_path
    }

    #[cfg(unix)]
    fn server_config_path(&self, port: u16) -> PathBuf {
        let config_file_name = format!("shadowsocks-server-{port}.json");
        let mut config_file_path = self.svr_cfg.server_working_directory.clone();
        config_file_path.push(&config_file_name);
        config_file_path
    }

    #[cfg(unix)]
    fn kill_standalone_server(&self, port: u16) {
        use log::{debug, warn};
        use std::{
            fs::{self, File},
            io::Read,
        };

        let pid_path = self.server_pid_path(port);
        if pid_path.exists() {
            if let Ok(mut pid_file) = File::open(&pid_path) {
                let mut pid_content = String::new();
                if pid_file.read_to_string(&mut pid_content).is_ok() {
                    let pid_content = pid_content.trim();

                    match pid_content.parse::<libc::pid_t>() {
                        Ok(pid) => {
                            let _ = unsafe { libc::kill(pid, libc::SIGTERM) };
                            debug!("killed standalone server port {}, pid: {}", port, pid);
                        }
                        Err(..) => {
                            warn!("failed to read pid from {}", pid_path.display());
                        }
                    }
                }
            }
        }

        let server_config_path = self.server_config_path(port);

        let _ = fs::remove_file(pid_path);
        let _ = fs::remove_file(server_config_path);
    }

    #[cfg(unix)]
    async fn add_server_standalone(&self, svr_cfg: ServerConfig) {
        use std::{
            fs::{self, OpenOptions},
            io::Write,
        };

        use tokio::process::Command;

        use crate::config::{Config, ConfigType, ServerInstanceConfig};

        // Lock the map first incase there are multiple requests to create one server instance
        let mut servers = self.servers.lock().await;

        // Check if working_directory exists
        if !self.svr_cfg.server_working_directory.exists() {
            fs::create_dir_all(&self.svr_cfg.server_working_directory).expect("create working_directory");
        }

        let port = svr_cfg.addr().port();

        // Check if there is already a running process
        self.kill_standalone_server(port);

        // Create configuration file for server
        let config_file_path = self.server_config_path(port);
        let pid_path = self.server_pid_path(port);

        let server_instance = ServerInstanceConfig {
            config: svr_cfg.clone(),
            acl: None, // Set with --acl command line argument
            #[cfg(any(target_os = "linux", target_os = "android"))]
            outbound_fwmark: None,
            outbound_bind_addr: None,
            outbound_bind_interface: None,
            outbound_udp_allow_fragmentation: None,
        };

        let mut config = Config::new(ConfigType::Server);
        config.server.push(server_instance);

        trace!("created standalone server with config {:?}", config);

        let config_file_content = format!("{config}");

        match OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&config_file_path)
        {
            Err(err) => {
                error!(
                    "failed to open {} for writing, error: {}",
                    config_file_path.display(),
                    err
                );
                return;
            }
            Ok(mut file) => {
                if let Err(err) = file.write_all(config_file_content.as_bytes()) {
                    error!("failed to write {}, error: {}", config_file_path.display(), err);
                    return;
                }
                let _ = file.sync_data();
            }
        }

        let manager_addr = self.svr_cfg.addr.to_string();

        // Start server process
        let mut child_command = Command::new(&self.svr_cfg.server_program);
        child_command
            .arg("-c")
            .arg(&config_file_path)
            .arg("--daemonize")
            .arg("--daemonize-pid")
            .arg(&pid_path)
            .arg("--manager-addr")
            .arg(&manager_addr);

        if let Some(ref acl) = self.acl {
            child_command.arg("--acl").arg(acl.file_path().to_str().expect("acl"));
        }

        let child_result = child_command.kill_on_drop(false).spawn();

        if let Err(err) = child_result {
            error!(
                "failed to spawn process of {}, error: {}",
                self.svr_cfg.server_program, err
            );
            return;
        }

        // Create. Record into the map
        servers.insert(
            port,
            ServerInstance {
                mode: ServerInstanceMode::Standalone { flow_stat: 0 },
                svr_cfg,
                tcp_user_manager_sender: None,
                udp_user_manager_sender: None,
            },
        );
    }

    // async fn get_tcp_user_manager_sender(&self, port:u16)-> Option<UnboundedSender<ServerUserManager>> {
    //     let mut found :Option<UnboundedSender<ServerUserManager>> = None;
    //     let servers = self.servers.lock().await;
    //     for (_, server) in servers.iter() {
    //         let same = server.svr_cfg.addr().port() == port;
    //         if same {
    //             found =  server.tcp_user_manager_sender.clone();
    //         }
    //         break;
    //     }
    //     found
    // }
    // async fn get_udp_user_manager_sender(&self, port:u16)-> Option<UnboundedSender<ServerUserManager>> {
    //     let mut found :Option<UnboundedSender<ServerUserManager>> = None;
    //     let servers = self.servers.lock().await;
    //     for (_, server) in servers.iter() {
    //         let same = server.svr_cfg.addr().port() == port;
    //         if same {
    //             found =  server.udp_user_manager_sender.clone();
    //         }
    //         break;
    //     }
    //     found
    // }

    async fn get_config(&self, port: u16) -> Option<ServerConfig> {
        let mut found :Option<ServerConfig> = None;
        let servers = self.servers.lock().await;
        for (_, server) in servers.iter() {
            let same = server.svr_cfg.addr().port() == port;
            if same {
                found =  Some(server.svr_cfg.clone());
            }
        }
        found
    }

    async fn handle_remove_user(&self, remove_request: &RemoveUserRequest) ->  io::Result<RemoveUserResponse> {
        let user_hash: String = remove_request.key.clone();
        let key_in = ServerUser::str_to_key(&user_hash).expect("failed to decode Key");
        let mut servers = self.servers.lock().await;

        let matching_server = servers.iter_mut().find(|(_, server_instance)| {
            server_instance
                .svr_cfg
                .user_manager()
                .map(|user_manager| {
                    let users_map: &HashMap<Bytes, Arc<ServerUser>> = &user_manager.users;
                    users_map
                        .values()
                        .any(|user| user.key() == key_in)
                })
                .unwrap_or(false)
        });
        if let Some((_, server_instance)) = matching_server {
            let bytes: Bytes = key_in.into();
            let identity = ServerUser::key_to_identity(&bytes);
            let mut user_manager = server_instance.svr_cfg.copy_user_manager();
            if let Some(_) = user_manager.remove_user(&identity) {
                server_instance.update_user_manager(&user_manager);
            }

            Ok(RemoveUserResponse("User found and processed".to_string()))
        } else {
            Ok(RemoveUserResponse("User not found".to_string()))
        }
    }

    async fn handle_add_user(&self, req: &AddUserRequest) -> io::Result<AddUserResponse> {
        let new_config = &req.config;
        let port  = new_config.server_port;
        if let Some(mut existing_config) =self.get_config(port).await {
            match ServerUserManager::user_manager_with_users(&new_config.users) {
                Ok(mut new_manager) => {
                    if let Some(old_manager) = existing_config.user_manager() {
                        old_manager.users_iter().for_each(|u| {
                            new_manager.add_user(u.clone());
                        });
                    }
                    let mut servers = self.servers.lock().await;
                    let matching_server = servers.iter_mut().find(|(_, srv)|{
                        srv.svr_cfg.addr().port() == port
                    });
                    if let Some((_,matching_server)) = matching_server {
                        matching_server.update_user_manager(&new_manager);
                    }

                    // update existing config!!
                    existing_config.set_user_manager(new_manager);
                },
                Err(err) => {
                    error!("Failed to Build new ServerUserManager: {:?}", err);
                }
            }
        }
        Ok(AddUserResponse("Done".into()))
    }

    async fn handle_add(&self, req: &AddRequest) -> io::Result<AddResponse> {
        let addr = match self.svr_cfg.server_host {
            ManagerServerHost::Domain(ref dname) => ServerAddr::DomainName(dname.clone(), req.server_port),
            ManagerServerHost::Ip(ip) => ServerAddr::SocketAddr(SocketAddr::new(ip, req.server_port)),
        };

        let method = match req.method {
            Some(ref m) => match m.parse::<CipherKind>() {
                Ok(method) => method,
                Err(..) => {
                    error!("unrecognized method \"{}\", req: {:?}", m, req);

                    let err = format!("unrecognized method \"{m}\"");
                    return Ok(AddResponse(err));
                }
            },
            #[cfg(feature = "aead-cipher")]
            None => self.svr_cfg.method.unwrap_or(CipherKind::CHACHA20_POLY1305),
            #[cfg(not(feature = "aead-cipher"))]
            None => return Ok(AddResponse("method is required")),
        };

        let mut svr_cfg = match ServerConfig::new(addr, req.password.clone(), method) {
            Ok(svr_cfg) => svr_cfg,
            Err(err) => {
                error!("failed to create ServerConfig, error: {}", err);
                return Ok(AddResponse("invalid server".to_string()));
            }
        };

        if let Some(ref plugin) = req.plugin {
            let p = PluginConfig {
                plugin: plugin.clone(),
                plugin_opts: req.plugin_opts.clone(),
                plugin_args: Vec::new(),
                plugin_mode: match req.plugin_mode {
                    None => Mode::TcpOnly,
                    Some(ref mode) => match mode.parse::<Mode>() {
                        Ok(m) => m,
                        Err(..) => {
                            error!("unrecognized plugin_mode \"{}\", req: {:?}", mode, req);

                            let err = format!("unrecognized plugin_mode \"{}\"", mode);
                            return Ok(AddResponse(err));
                        }
                    },
                },
            };
            svr_cfg.set_plugin(p);
        } else if let Some(ref plugin) = self.svr_cfg.plugin {
            svr_cfg.set_plugin(plugin.clone());
        }

        let mode = match req.mode {
            None => None,
            Some(ref mode) => match mode.parse::<Mode>() {
                Ok(m) => Some(m),
                Err(..) => {
                    error!("unrecognized mode \"{}\", req: {:?}", mode, req);

                    let err = format!("unrecognized mode \"{mode}\"");
                    return Ok(AddResponse(err));
                }
            },
        };

        svr_cfg.set_mode(mode.unwrap_or(self.svr_cfg.mode));

        match ServerUserManager::user_manager_with_users(req.users.as_ref().expect("missing users")) {
            Ok(manager) => {
                svr_cfg.set_user_manager(manager);
            }
            Err(e) => {
                return Err(e);
            }
        }

        self.add_server(svr_cfg).await;

        Ok(AddResponse("ok".to_owned()))
    }

    async fn handle_remove(&self, req: &RemoveRequest) -> RemoveResponse {
        let mut servers = self.servers.lock().await;
        servers.remove(&req.server_port);

        #[cfg(unix)]
        if self.svr_cfg.server_mode == ManagerServerMode::Standalone {
            self.kill_standalone_server(req.server_port);
        }

        RemoveResponse("ok".to_owned())
    }

    async fn handle_list(&self) -> ListResponse {
        let instances = self.servers.lock().await;

        let mut servers = Vec::new();

        for (_, server) in instances.iter() {
            let svr_cfg = &server.svr_cfg;

            let mut users = None;
            if let Some(user_manager) = server.svr_cfg.user_manager() {
                let mut vu = Vec::with_capacity(user_manager.user_count());

                for user in user_manager.users_iter() {
                    vu.push(ServerUserConfig {
                        name: user.name().to_owned(),
                        password: user.encoded_key(),
                    });
                }

                users = Some(vu);
            }

            let sc = protocol::ServerConfigOther {
                server_port: svr_cfg.addr().port(),
                password: svr_cfg.password().to_owned(),
                method: None,
                no_delay: None,
                plugin: None,
                plugin_opts: None,
                plugin_mode: None,
                mode: None,
                users,
            };
            servers.push(sc);
        }

        ListResponse { servers }
    }

    async fn handle_ping(&self) -> PingResponse {
        let instances = self.servers.lock().await;

        let mut stat = HashMap::new();
        for (port, server) in instances.iter() {
            stat.insert(*port, server.flow_stat());
        }

        PingResponse { stat }
    }

    #[cfg(not(unix))]
    async fn handle_stat(&self, _: &StatRequest) {}

    #[cfg(unix)]
    async fn handle_stat(&self, stat: &StatRequest) {
        use log::warn;
        use std::collections::hash_map::Entry;

        use crate::config::{Config, ConfigType};

        // `stat` is only supported for Standalone mode
        if self.svr_cfg.server_mode != ManagerServerMode::Standalone {
            return;
        }

        let mut instances = self.servers.lock().await;

        // Get or create a new instance then record the data statistic numbers
        for (port, flow) in stat.stat.iter() {
            match instances.entry(*port) {
                Entry::Occupied(mut occ) => match occ.get_mut().mode {
                    ServerInstanceMode::Builtin { .. } => {
                        error!("received `stat` for port {} that is running a builtin server", *port)
                    }
                    ServerInstanceMode::Standalone { ref mut flow_stat } => *flow_stat = *flow,
                },
                Entry::Vacant(vac) => {
                    // Read config from file

                    let server_config_path = self.server_config_path(*port);
                    if !server_config_path.exists() {
                        warn!(
                            "received `stat` for port {} but file {} doesn't exist",
                            *port,
                            server_config_path.display()
                        );
                        continue;
                    }

                    match Config::load_from_file(&server_config_path, ConfigType::Server) {
                        Err(err) => {
                            error!(
                                "failed to load {} for server port {}, error: {}",
                                server_config_path.display(),
                                *port,
                                err
                            );
                            continue;
                        }
                        Ok(config) => {
                            trace!(
                                "loaded {} for server port {}, {:?}",
                                server_config_path.display(),
                                *port,
                                config
                            );

                            if config.server.len() != 1 {
                                error!(
                                    "invalid config {} for server port {}, containing {} servers",
                                    server_config_path.display(),
                                    *port,
                                    config.server.len()
                                );
                                continue;
                            }

                            let svr_cfg = config.server[0].config.clone();

                            vac.insert(ServerInstance {
                                mode: ServerInstanceMode::Standalone { flow_stat: *flow },
                                svr_cfg,
                                tcp_user_manager_sender: None,
                                udp_user_manager_sender: None,
                            });
                        }
                    }
                }
            }
        }
    }
}
