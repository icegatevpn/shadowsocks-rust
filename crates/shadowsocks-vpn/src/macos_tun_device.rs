use clap::Command;
use log::{debug, error, info, trace, warn};
use serde::{Deserialize, Serialize};
use shadowsocks::ServerAddr;
use shadowsocks_rust::service::local;
use shadowsocks_rust::VERSION;
use shadowsocks_service::config::Config;
use shadowsocks_service::config::ProtocolType;
use std::io;
use std::process::Command as ProcessCommand;
use std::sync::Arc;
use tokio::sync::Mutex;

#[cfg(target_os = "macos")]
pub struct MacOSTunDevice {
    config: Option<Config>,
    tun_interface: Option<String>,
    running: Arc<Mutex<bool>>,
    original_routes: Arc<Mutex<Option<String>>>,
}
#[cfg(target_os = "macos")]
#[derive(Debug, Serialize, Deserialize)]
struct RouteState {
    default_gateway: String,
    interface: String,
    ipv6_routes: Vec<String>,
}

#[cfg(target_os = "macos")]
impl MacOSTunDevice {
    pub fn new() -> io::Result<Self> {
        Ok(MacOSTunDevice {
            config: None,
            tun_interface: None,
            running: Arc::new(Mutex::new(false)),
            original_routes: Arc::new(Mutex::new(None)),
        })
    }

    async fn add_bypass_route_for_server(&self, default_gateway: &str) -> io::Result<()> {
        if let Some(config) = self.config.as_ref() {
            for server in &config.server {
                let server_addr = match server.config.addr() {
                    ServerAddr::SocketAddr(addr) => addr.ip().to_string(),
                    ServerAddr::DomainName(domain, _) => {
                        // Get server's IP if it's a hostname
                        use tokio::net::lookup_host;
                        if let Ok(mut addrs) = lookup_host(format!("{}:0", domain)).await {
                            if let Some(addr) = addrs.next() {
                                addr.ip().to_string()
                            } else {
                                warn!("Could not resolve server address: {}", domain);
                                continue;
                            }
                        } else {
                            warn!("Failed to lookup server address: {}", domain);
                            continue;
                        }
                    }
                };

                info!(
                    "Adding bypass route for server {} via gateway {}",
                    server_addr, &default_gateway
                );
                // Add bypass route for the server
                let output = ProcessCommand::new("route")
                    .arg("-n")
                    .arg("add")
                    .arg("-host")
                    .arg(&server_addr)
                    .arg("-gateway")
                    .arg(&default_gateway)
                    .output()?;

                if !output.status.success() {
                    let error = String::from_utf8_lossy(&output.stderr);
                    warn!("Failed to add server bypass route for {}: {}", server_addr, error);
                }
            }
        }

        Ok(())
    }

    pub async fn start(&mut self, config_str: String) -> io::Result<()> {
        if self.is_running().await {
            warn!("TUN device already running");
            return Ok(());
        }

        // Spawn the TUN device task
        let mut app = Command::new("shadowsocks").version(VERSION);
        app = local::define_command_line_options(app);

        let matches = app.get_matches();

        // Create the local service runtime and future
        let (config, runtime, main_fut) = match local::create(&matches, Some(&config_str)) {
            Ok((cf, rt, fut)) => (cf, rt, fut),
            Err(err) => {
                error!("Failed to create Shadowsocks service: {}", err);
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Service creation error: {}", err),
                ));
            }
        };
        let running = self.running.clone();
        std::thread::spawn(move || {
            info!("Starting Shadowsocks service in background thread");

            // This is now safe because we're in a new OS thread
            match runtime.block_on(main_fut) {
                Ok(_) => {
                    info!("Shadowsocks service completed successfully");
                }
                Err(err) => {
                    error!("Shadowsocks service error: {}", err);
                }
            }

            // Update the running state when the service exits
            let _ = futures::executor::block_on(async {
                *running.lock().await = false;
            });
        });

        *self.running.lock().await = true;
        self.config = Some(config.clone());

        if let Some(tun) = config.local.iter().find(|ff| ff.config.protocol == ProtocolType::Tun) {
            self.tun_interface = tun.config.tun_interface_name.clone();
            info!("Shadowsocks running on Tun {:?}...", self.tun_interface)
        }

        // Configure routing
        if let Some(interface) = &self.tun_interface {
            self.configure_routing(interface).await?
        }
        Ok(())
    }

    async fn save_routing_state(&self) -> io::Result<RouteState> {
        let output = ProcessCommand::new("netstat").arg("-rn").output()?;
        if !output.status.success() {
            return Err(io::Error::new(io::ErrorKind::Other, "Failed to get routing state"));
        }

        let table = String::from_utf8_lossy(&output.stdout);
        debug!("Current routing table:\n{}", table);

        // Parse default route info
        let default_route = table
            .lines()
            .find(|line| line.contains("default") && !line.contains("::"))
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Could not find default gateway"))?;

        let parts: Vec<&str> = default_route.split_whitespace().collect();
        let gateway = parts
            .get(1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Invalid default route format"))?
            .to_string();
        let interface = parts
            .get(3)
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Invalid default route format"))?
            .to_string();

        // Save IPv6 routes
        let ipv6_routes: Vec<String> = table
            .lines()
            .filter(|line| line.contains("::") && !line.trim().is_empty())
            .map(|line| line.trim().to_string())
            .collect();

        debug!("Saved route state - Gateway: {}, Interface: {}", gateway, interface);

        Ok(RouteState {
            default_gateway: gateway,
            interface,
            ipv6_routes,
        })
    }

    fn native_default_gateway(&self) -> io::Result<String> {
        let output = ProcessCommand::new("route").args(["-n", "get", "default"]).output()?;

        if !output.status.success() {
            return Err(io::Error::new(io::ErrorKind::Other, "Failed to get default gateway"));
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        let mut gateway = None;
        for line in output_str.lines() {
            if line.trim().starts_with("gateway:") {
                gateway = Some(line.split_whitespace().last().unwrap_or("").to_string());
                break;
            }
        }

        Ok(gateway.ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Could not determine default gateway"))?)
    }

    async fn clear_default_route(&self, default_gateway: &str) -> io::Result<()> {
        debug!("Current default gateway is: {}", &default_gateway);

        // First try to delete the existing default route
        let delete_output = ProcessCommand::new("route")
            .arg("-n")
            .arg("delete")
            .arg("default")
            .output()?;
        if delete_output.status.success() {
            debug!("Successfully deleted existing default route");
        } else {
            debug!(
                "No existing default route to delete or delete failed (this is usually OK): {}",
                String::from_utf8_lossy(&delete_output.stderr)
            );
        }

        Ok(())
    }

    async fn configure_routing(&self, interface: &str) -> io::Result<()> {
        // return Ok(());  bypass all!!
        // Save current routing state before making changes
        let route_state = self.save_routing_state().await?;
        debug!(
            "Configuring routes with default gateway: {}",
            route_state.default_gateway
        );
        // Store the route state
        *self.original_routes.lock().await = Some(serde_json::to_string(&route_state)?);

        let gateway = self.native_default_gateway()?;

        // Add bypass routes for shadowsocks servers before changing default route
        self.add_bypass_route_for_server(&gateway).await?;

        self.clear_default_route(&gateway).await?;

        // Disable IPv6 on the interface
        // self.disable_ipv6(interface).await?;
        self.disable_ipv6(&route_state.interface).await?;

        // Now add our new default route through the TUN interface
        let add_output = ProcessCommand::new("route")
            .arg("-n")
            .arg("add")
            .arg("default")
            .arg("-interface")
            .arg(interface)
            .output()?;

        info!(
            "Adding default route to new interface: {}",
            String::from_utf8_lossy(&add_output.stdout)
        );

        if !add_output.status.success() {
            error!(
                "Failed to add default route via TUN interface: {}",
                String::from_utf8_lossy(&add_output.stderr)
            );

            // Try to restore the original default route
            let restore_output = ProcessCommand::new("route")
                .arg("-n")
                .arg("add")
                .arg("default")
                .arg(&gateway)
                .output()?;

            if !restore_output.status.success() {
                error!(
                    "Failed to restore original default route to {}: {}",
                    gateway,
                    String::from_utf8_lossy(&restore_output.stderr)
                );
            }

            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "Failed to add default route: {}",
                    String::from_utf8_lossy(&add_output.stderr)
                ),
            ));
        }
        Ok(())
    }

    fn device_service_name(&self, interface: &str) -> io::Result<String> {
        // Get network service name for the interface
        let output = ProcessCommand::new("networksetup")
            .args(["-listallhardwareports"])
            .output()?;
        let output_str = String::from_utf8_lossy(&output.stdout);
        let mut service_name = None;
        // Parse output to find service name for our interface
        for chunk in output_str.split("\n\n") {
            if chunk.contains(&format!("Device: {}", interface)) {
                if let Some(line) = chunk.lines().next() {
                    service_name = line.strip_prefix("Hardware Port: ").map(String::from);
                }
            }
        }
        let service = service_name.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("Could not find network service for interface {}", interface),
            )
        })?;
        Ok(service)
    }

    async fn disable_ipv6(&self, original_interface: &str) -> io::Result<()> {
        debug!("Disabling IPv6 on interface: {}", original_interface);
        // Get network service name for the interface

        let service = self.device_service_name(original_interface)?;
        debug!(
            "Disabling IPv6 on service: {} (interface: {})",
            service, original_interface
        );

        // Disable IPv6 on the network service
        let output = ProcessCommand::new("networksetup")
            .args(["-setv6off", &service])
            .output()?;

        if !output.status.success() {
            warn!(
                "Failed to disable IPv6 on service {} (interface {}): {}",
                service,
                original_interface,
                String::from_utf8_lossy(&output.stderr)
            );
        }

        Ok(())
    }

    async fn restore_ipv6(&self, original_interface: &str) -> io::Result<()> {
        // Get network service name for the interface
        let service = self.device_service_name(original_interface)?;
        debug!(
            "Restoring IPv6 on service: {} (interface: {})",
            service, original_interface
        );

        // Re-enable IPv6 on the network service
        let output = ProcessCommand::new("networksetup")
            .args(["-setv6automatic", &service])
            .output()?;

        if !output.status.success() {
            warn!(
                "Failed to restore IPv6 on service {} (interface {}): {}",
                service,
                original_interface,
                String::from_utf8_lossy(&output.stderr)
            );
        }

        Ok(())
    }

    async fn restore_routing_state(&self) -> io::Result<()> {
        let route_state: RouteState = if let Some(saved_state) = self.original_routes.lock().await.as_ref() {
            serde_json::from_str(saved_state)?
        } else {
            return Err(io::Error::new(io::ErrorKind::Other, "No saved route state found"));
        };

        debug!("Restoring default route via gateway: {}", route_state.default_gateway);

        // Then restore the original default route
        let output = ProcessCommand::new("route")
            .arg("-n")
            .arg("add")
            .arg("-net")
            .arg("0.0.0.0/0")
            .arg(route_state.default_gateway)
            .output()?;

        if !output.status.success() {
            error!(
                "Failed to restore default route: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            return Err(io::Error::new(io::ErrorKind::Other, "Failed to restore default route"));
        }

        // Verify the restoration
        let check_output = ProcessCommand::new("netstat").arg("-rn").output()?;
        trace!("Final route table: {}", String::from_utf8_lossy(&check_output.stdout));

        Ok(())
    }

    async fn cleanup_routing(&self, interface: &str) -> io::Result<()> {
        debug!("Cleaning up routing state for: {}", interface);
        // Get the original state first - we need this for IPv6 restoration
        let route_state = match self.original_routes.lock().await.as_ref() {
            Some(state_str) => match serde_json::from_str::<RouteState>(state_str) {
                Ok(state) => state,
                Err(e) => {
                    error!("Failed to parse original route state: {}", e);
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "Failed to parse original route state",
                    ));
                }
            },
            None => {
                error!("No original route state found");
                return Err(io::Error::new(io::ErrorKind::Other, "No original route state found"));
            }
        };
        // First try to restore IPv6 on the original interface
        let ipv6_result = self.restore_ipv6(&route_state.interface).await;
        if let Err(ref e) = ipv6_result {
            error!("Failed to restore IPv6, but continuing with other cleanup: {}", e);
            // Don't return early - continue with other cleanup
        }

        debug!("Removing VPN routes and restoring original routing...");

        // Remove the default route through our TUN interface
        let output = ProcessCommand::new("route")
            .arg("-n")
            .arg("delete")
            .arg("-net")
            .arg("0.0.0.0/0")
            .arg("-interface")
            .arg(interface)
            .output()?;

        debug!("Remove default route: {}", String::from_utf8_lossy(&output.stdout));

        if !output.status.success() {
            warn!(
                "Failed to remove default route: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        // Remove server bypass routes
        if let Some(config) = self.config.as_ref() {
            for server in &config.server {
                let server_addr = match server.config.addr() {
                    ServerAddr::SocketAddr(addr) => addr.ip().to_string(),
                    ServerAddr::DomainName(domain, _) => {
                        use tokio::net::lookup_host;
                        if let Ok(mut addrs) = lookup_host(format!("{}:0", domain)).await {
                            if let Some(addr) = addrs.next() {
                                addr.ip().to_string()
                            } else {
                                continue;
                            }
                        } else {
                            continue;
                        }
                    }
                };

                let output = ProcessCommand::new("route")
                    .arg("-n")
                    .arg("delete")
                    .arg("-host")
                    .arg(&server_addr)
                    .output()?;
                debug!(
                    "Remove other default route:({}) {}",
                    server_addr,
                    String::from_utf8_lossy(&output.stdout)
                );

                if !output.status.success() {
                    warn!(
                        "Failed to remove bypass route for server {}: {}",
                        server_addr,
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
            }
        }

        // Restore original routing state
        if let Err(e) = self.restore_routing_state().await {
            error!("Failed to restore original routing state: {}", e);
            return Err(e);
        }

        // Verify IPv6 is enabled
        self.verify_ipv6_enabled(&route_state.interface).await?;

        info!("Cleanup completed successfully");

        Ok(())
    }

    pub async fn stop(&self) -> io::Result<()> {
        debug!("STOPPING...");
        if let Some(interface) = &self.tun_interface {
            self.cleanup_routing(interface).await?;
        }

        *self.running.lock().await = false;
        Ok(())
    }

    pub async fn is_running(&self) -> bool {
        *self.running.lock().await
    }

    async fn verify_ipv6_enabled(&self, interface: &str) -> io::Result<()> {
        // Get network service name
        let service = self.device_service_name(interface)?;

        // Check IPv6 status
        let output = ProcessCommand::new("networksetup")
            .args(["-getinfo", &service])
            .output()?;

        let info = String::from_utf8_lossy(&output.stdout);

        if !info.contains("IPv6: Automatic") {
            warn!(
                "IPv6 may not be properly enabled on {}. Current network info:\n{}",
                service, info
            );
            // Try one more time to enable it
            let _ = ProcessCommand::new("networksetup")
                .args(["-setv6automatic", &service])
                .output()?;
        }

        Ok(())
    }
}
