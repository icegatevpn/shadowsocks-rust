use log::{debug, error, info, warn};
use shadowsocks::config::Mode;
use shadowsocks_service::{
    config::Config,
    local::{
        context::ServiceContext,
        loadbalancing::PingBalancerBuilder,
        tun::{StaticDeviceNetHelper, TunBuilder},
    },
};
use std::io;
use std::net::IpAddr;
use std::os::fd::AsRawFd;
use std::process::Command;
use std::sync::Arc;
use tempfile::NamedTempFile;
use tokio::sync::Mutex;
use tun::{AbstractDevice, AsyncDevice, Configuration, Layer};
use serde::{Deserialize, Serialize};
use shadowsocks::ServerAddr;

pub struct MacOSTunDevice {
    config: Config,
    tun_interface: Option<String>,
    running: Arc<Mutex<bool>>,
    original_routes: Arc<Mutex<Option<String>>>,

}

#[derive(Debug, Serialize, Deserialize)]
struct RouteState {
    default_gateway: String,
    interface: String,
}

impl MacOSTunDevice {

    pub fn new(config: Config) -> io::Result<Self> {
        Ok(MacOSTunDevice {
            config,
            tun_interface: None,
            running: Arc::new(Mutex::new(false)),
            original_routes: Arc::new(Mutex::new(None)),
        })
    }
    async fn add_bypass_route_for_server(&self, default_gateway: &str) -> io::Result<()> {
        // Add bypass routes for each server
        for server in &self.config.server {
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

            debug!(
                "Adding bypass route for server {} via gateway {}",
                server_addr, default_gateway
            );

            // Add bypass route for the server
            let output = Command::new("route")
                .arg("-n")
                .arg("add")
                .arg("-host")
                .arg(&server_addr)
                .arg("-gateway")
                .arg(default_gateway)
                .output()?;

            if !output.status.success() {
                let error = String::from_utf8_lossy(&output.stderr);
                warn!("Failed to add server bypass route for {}: {}", server_addr, error);
            }
        }

        Ok(())
    }
    pub async fn start(&mut self) -> io::Result<()> {
        let mut running = self.running.lock().await;
        if *running {
            warn!("TUN device already running");
            return Ok(());
        }

        // Create shadowsocks context and balancer
        let context = Arc::new(ServiceContext::new());
        let mut balancer = PingBalancerBuilder::new(context.clone(), Mode::TcpAndUdp);

        // Add servers from config
        for server in &self.config.server {
            balancer.add_server(server.clone());
        }

        let balancer = balancer.build().await?;

        // Create and configure TUN builder
        let mut builder = TunBuilder::new(context, balancer);

        // Let shadowsocks create and configure the TUN interface
        let tun = builder.build().await?;

        // Store the interface name for cleanup
        if let Ok(name) = tun.interface_name() {
            self.tun_interface = Some(name.clone());
            // Configure routing once interface is ready
            self.configure_routing(&name).await?;
        }

        *running = true;
        drop(running);

        // Spawn the TUN device task
        tokio::spawn(async move {
            if let Err(e) = tun.run().await {
                error!("TUN device error: {}", e);
            }
        });

        Ok(())
    }

    async fn save_routing_state(&self) -> io::Result<RouteState> {
        let output = Command::new("netstat").arg("-rn").output()?;
        if !output.status.success() {
            return Err(io::Error::new(io::ErrorKind::Other, "Failed to get routing state"));
        }

        let table = String::from_utf8_lossy(&output.stdout);

        // Parse default route info
        let default_route = table
            .lines()
            .find(|line| line.contains("default"))
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Could not find default gateway"))?;

        let parts: Vec<&str> = default_route.split_whitespace().collect();
        let gateway = parts.get(1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Invalid default route format"))?
            .to_string();
        let interface = parts.get(3)
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Invalid default route format"))?
            .to_string();

        debug!("Saved default route - Gateway: {}, Interface: {}", gateway, interface);

        Ok(RouteState {
            default_gateway: gateway,
            interface,
        })
    }
    async fn clear_default_route(&self) -> io::Result<String> {
        let current_routes = Command::new("netstat")
            .arg("-rn")
            .output()?;
        if current_routes.status.success() {
            debug!("Current routing table before changes:\n{}",
            String::from_utf8_lossy(&current_routes.stdout));
        }
        // Get current default gateway before we remove it
        let default_gateway = String::from_utf8_lossy(&current_routes.stdout)
            .lines()
            .find(|line| line.contains("default"))
            .and_then(|line| line.split_whitespace().nth(1))
            .ok_or_else(|| io::Error::new(
                io::ErrorKind::Other,
                "Could not find current default gateway"
            ))?.to_string();
        debug!("Current default gateway is: {}", &default_gateway);

        // First try to delete the existing default route
        let delete_output = Command::new("route")
            .arg("-n")
            .arg("delete")
            .arg("default")
            .output()?;
        if delete_output.status.success() {
            debug!("Successfully deleted existing default route");
        } else {
            debug!("No existing default route to delete or delete failed (this is usually OK): {}",
            String::from_utf8_lossy(&delete_output.stderr));
        }

        Ok(default_gateway)
    }

    async fn configure_routing(&self, interface: &str) -> io::Result<()> {
        // Save current routing state before making changes
        let route_state = self.save_routing_state().await?;
        debug!("Configuring routes with default gateway: {}", route_state.default_gateway);
        // Store the route state
        *self.original_routes.lock().await = Some(serde_json::to_string(&route_state)?);

        let default_gateway = self.clear_default_route().await?;

        // Now add our new default route through the TUN interface
        let add_output = Command::new("route")
            .arg("-n")
            .arg("add")
            .arg("default")
            .arg("-interface")
            .arg(interface)
            .output()?;

        info!("Adding default route to new interface: {}",  String::from_utf8_lossy(&add_output.stdout));

        if !add_output.status.success() {
            error!("Failed to add default route via TUN interface: {}",
            String::from_utf8_lossy(&add_output.stderr));

            // Try to restore the original default route
            let restore_output = Command::new("route")
                .arg("-n")
                .arg("add")
                .arg("default")
                .arg(&default_gateway)
                .output()?;

            if !restore_output.status.success() {
                error!("Failed to restore original default route to {}: {}",
                default_gateway,
                String::from_utf8_lossy(&restore_output.stderr));
            }

            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to add default route: {}",
                        String::from_utf8_lossy(&add_output.stderr))
            ));
        }

        // Add bypass routes for shadowsocks servers before changing default route
        self.add_bypass_route_for_server(&default_gateway).await?;

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
        let output = Command::new("route")
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
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Failed to restore default route"
            ));
        }

        // Verify the restoration
        let check_output = Command::new("netstat").arg("-rn").output()?;
        debug!("Final route table: {}", String::from_utf8_lossy(&check_output.stdout));

        Ok(())
    }

    async fn cleanup_routing(&self, interface: &str) -> io::Result<()> {
        debug!("Cleaning up routing state for: {}", interface);
        // Remove the default route through our TUN interface
        let output = Command::new("route")
            .arg("-n")
            .arg("delete")
            .arg("-net")
            .arg("0.0.0.0/0")
            .arg("-interface")
            .arg(interface)
            .output()?;

        debug!("Remove 1 default route: {}",  String::from_utf8_lossy(&output.stdout));

        if !output.status.success() {
            warn!(
                "Failed to remove default route: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        // Remove server bypass routes
        for server in &self.config.server {
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

            let output = Command::new("route")
                .arg("-n")
                .arg("delete")
                .arg("-host")
                .arg(&server_addr)
                .output()?;
            debug!("Remove 2 default route:({}) {}",server_addr,  String::from_utf8_lossy(&output.stdout));

            if !output.status.success() {
                warn!(
                    "Failed to remove bypass route for server {}: {}",
                    server_addr,
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }

        self.restore_routing_state().await?;

        Ok(())
    }

    pub async fn stop(&self) -> io::Result<()> {
        let mut running = self.running.lock().await;
        if !*running {
            return Ok(());
        }

        if let Some(interface) = &self.tun_interface {
            self.cleanup_routing(interface).await?;
        }

        *running = false;
        Ok(())
    }

    pub async fn is_running(&self) -> bool {
        *self.running.lock().await
    }
}
