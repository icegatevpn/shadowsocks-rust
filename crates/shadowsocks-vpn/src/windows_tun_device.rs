use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use shadowsocks::config::Mode;
use shadowsocks::ServerAddr;
use shadowsocks_service::config::ProtocolType;
use shadowsocks_service::{
    config::Config,
    local::{context::ServiceContext, loadbalancing::PingBalancerBuilder, tun::TunBuilder},
};
use std::io;
use std::process::Command;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct RouteState {
    default_gateway: String,
    interface_metric: u32,
}

pub struct WindowsTunDevice {
    config: Config,
    tun_interface: Option<String>,
    running: Arc<Mutex<bool>>,
    original_state: Arc<Mutex<Option<RouteState>>>,
    tun_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl WindowsTunDevice {
    pub fn new(config: Config) -> io::Result<Self> {
        Ok(WindowsTunDevice {
            config,
            tun_interface: None,
            running: Arc::default(),
            original_state: Arc::default(),
            tun_task: Mutex::default(),
        })
    }

    async fn save_route_state(&self) -> io::Result<RouteState> {
        // Get current default gateway
        let output = Command::new("route").args(["print", "0.0.0.0"]).output()?;

        let output_str = String::from_utf8_lossy(&output.stdout);
        let mut default_gateway = String::new();
        let mut interface_metric = 0;

        for line in output_str.lines() {
            if line.contains("0.0.0.0") && line.contains("0.0.0.0") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    default_gateway = parts[2].to_string();
                    if parts.len() >= 5 {
                        interface_metric = parts[4].parse().unwrap_or(0);
                    }
                    break;
                }
            }
        }

        if default_gateway.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "Could not find default gateway",
            ));
        }

        Ok(RouteState {
            default_gateway,
            interface_metric,
        })
    }

    async fn disable_ipv6_bindings(&self) -> io::Result<()> {
        debug!("Disabling IPv6 bindings on all interfaces");

        // Disable IPv6 binding on all network adapters
        let output = Command::new("powershell")
            .args([
                "-Command",
                "Get-NetAdapter | ForEach-Object { Disable-NetAdapterBinding -Name $_.Name -ComponentID 'ms_tcpip6' }",
            ])
            .output()?;

        if !output.status.success() {
            warn!(
                "Failed to disable IPv6 bindings: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        // Disable IPv6 transition technologies
        let _ = Command::new("netsh")
            .args(["interface", "ipv6", "set", "teredo", "disabled"])
            .output()?;

        let _ = Command::new("netsh")
            .args(["interface", "ipv6", "set", "interface", "*", "routerdiscovery=disabled"])
            .output()?;

        // Set IPv6 preference to IPv4
        let output = Command::new("reg")
            .args([
                "add",
                "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters",
                "/v",
                "DisabledComponents",
                "/t",
                "REG_DWORD",
                "/d",
                "0xFF", // Disable all IPv6 components
                "/f",
            ])
            .output()?;

        if !output.status.success() {
            warn!(
                "Failed to set IPv6 registry key: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        Ok(())
    }

    async fn configure_routing(&self, interface_name: &str) -> io::Result<()> {
        // Save current routing state
        let state = self.save_route_state().await?;
        debug!("Saving route state: {:?}", state);
        *self.original_state.lock().await = Some(state.clone());

        // Add route for VPN server through physical interface's default gateway
        for server in &self.config.server {
            let server_addr = match server.config.addr() {
                ServerAddr::SocketAddr(addr) => addr.ip().to_string(),
                ServerAddr::DomainName(domain, _) => {
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
                "Adding route for VPN server {} via {}",
                server_addr, state.default_gateway
            );

            // Delete any existing routes for VPN server
            let _ = Command::new("route").args(["delete", &server_addr]).output()?;

            // Add route for VPN server
            let output = Command::new("route")
                .args([
                    "-p", // Make route persistent
                    "add",
                    &server_addr,
                    "mask",
                    "255.255.255.255",
                    &state.default_gateway,
                    "metric",
                    "1",
                ])
                .output()?;

            if !output.status.success() {
                warn!(
                    "Failed to add route for VPN server: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }

        // Delete existing default route
        debug!("Deleting existing default route");
        let _ = Command::new("route")
            .args(["delete", "0.0.0.0", "mask", "0.0.0.0"])
            .output()?;

        // Add new default route through TUN interface
        debug!("Adding new default route via TUN interface");
        let output = Command::new("route")
            .args([
                "-p", // Make route persistent
                "add",
                "0.0.0.0",
                "mask",
                "0.0.0.0",
                "10.10.0.1", // TUN interface IP
                "metric",
                "1",
            ])
            .output()?;

        if !output.status.success() {
            error!(
                "Failed to add default route: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            return Err(io::Error::new(io::ErrorKind::Other, "Failed to add default route"));
        }

        // Verify the routing configuration
        let output = Command::new("route").arg("print").output()?;
        debug!("Final routing table:\n{}", String::from_utf8_lossy(&output.stdout));

        Ok(())
    }

    async fn restore_routing(&self, state: &RouteState) -> io::Result<()> {
        debug!("Restoring original routing configuration");

        // Delete our default route
        let _ = Command::new("route")
            .args(["delete", "0.0.0.0", "mask", "0.0.0.0"])
            .output()?;

        // Restore original default route
        let output = Command::new("route")
            .args([
                "-p",
                "add",
                "0.0.0.0",
                "mask",
                "0.0.0.0",
                &state.default_gateway,
                "metric",
                &state.interface_metric.to_string(),
            ])
            .output()?;

        if !output.status.success() {
            warn!(
                "Failed to restore default route: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        // Remove any persistent routes we added
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

            let _ = Command::new("route").args(["delete", &server_addr]).output()?;
        }

        Ok(())
    }

    async fn restore_ipv6(&self) -> io::Result<()> {
        debug!("Restoring IPv6 configuration");

        // Re-enable IPv6 bindings
        let output = Command::new("powershell")
            .args([
                "-Command",
                "Get-NetAdapter | ForEach-Object { Enable-NetAdapterBinding -Name $_.Name -ComponentID 'ms_tcpip6' }",
            ])
            .output()?;

        if !output.status.success() {
            warn!(
                "Failed to re-enable IPv6 bindings: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        // Reset IPv6 configuration
        let output = Command::new("reg")
            .args([
                "add",
                "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters",
                "/v",
                "DisabledComponents",
                "/t",
                "REG_DWORD",
                "/d",
                "0x0",
                "/f",
            ])
            .output()?;

        if !output.status.success() {
            warn!(
                "Failed to restore IPv6 registry settings: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        Ok(())
    }

    pub async fn start(&mut self) -> io::Result<()> {
        if self.is_running().await {
            warn!("TUN device already running");
            return Ok(());
        }

        // Get the TUN configuration from the locals
        let tun_config = self
            .config
            .local
            .iter()
            .find(|local| local.config.protocol == ProtocolType::Tun)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "No TUN configuration found in config"))?;

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

        // Configure the TUN interface based on the config
        if let Some(name) = &tun_config.config.tun_interface_name {
            builder.name(name);
        }

        if let Some(address) = &tun_config.config.tun_interface_address {
            builder.address(*address);
        }

        if let Some(destination) = &tun_config.config.tun_interface_destination {
            builder.destination(*destination);
        }

        builder.mode(tun_config.config.mode);

        // Build the TUN interface
        let tun = builder.build().await?;

        // Store the interface name
        if let Ok(name) = tun.interface_name() {
            self.tun_interface = Some(name.clone());

            // Disable IPv6
            self.disable_ipv6_bindings().await?;

            // Configure routing
            self.configure_routing(&name).await?;
        }

        *self.running.lock().await = true;

        // Run the TUN device
        let task = tokio::spawn(async move {
            if let Err(e) = tun.run().await {
                error!("TUN device error: {}", e);
            }
            println!("tun finish");
        });
        *self.tun_task.lock().await = Some(task);
        Ok(())
    }

    pub async fn stop(&self) -> io::Result<()> {
        if !self.is_running().await {
            return Ok(());
        }
        if let Some(task) = self.tun_task.lock().await.as_ref() {
            task.abort();
        }
        if let Some(state) = self.original_state.lock().await.as_ref() {
            // Restore routing first
            self.restore_routing(state).await?;

            // Then restore IPv6
            self.restore_ipv6().await?;
        }

        *self.running.lock().await = false;
        Ok(())
    }

    pub async fn is_running(&self) -> bool {
        *self.running.lock().await
    }
}
