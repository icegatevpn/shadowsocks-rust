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
use tokio::sync::{oneshot, Mutex};
use shadowsocks_rust::service::local;
use shadowsocks_rust::VERSION;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct RouteState {
    default_gateway: String,
    interface_metric: u32,
}

pub struct WindowsTunDevice {
    config: Option<Config>,
    tun_interface: Option<String>,
    running: Arc<Mutex<bool>>,
    original_state: Arc<Mutex<Option<RouteState>>>,
    tun_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    kill_switch: Option<oneshot::Sender<()>>
}

impl WindowsTunDevice {
    pub fn new() -> io::Result<Self> {
        Ok(WindowsTunDevice {
            config: None,
            tun_interface: None,
            running: Arc::default(),
            original_state: Arc::default(),
            tun_task: Mutex::default(),
            kill_switch: None
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

    async fn  configure_routing(&self, interface_name: &str) -> io::Result<()> {
        let mut config_interface_name: Option<String> = None;
        if let Some(config) = &self.config {
            let tun = config.local.iter().find(|l| {
                l.config.protocol == ProtocolType::Tun
                });
            if let Some(tun) = tun {
                config_interface_name = Some(tun.config.tun_interface_address.unwrap().hosts().nth(0).unwrap().to_string());
            }
        };


        // Save current routing state
        let state = self.save_route_state().await?;
        debug!("Saving route state: {:?}", state);
        *self.original_state.lock().await = Some(state.clone());

        // Add route for VPN server through physical interface's default gateway
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
                        // "-p", // Make route persistent
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
                // "-p", // Make route persistent
                "add",
                "0.0.0.0",
                "mask",
                "0.0.0.0",
                &config_interface_name.unwrap(),
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

                let _ = Command::new("route").args(["delete", &server_addr]).output()?;
            }
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

    pub async fn start(&mut self, config_str: String) -> io::Result<()> {
        if self.is_running().await {
            warn!("TUN device already running");
            return Ok(());
        }

        // Spawn the TUN device task
        let mut app = clap::Command::new("shadowsocks").version(VERSION);
        app = local::define_command_line_options(app);

        let matches = app.get_matches();

        // Create the local service runtime and future
        let (config, runtime, kill_switch, main_fut) = match local::create(&matches, Some(&config_str)) {
            Ok((cf, rt, ks, fut)) => (cf, rt, ks, fut),
            Err(err) => {
                error!("Failed to create Shadowsocks service: {}", err);
                return Err(io::Error::new(io::ErrorKind::Other, format!("Service creation error: {}", err)));
            }
        };
        self.kill_switch = Some(kill_switch);
        let running = self.running.clone();
        std::thread::spawn(move || {
            info!("Starting Shadowsocks service in background thread");

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

        if let Some(tun) = config.local.iter().find(|ff|{
            ff.config.protocol == ProtocolType::Tun
        }) {
            self.tun_interface = tun.config.tun_interface_name.clone();
            info!("Shadowsocks running on Tun {:?}...",self.tun_interface)
        }

        // Configure routing and Disable IPv6
        if let Some(interface) = &self.tun_interface {
            self.disable_ipv6_bindings().await?;
            self.configure_routing(interface).await?
        }
        Ok(())
    }

    pub async fn stop(&mut self) -> io::Result<()> {

        if let Some(shutdown_tx) = self.kill_switch.take() {
            _ = shutdown_tx.send(());
            info!("Shutdown signal sent to VPN task");
        }
        if let Some(state) = self.original_state.lock().await.as_ref() {
            self.restore_routing(state).await?;
            self.restore_ipv6().await?;
        }

        *self.running.lock().await = false;
        Ok(())
    }

    pub async fn is_running(&self) -> bool {
        *self.running.lock().await
    }
}
