use std::io;
use log::{debug, error, info, warn};
use shadowsocks::config::Mode;
use shadowsocks_service::{
    config::Config,
    local::{
        context::ServiceContext,
        loadbalancing::PingBalancerBuilder,
        tun::{TunBuilder},
    },
};
use std::process::Command;
use std::sync::Arc;
use tokio::sync::Mutex;
use serde::{Deserialize, Serialize};
use shadowsocks::ServerAddr;
use windows_sys::Win32::NetworkManagement::IpHelper::{GetBestRoute, MIB_IPFORWARDROW};
use std::net::Ipv4Addr;

#[derive(Debug, Serialize, Deserialize)]
struct RouteState {
    default_gateway: String,
    interface_index: u32,
    metric: u32,
}

pub struct WindowsTunDevice {
    config: Config,
    tun_interface: Option<String>,
    running: Arc<Mutex<bool>>,
    original_routes: Arc<Mutex<Option<String>>>,
}

impl WindowsTunDevice {
    pub fn new(config: Config) -> io::Result<Self> {
        Ok(WindowsTunDevice {
            config,
            tun_interface: None,
            running: Arc::new(Mutex::new(false)),
            original_routes: Arc::new(Mutex::new(None)),
        })
    }

    async fn save_routing_state(&self) -> io::Result<RouteState> {
        // Get the best route to 0.0.0.0
        let mut forward_row: MIB_IPFORWARDROW = unsafe { std::mem::zeroed() };
        let destination = Ipv4Addr::new(0, 0, 0, 0);

        unsafe {
            let result = GetBestRoute(
                u32::from(destination),
                0,
                &mut forward_row,
            );

            if result != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed to get best route: {}", result)
                ));
            }
        }

        let gateway = Ipv4Addr::from(forward_row.dwForwardNextHop.to_be());

        Ok(RouteState {
            default_gateway: gateway.to_string(),
            interface_index: forward_row.dwForwardIfIndex,
            metric: forward_row.dwForwardMetric1,
        })
    }

    async fn configure_routing(&self, interface: &str) -> io::Result<()> {
        // Save current routing state
        let route_state = self.save_routing_state().await?;
        debug!("Saving route state: {:?}", route_state);
        *self.original_routes.lock().await = Some(serde_json::to_string(&route_state)?);

        // Delete existing default route
        let output = Command::new("route")
            .arg("DELETE")
            .arg("0.0.0.0")
            .arg("MASK")
            .arg("0.0.0.0")
            .output()?;

        if !output.status.success() {
            warn!("Failed to delete default route: {}",
                String::from_utf8_lossy(&output.stderr));
        }

        // Add new default route through TUN interface
        let add_output = Command::new("route")
            .arg("ADD")
            .arg("0.0.0.0")
            .arg("MASK")
            .arg("0.0.0.0")
            .arg(interface)
            .arg("METRIC")
            .arg("1")
            .output()?;

        if !add_output.status.success() {
            error!("Failed to add default route: {}",
                String::from_utf8_lossy(&add_output.stderr));
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Failed to add default route"
            ));
        }

        // Add bypass routes for shadowsocks servers
        self.add_bypass_routes(&route_state.default_gateway).await?;

        Ok(())
    }

    async fn add_bypass_routes(&self, default_gateway: &str) -> io::Result<()> {
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

            let output = Command::new("route")
                .arg("ADD")
                .arg(&server_addr)
                .arg("MASK")
                .arg("255.255.255.255")
                .arg(default_gateway)
                .output()?;

            if !output.status.success() {
                warn!("Failed to add bypass route for {}: {}",
                    server_addr,
                    String::from_utf8_lossy(&output.stderr));
            }
        }

        Ok(())
    }

    async fn restore_routing_state(&self) -> io::Result<()> {
        let route_state: RouteState = if let Some(saved_state) = self.original_routes.lock().await.as_ref() {
            serde_json::from_str(saved_state)?
        } else {
            return Err(io::Error::new(io::ErrorKind::Other, "No saved route state found"));
        };

        // Add back the original default route
        let output = Command::new("route")
            .arg("ADD")
            .arg("0.0.0.0")
            .arg("MASK")
            .arg("0.0.0.0")
            .arg(&route_state.default_gateway)
            .arg("METRIC")
            .arg(route_state.metric.to_string())
            .output()?;

        if !output.status.success() {
            error!("Failed to restore default route: {}",
                String::from_utf8_lossy(&output.stderr));
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Failed to restore default route"
            ));
        }

        Ok(())
    }

    pub async fn start(&mut self) -> io::Result<()> {
        if self.is_running().await {
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
        let builder = TunBuilder::new(context, balancer);

        // Build the TUN interface
        let tun = builder.build().await?;

        // Store the interface name
        if let Ok(name) = tun.interface_name() {
            self.tun_interface = Some(name.clone());
            // Configure routing
            self.configure_routing(&name).await?;
        }

        *self.running.lock().await = true;

        // Run the TUN device
        tokio::spawn(async move {
            if let Err(e) = tun.run().await {
                error!("TUN device error: {}", e);
            }
        });

        Ok(())
    }

    pub async fn stop(&self) -> io::Result<()> {
        if !self.is_running().await {
            return Ok(());
        }

        // Restore original routing state
        self.restore_routing_state().await?;

        *self.running.lock().await = false;
        Ok(())
    }

    pub async fn is_running(&self) -> bool {
        *self.running.lock().await
    }
}