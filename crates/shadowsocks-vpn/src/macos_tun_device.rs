use std::{io, ptr};
use std::sync::Arc;
use tokio::runtime::Runtime;
use tokio::sync::Mutex;
use log::{debug, error, info, warn};
use std::process::Command;
use std::net::Ipv4Addr;
use shadowsocks::config::Mode;
use shadowsocks_service::{
    config::{Config, ConfigType},
    local::{
        context::ServiceContext,
        loadbalancing::PingBalancerBuilder,
        tun::{TunBuilder, StaticDeviceNetHelper},
    },
};
use std::net::{IpAddr};
use tempfile::NamedTempFile;

const UTUN_CONTROL_NAME: &str = "com.apple.net.utun_control";

pub struct MacOSTunDevice {
    config: Config,
    tun_name: String,
    address: IpAddr,
    netmask: IpAddr,
    running: Arc<Mutex<bool>>,
    original_routes: Arc<Mutex<Option<String>>>,
}

impl MacOSTunDevice {
    pub fn new(config: Config, tun_name: &str, address: IpAddr, netmask: IpAddr) -> io::Result<Self> {

        Ok(MacOSTunDevice {
            config,
            tun_name: tun_name.to_string(),
            address,
            netmask,
            running: Arc::new(Mutex::new(false)),
            original_routes: Arc::new(Mutex::new(None)),
        })
    }

    pub async fn start(&self) -> io::Result<()> {
        let mut running = self.running.lock().await;
        if *running {
            warn!("TUN device already running");
            return Ok(());
        }

        // Create TUN interface using macOS specific command
        self.create_tun_interface().await?;

        // Configure IP address and routing
        self.configure_tun_interface().await?;

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
        builder.name(&self.tun_name);

        // Create network helper
        let net_helper = StaticDeviceNetHelper::new(self.address, self.netmask);
        builder.with_net_helper(net_helper);

        // Build and run TUN device
        let tun = builder.build().await?;

        *running = true;
        drop(running);

        // Run in background
        self.runtime.spawn(async move {
            if let Err(e) = tun.run().await {
                error!("TUN device error: {}", e);
            }
        });

        Ok(())
    }

    /// Save current routing table state
    async fn save_routing_state(&self) -> io::Result<String> {
        let output = Command::new("netstat")
            .arg("-rn")
            .output()?;

        if !output.status.success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Failed to save routing state",
            ));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    async fn create_tun_interface(&self) -> io::Result<()> {
        // Create utun interface using macOS networksetup command
        let output = Command::new("networksetup")
            .arg("-createnetworkservice")
            .arg(&self.tun_name)
            .arg(UTUN_CONTROL_NAME)
            .output()?;

        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to create TUN interface: {}", error),
            ));
        }

        Ok(())
    }

    /// Validate that a route belongs to our TUN interface
    fn validate_route_ownership(&self, route: &str) -> bool {
        // Only delete routes that explicitly mention our TUN interface
        route.contains(&self.tun_name)
    }

    async fn configure_tun_interface(&self) -> io::Result<()> {
        // Save current routing state before making changes
        let original_routes = self.save_routing_state().await?;

        // Store original state in struct for recovery if needed
        self.original_routes.lock().await.replace(original_routes);

        // Configure IP address
        let output = Command::new("ifconfig")
            .arg(&self.tun_name)
            .arg("inet")
            .arg(self.address.to_string())
            .arg(self.netmask.to_string())
            .output()?;

        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to configure TUN interface: {}", error),
            ));
        }

        // Enable interface
        let output = Command::new("ifconfig")
            .arg(&self.tun_name)
            .arg("up")
            .output()?;

        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to enable TUN interface: {}", error),
            ));
        }

        // Add default route through TUN interface
        let output = Command::new("route")
            .arg("add")
            .arg("-net")
            .arg("0.0.0.0/1")
            .arg("-interface")
            .arg(&self.tun_name)
            .output()?;

        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to add route: {}", error),
            ));
        }

        Ok(())
    }

    async fn restore_routing_state(&self) -> io::Result<()> {
        // First, remove our specific routes to ensure clean state
        let routes_to_remove = [
            ("128.0.0.0", "128.0.0.0"),
            ("0.0.0.0", "127.255.255.255"),
        ];

        for (net, mask) in routes_to_remove.iter() {
            // Only remove if the route exists and belongs to our interface
            let check_output = Command::new("netstat")
                .arg("-rn")
                .output()?;

            if check_output.status.success() {
                let route_table = String::from_utf8_lossy(&check_output.stdout);
                if self.validate_route_ownership(&route_table) {
                    let output = Command::new("route")
                        .arg("-n")
                        .arg("delete")
                        .arg("-net")
                        .arg(net)
                        .arg("-netmask")
                        .arg(mask)
                        .arg("-interface")
                        .arg(&self.tun_name)
                        .output()?;

                    if !output.status.success() {
                        warn!(
                            "Failed to remove route {}/{}: {}",
                            net,
                            mask,
                            String::from_utf8_lossy(&output.stderr)
                        );
                    }
                }
            }
        }

        // Now restore the original routing table from our saved state
        if let Some(original_routes) = self.original_routes.lock().await.as_ref() {
            // Create a temporary file to store the original routing table
            let temp_file = tempfile::NamedTempFile::new()?;
            std::fs::write(temp_file.path(), original_routes)?;

            // Use route restore command to restore the original routing table
            let output = Command::new("route")
                .arg("-n")
                .arg("restore")
                .arg(temp_file.path())
                .output()?;

            if !output.status.success() {
                let error = String::from_utf8_lossy(&output.stderr);
                warn!("Failed to restore original routing table: {}", error);
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed to restore original routing table: {}", error),
                ));
            }
        } else {
            warn!("No original routing state found to restore");
        }

        Ok(())
    }

    pub async fn stop(&self) -> io::Result<()> {
        let mut running = self.running.lock().await;
        if !*running {
            return Ok(());
        }

        // Restore original routing state
        if let Err(e) = self.restore_routing_state().await {
            warn!("Failed to restore routing state: {}", e);
        }

        // Delete TUN interface
        let output = Command::new("networksetup")
            .arg("-removenetworkservice")
            .arg(&self.tun_name)
            .output()?;

        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to remove TUN interface: {}", error),
            ));
        }

        *running = false;
        Ok(())
    }

    pub async fn is_running(&self) -> bool {
        *self.running.lock().await
    }
}

impl Drop for MacOSTunDevice {
    fn drop(&mut self) {
        // Ensure cleanup on drop
        let runtime = Runtime::new().unwrap();
        runtime.block_on(self.stop()).ok();
    }
}