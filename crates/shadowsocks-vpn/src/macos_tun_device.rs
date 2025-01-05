use log::{debug, error, info, warn};
use std::io::Write;
use std::process::Command;
use std::sync::Arc;
use std::{io, ptr};
use tokio::sync::Mutex;
use shadowsocks::config::Mode;
use shadowsocks_service::{
    config::{Config, ConfigType},
    local::{
        context::ServiceContext,
        loadbalancing::PingBalancerBuilder,
        tun::{StaticDeviceNetHelper, TunBuilder},
    },
    shadowsocks::config::ServerAddr,
};
use std::net::IpAddr;
use tempfile::NamedTempFile;

use nix::libc;

use nix::fcntl::{fcntl, FcntlArg};
use nix::libc::{connect, AF_SYSTEM, AF_SYS_CONTROL};
use nix::sys::socket::{socket, AddressFamily, SockFlag, SockProtocol, SockType};
use nix::unistd::close;
use std::ffi::CString;
use std::fmt::format;
use std::os::fd::{AsRawFd, RawFd};
use std::time::Duration;
use tokio::time::sleep;

const UTUN_CONTROL_NAME: &str = "com.apple.net.utun_control";
const INTERFACE_WAIT_TIMEOUT: Duration = Duration::from_secs(10); // Increased timeout
const INTERFACE_POLL_INTERVAL: Duration = Duration::from_millis(100);

pub struct MacOSTunDevice {
    config: Config,
    tun_name: Option<String>,
    fd: Option<RawFd>,
    address: IpAddr,
    netmask: IpAddr,
    running: Arc<Mutex<bool>>,
    original_routes: Arc<Mutex<Option<String>>>,
}

#[repr(C)]
#[derive(Debug)]
struct SockaddrCtl {
    sc_len: u8,
    sc_family: u8,
    ss_sysaddr: u16,
    sc_id: u32,
    sc_unit: u32,
    sc_reserved: [u32; 5],
}
const MAX_PATH_LEN: usize = 4096;


impl MacOSTunDevice {
    fn new_tune_name(&self) -> String {
        self.tun_name.clone().unwrap_or("none".to_string())
    }
    pub fn new(config: Config, address: IpAddr, netmask: IpAddr) -> io::Result<Self> {
        Ok(MacOSTunDevice {
            config,
            tun_name: None,
            fd: None,
            address,
            netmask,
            running: Arc::new(Mutex::new(false)),
            original_routes: Arc::new(Mutex::new(None)),
        })
    }

    pub async fn start(&mut self) -> io::Result<()> {
        let mut running = self.running.lock().await;
        if *running {
            warn!("TUN device already running");
            return Ok(());
        }

        // Create TUN interface using macOS specific command
        let raw_fd = self.create_tun_interface().await?;
        self.tun_name = Some(format!("utun{}", raw_fd.1));

        debug!("created interface {:?}", self.tun_name);
        // return Err(io::Error::new(io::ErrorKind::Other, format!("Done")));

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
        builder.file_descriptor(raw_fd.0);
        // todo, do I need to set the builder address??
        // builder.address(self.address)

        // Create network helper
        let net_helper = StaticDeviceNetHelper::new(self.address, self.netmask);
        builder.with_net_helper(net_helper);

        // Build and run TUN device
        let tun = builder.build().await?;

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
    
    async fn create_tun_interface(&self) -> io::Result<(RawFd, u32)> {
        // Try a range of unit numbers in case some are already in use
        for unit in 4..20 {
            let sock = socket(
                AddressFamily::System,
                SockType::Datagram,
                SockFlag::empty(),
                SockProtocol::KextControl,
            )?;

            debug!("Socket created: {:?}", sock);
            let raw_fd = sock.as_raw_fd();
            // Set non-blocking mode for the socket
            unsafe {
                let flags = libc::fcntl(raw_fd, libc::F_GETFL);
                if flags < 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::fcntl(raw_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }

            // Set up control name
            let mut ctl_info = libc::ctl_info {
                ctl_id: 0,
                ctl_name: [0; libc::MAX_KCTL_NAME as usize],
            };

            let name = CString::new(UTUN_CONTROL_NAME).expect("CString::new failed");
            for (i, &byte) in name.as_bytes_with_nul().iter().enumerate() {
                ctl_info.ctl_name[i] = byte as libc::c_char;
            }

            // Get control ID
            unsafe {
                if libc::ioctl(raw_fd, libc::CTLIOCGINFO, &mut ctl_info) < 0 {
                    let err = io::Error::last_os_error();
                    error!("Failed to get control ID: {}", err);
                    continue; // Try next unit
                }
            }

            debug!("Control ID obtained for unit {}: {} {}", unit, raw_fd, ctl_info.ctl_id);

            // Try to bind the interface
            match self.bind_utun_interface(raw_fd, ctl_info.ctl_id, unit) {
                Ok(_) => {
                    // Successfully bound, now wait for interface
                    match self.wait_for_interface(&format!("utun{}",unit)).await {
                        Ok(_) => {
                            info!("Successfully created and verified interface utun{}", unit);
                            return Ok((raw_fd, unit));
                        }
                        Err(e) => {
                            warn!("Interface creation succeeded but verification failed for utun{}: {}", unit, e);
                            continue; // Try next unit
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to bind utun{}: {}", unit, e);
                    continue; // Try next unit
                }
            }
        }

        Err(io::Error::new(
            io::ErrorKind::Other,
            "Failed to create TUN interface after trying all available units",
        ))
    }

    fn bind_utun_interface(&self, fd: RawFd, ctl_id: u32, unit: u32) -> io::Result<()> {
        let addr = SockaddrCtl {
            sc_len: std::mem::size_of::<SockaddrCtl>() as u8,
            sc_family: AF_SYSTEM as u8,
            ss_sysaddr: AF_SYS_CONTROL as u16,
            sc_id: ctl_id,
            sc_unit: unit,
            sc_reserved: [0; 5],
        };

        debug!("binding utun interface to {:?}", addr);

        let addr_ptr = &addr as *const SockaddrCtl as *const libc::sockaddr;
        let addr_len = std::mem::size_of::<SockaddrCtl>() as libc::socklen_t;

        let ret = unsafe {
            libc::connect(fd, addr_ptr, addr_len)
        };

        if ret < 0 {
            let err = io::Error::last_os_error();
            error!("Failed to bind utun interface: {}", err);
            return Err(err);
        }

        // Set socket to blocking mode again after connection
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            if flags < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK) < 0 {
                return Err(io::Error::last_os_error());
            }
        }

        info!("TUN interface created: utun{}", unit);
        Ok(())
    }

    async fn wait_for_interface(&self, iface_name:&str) -> io::Result<()> {
        // let interface_name = self.new_tune_name();
        let start = std::time::Instant::now();
        let mut last_error = String::new();

        while start.elapsed() < INTERFACE_WAIT_TIMEOUT {
            match Command::new("ifconfig")
                .arg(&iface_name)
                .output()
            {
                Ok(output) => {
                    if output.status.success() {
                        // Additional verification - check if interface exists in the routing table
                        if let Ok(route_output) = Command::new("route")
                            .arg("get")
                            .arg(&iface_name)
                            .output()
                        {
                            if route_output.status.success() {
                                debug!("Interface {} is ready and routable", iface_name);
                                return Ok(());
                            }
                        }
                    }
                    last_error = String::from_utf8_lossy(&output.stderr).to_string();
                }
                Err(e) => {
                    last_error = e.to_string();
                }
            }

            sleep(INTERFACE_POLL_INTERVAL).await;
        }

        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("Timeout waiting for interface {} to be ready. Last error: {}", iface_name, last_error)
        ))
    }

    /// Save current routing table state
    async fn save_routing_state(&self) -> io::Result<String> {
        let output = Command::new("netstat").arg("-rn").output()?;

        if !output.status.success() {
            return Err(io::Error::new(io::ErrorKind::Other, "Failed to save routing state"));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Validate that a route belongs to our TUN interface
    fn validate_route_ownership(&self, route: &str) -> bool {
        let tname = self.new_tune_name();
        route.contains(&tname)
    }

    async fn add_bypass_route_for_server(&self) -> io::Result<()> {
        // Get the current default gateway first
        let netstat_output = Command::new("netstat").arg("-nr").output()?;

        let output = String::from_utf8_lossy(&netstat_output.stdout);
        let default_gateway = output
            .lines()
            .find(|line| line.contains("default"))
            .and_then(|line| line.split_whitespace().nth(1))
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Could not find default gateway"))?;

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
                .arg("-host")  // Single host route for server
                .arg(&server_addr)
                .arg("-gateway")
                .arg(default_gateway)  // Route through system's default gateway
                .output()?;

            if !output.status.success() {
                let error = String::from_utf8_lossy(&output.stderr);
                warn!("Failed to add server bypass route for {}: {}", server_addr, error);
            }
        }

        Ok(())
    }

    async fn configure_tun_interface(&self) -> io::Result<()> {
        // Save current routing state before making changes
        let original_routes = self.save_routing_state().await?;

        // Store original state in struct for recovery if needed
        *self.original_routes.lock().await = Some(original_routes);
        // self.original_routes.lock().await.replace(original_routes);

        // Configure IP address
        let output = Command::new("ifconfig")
            .arg(self.new_tune_name())
            .arg("inet")
            .arg(self.address.to_string())
            .arg(self.netmask.to_string())
            .arg("up")
            .output()?;

        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            error!("Failed to configure interface: {}", error);
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to configure TUN interface: {}", error),
            ));
        }

        // Verify interface is up
        let status = Command::new("ifconfig")
            .arg(&self.new_tune_name())
            .output()?;

        if !status.status.success() {
            error!("Interface configuration verification failed");
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Interface verification failed"
            ));
        }
        debug!("Interface configured successfully: {}", String::from_utf8_lossy(&status.stdout));

        // Configure routing
        self.configure_routing().await?;

        Ok(())
    }
    async fn configure_routing(&self) -> io::Result<()> {

        // Add default route through TUN interface
        let output = Command::new("route")
            .arg("-n")  // Use numeric addresses only
            .arg("add")
            .arg("-net")
            .arg("0.0.0.0/0")  // All traffic
            .arg("-interface")
            .arg(&self.new_tune_name())
            .output()?;

        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            error!("Failed to add default route: {}", error);
            self.restore_routing_state().await?;
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to add route: {}", error),
            ));
        }

        // Add specific route for localhost to bypass VPN
        let output = Command::new("route")
            .arg("-n")
            .arg("add")
            .arg("-net")
            .arg("127.0.0.0/8")  // Localhost range
            .arg("-gateway")
            .arg("127.0.0.1")    // Direct to loopback
            .output()?;

        if !output.status.success() {
            warn!(
                "Failed to add localhost bypass route: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        // Add bypass routes for shadowsocks servers
        if let Err(e) = self.add_bypass_route_for_server().await {
            warn!("Failed to add bypass routes for servers: {}", e);
        }

        Ok(())
    }

    async fn restore_routing_state(&self) -> io::Result<()> {
        // Remove the default route through our TUN interface
        let check_output = Command::new("netstat").arg("-rn").output()?;

        if check_output.status.success() {
            let route_table = String::from_utf8_lossy(&check_output.stdout);
            if self.validate_route_ownership(&route_table) {
                // Remove the default route
                let output = Command::new("route")
                    .arg("-n")
                    .arg("delete")
                    .arg("-net")
                    .arg("0.0.0.0/0")
                    .arg("-interface")
                    .arg(self.new_tune_name())
                    .output()?;

                if !output.status.success() {
                    warn!(
                        "Failed to remove default route: {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
            }
        }

        // Remove the localhost bypass route if it exists
        let output = Command::new("route")
            .arg("-n")
            .arg("delete")
            .arg("-net")
            .arg("127.0.0.0/8")
            .output()?;

        if !output.status.success() {
            warn!(
                "Failed to remove localhost bypass route: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        // Remove server bypass routes
        for server in &self.config.server {
            let server_addr = match server.config.addr() {
                ServerAddr::SocketAddr(addr) => addr.ip().to_string(),
                ServerAddr::DomainName(domain, _) => {
                    // Try to resolve the domain
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

            if !output.status.success() {
                warn!(
                    "Failed to remove bypass route for server {}: {}",
                    server_addr,
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }

        // Now restore the original routing table from our saved state
        if let Some(original_routes) = self.original_routes.lock().await.as_ref() {
            // Create a temporary file to store the original routing table
            let temp_file = NamedTempFile::new()?;
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

    pub async fn stop_and_cleanup(&self) -> io::Result<()> {
        debug!("Stopping TUN");
        let mut running = self.running.lock().await;
        if !*running {
            return Ok(());
        }

        // Restore original routing state
        if let Err(e) = self.restore_routing_state().await {
            warn!("Failed to restore routing state: {}", e);
        }

        // Delete TUN interface
        // todo, not sure if I need to do this either.
        // let output = Command::new("networksetup")
        //     .arg("-removenetworkservice")
        //     .arg(&self.tun_name)
        //     .output()?;
        //
        // if !output.status.success() {
        //     let error = String::from_utf8_lossy(&output.stderr);
        //     return Err(io::Error::new(
        //         io::ErrorKind::Other,
        //         format!("Failed to remove TUN interface: {}", error),
        //     ));
        // }

        // Close the socket
        // todo, not sure I need to do this, is appears to close itself when it's out of scope
        // if let Err(e) = close(raw_fd) {
        //     warn!("Trouble Closing utun interface: {}", e);
        // } else {
        //     debug!("Closed utun{} interface.", raw_fd);
        // }

        *running = false;
        Ok(())
    }

    pub async fn is_running(&self) -> bool {
        *self.running.lock().await
    }
}
