//! Shadowsocks Local server serving on a Tun interface

use byte_string::ByteStr;
use cfg_if::cfg_if;
use ipnet::IpNet;
use log::{debug, error, info, trace, warn};
use shadowsocks::config::Mode;
use smoltcp::wire::{IpProtocol, TcpPacket, UdpPacket};
#[cfg(unix)]
use std::os::unix::io::RawFd;
use std::{
    io::{self, ErrorKind},
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc,
    time,
};

cfg_if! {
    if #[cfg(any(target_os = "ios",
                 target_os = "tvos",
                 target_os = "macos",
                 target_os = "linux",
                 target_os = "android",
                 target_os = "windows",
                 target_os = "freebsd"))] {
        use tun::{
            create_as_async, AsyncDevice, Configuration as TunConfiguration, AbstractDevice, Error as TunError, Layer,
        };
    } else {
        use tun::{AbstractDevice, Configuration as TunConfiguration, Error as TunError, Layer};

        mod fake_tun;
        use self::fake_tun::{create_as_async, AsyncDevice};
    }
}

use crate::local::{context::ServiceContext, loadbalancing::PingBalancer};

use self::{ip_packet::IpPacket, tcp::TcpTun, udp::UdpTun};

mod ip_packet;
mod tcp;
mod udp;
mod virt_device;

pub trait DeviceNetHelper: Send + Sync {
    fn address(&self) -> io::Result<IpAddr>;
    fn netmask(&self) -> io::Result<IpAddr>;
}
/// Basic implementation that stores static values
pub struct StaticDeviceNetHelper {
    address: IpAddr,
    netmask: IpAddr,
}

impl StaticDeviceNetHelper {
    pub fn new(address: IpAddr, netmask: IpAddr) -> Self {
        StaticDeviceNetHelper { address, netmask }
    }
}
impl DeviceNetHelper for StaticDeviceNetHelper {
    fn address(&self) -> io::Result<IpAddr> {
        Ok(self.address)
    }

    fn netmask(&self) -> io::Result<IpAddr> {
        Ok(self.netmask)
    }
}

/// Tun service builder
pub struct TunBuilder {
    context: Arc<ServiceContext>,
    balancer: PingBalancer,
    tun_config: TunConfiguration,
    udp_expiry_duration: Option<Duration>,
    udp_capacity: Option<usize>,
    net_helper: Option<Arc<dyn DeviceNetHelper>>,
    mode: Mode,
}

/// TunConfiguration contains a HANDLE, which is a *mut c_void on Windows.
unsafe impl Send for TunBuilder {}

impl TunBuilder {
    /// Create a Tun service builder
    pub fn new(context: Arc<ServiceContext>, balancer: PingBalancer) -> TunBuilder {
        TunBuilder {
            context,
            balancer,
            tun_config: TunConfiguration::default(),
            udp_expiry_duration: None,
            udp_capacity: None,
            net_helper: None,
            mode: Mode::TcpOnly,
        }
    }

    pub fn address(&mut self, addr: IpNet) {
        self.tun_config.address(addr.addr()).netmask(addr.netmask());
    }
    // Add method to set the network helper
    pub fn with_net_helper<H: DeviceNetHelper + 'static>(&mut self, helper: H) -> &mut Self {
        info!(
            " ****** net helper: {}: {}",
            helper.address().unwrap(),
            helper.netmask().unwrap()
        );
        self.net_helper = Some(Arc::new(helper));
        self
    }

    pub fn destination(&mut self, addr: IpNet) {
        self.tun_config.destination(addr.addr());
    }

    pub fn name(&mut self, name: &str) {
        self.tun_config.tun_name(name);
    }

    #[cfg(unix)]
    pub fn file_descriptor(&mut self, fd: RawFd) {
        self.tun_config.raw_fd(fd);
    }

    pub fn udp_expiry_duration(&mut self, udp_expiry_duration: Duration) {
        self.udp_expiry_duration = Some(udp_expiry_duration);
    }

    pub fn udp_capacity(&mut self, udp_capacity: usize) {
        self.udp_capacity = Some(udp_capacity);
    }

    pub fn mode(&mut self, mode: Mode) {
        self.mode = mode;
    }

    /// Build Tun server
    pub async fn build(mut self) -> io::Result<Tun> {
        self.tun_config.layer(Layer::L3).up();
        // XXX: tun2 set IFF_NO_PI by default.
        //
        // #[cfg(target_os = "linux")]
        // self.tun_config.platform_config(|tun_config| {
        //     // IFF_NO_PI preventing excessive buffer reallocating
        //     tun_config.packet_information(false);
        // });
        let device = match create_as_async(&self.tun_config) {
            Ok(d) => d,
            Err(TunError::Io(err)) => {
                error!("TunError::Io: {:?}", err);
                return Err(err);
            }
            Err(err) => {
                error!("error: {:?}", err);
                return Err(io::Error::new(ErrorKind::Other, err));
            }
        };
        let (udp, udp_cleanup_interval, udp_keepalive_rx) = UdpTun::new(
            self.context.clone(),
            self.balancer.clone(),
            self.udp_expiry_duration,
            self.udp_capacity,
        );
        let tcp = TcpTun::new(self.context, self.balancer, device.mtu().unwrap_or(1500) as u32);
        Ok(Tun {
            device,
            tcp,
            udp,
            udp_cleanup_interval,
            udp_keepalive_rx,
            mode: self.mode,
            net_helper: self.net_helper,
        })
    }
}

/// Tun service
pub struct Tun {
    device: AsyncDevice,
    net_helper: Option<Arc<dyn DeviceNetHelper>>,
    tcp: TcpTun,
    udp: UdpTun,
    udp_cleanup_interval: Duration,
    udp_keepalive_rx: mpsc::Receiver<SocketAddr>,
    mode: Mode,
}

impl Tun {
    /// Start serving
    pub fn interface_name(&self) -> io::Result<String> {
        self.device.tun_name().map_err(From::from)
    }

    pub async fn run(mut self) -> io::Result<()> {
        info!(
            "shadowsocks tun device {}, mode {}",
            self.interface_name().or_else(|r| Ok::<_, ()>(r.to_string())).unwrap(),
            self.mode,
        );

        let address = match self.device.address() {
            Ok(a) => a,
            Err(err) => {
                if let Some(helper) = &self.net_helper {
                    helper.address()?
                } else {
                    error!("[TUN] failed to get device address, error: {}", err);
                    return Err(io::Error::new(io::ErrorKind::Other, err));
                }
            }
        };

        let netmask = match self.device.netmask() {
            Ok(n) => n,
            Err(err) => {
                if let Some(helper) = &self.net_helper {
                    helper.netmask()?
                } else {
                    error!("[TUN] failed to get device netmask, error: {}", err);
                    return Err(io::Error::new(io::ErrorKind::Other, err));
                }
            }
        };

        let address_net = match IpNet::with_netmask(address, netmask) {
            Ok(n) => n,
            Err(err) => {
                error!("[TUN] invalid address {}, netmask {}, error: {}", address, netmask, err);
                return Err(io::Error::new(io::ErrorKind::Other, err));
            }
        };

        trace!(
            "[TUN] tun device network: {} (address: {}, netmask: {})",
            address_net,
            address,
            netmask
        );

        let address_broadcast = address_net.broadcast();

        let mut packet_buffer = vec![0u8; 65536].into_boxed_slice();
        let mut udp_cleanup_timer = time::interval(self.udp_cleanup_interval);

        loop {
            tokio::select! {
                // tun device
                read_result = async {
                    // let mut device = self.device.lock().await;
                    self.device.read(&mut packet_buffer).await
                } => {
                    let n = read_result?;
                    let packet = &mut packet_buffer[..n];
                    trace!("[TUN] received IP packet {:?}", ByteStr::new(packet));

                    if let Err(err) = self.handle_tun_frame(&address_broadcast, packet).await {
                        error!("[TUN] handle IP frame failed, error: {}", err);
                    }
                }

                // UDP channel sent back
                packet = self.udp.recv_packet() => {
                    // let mut device = self.device.lock().await;
                    match self.device.write(&packet).await {
                        Ok(n) => {
                            if n < packet.len() {
                                warn!("[TUN] sent IP packet (UDP), but truncated. sent {} < {}, {:?}",
                                      n, packet.len(), ByteStr::new(&packet));
                            } else {
                                trace!("[TUN] sent IP packet (UDP) {:?}", ByteStr::new(&packet));
                            }
                        }
                        Err(err) => {
                            error!("failed to write packet, error: {}", err);
                        }
                    }
                }

                // UDP cleanup expired associations
                _ = udp_cleanup_timer.tick() => {
                    self.udp.cleanup_expired().await;
                }

                // UDP keep-alive associations
                peer_addr_opt = self.udp_keepalive_rx.recv() => {
                    let peer_addr = peer_addr_opt.expect("UDP keep-alive channel closed unexpectly");
                    self.udp.keep_alive(&peer_addr).await;
                }

                // TCP channel sent back
                packet = self.tcp.recv_packet() => {
                    // let mut device = self.device.lock().await;
                    match self.device.write(&packet).await {
                        Ok(n) => {
                            if n < packet.len() {
                                warn!("[TUN] sent IP packet (TCP), but truncated. sent {} < {}, {:?}",
                                      n, packet.len(), ByteStr::new(&packet));
                            } else {
                                trace!("[TUN] sent IP packet (TCP) {:?}", ByteStr::new(&packet));
                            }
                        }
                        Err(err) => {
                            error!("failed to write packet, error: {}", err);
                        }
                    }
                }
            }
        }
    }

    async fn handle_tun_frame(&mut self, device_broadcast_addr: &IpAddr, frame: &[u8]) -> smoltcp::wire::Result<()> {
        let packet = match IpPacket::new_checked(frame)? {
            Some(packet) => packet,
            None => {
                warn!("unrecognized IP packet {:?}", ByteStr::new(frame));
                return Ok(());
            }
        };

        trace!("[TUN] {:?}", packet);

        let src_ip_addr = packet.src_addr();
        let dst_ip_addr = packet.dst_addr();
        let src_non_unicast = src_ip_addr == *device_broadcast_addr
            || match src_ip_addr {
                IpAddr::V4(v4) => v4.is_broadcast() || v4.is_multicast() || v4.is_unspecified(),
                IpAddr::V6(v6) => v6.is_multicast() || v6.is_unspecified(),
            };
        let dst_non_unicast = dst_ip_addr == *device_broadcast_addr
            || match dst_ip_addr {
                IpAddr::V4(v4) => v4.is_broadcast() || v4.is_multicast() || v4.is_unspecified(),
                IpAddr::V6(v6) => v6.is_multicast() || v6.is_unspecified(),
            };

        if src_non_unicast || dst_non_unicast {
            trace!(
                "[TUN] IP packet {} (unicast? {}) -> {} (unicast? {}) throwing away",
                src_ip_addr,
                !src_non_unicast,
                dst_ip_addr,
                !dst_non_unicast
            );
            return Ok(());
        }

        match packet.protocol() {
            IpProtocol::Tcp => {
                if !self.mode.enable_tcp() {
                    trace!("received TCP packet but mode is {}, throwing away", self.mode);
                    return Ok(());
                }

                let tcp_packet = match TcpPacket::new_checked(packet.payload()) {
                    Ok(p) => p,
                    Err(err) => {
                        error!(
                            "invalid TCP packet err: {}, src_ip: {}, dst_ip: {}, payload: {:?}",
                            err,
                            packet.src_addr(),
                            packet.dst_addr(),
                            ByteStr::new(packet.payload())
                        );
                        return Ok(());
                    }
                };

                let src_port = tcp_packet.src_port();
                let dst_port = tcp_packet.dst_port();

                let src_addr = SocketAddr::new(packet.src_addr(), src_port);
                let dst_addr = SocketAddr::new(packet.dst_addr(), dst_port);

                trace!(
                    "[TUN] TCP packet {} (unicast? {}) -> {} (unicast? {}) {}",
                    src_addr,
                    !src_non_unicast,
                    dst_addr,
                    !dst_non_unicast,
                    tcp_packet
                );

                // TCP first handshake packet.
                if let Err(err) = self.tcp.handle_packet(src_addr, dst_addr, &tcp_packet).await {
                    error!(
                        "handle TCP packet failed, error: {}, {} <-> {}, packet: {:?}",
                        err, src_addr, dst_addr, tcp_packet
                    );
                }

                self.tcp.drive_interface_state(frame).await;
            }
            IpProtocol::Udp => {
                if !self.mode.enable_udp() {
                    trace!("received UDP packet but mode is {}, throwing away", self.mode);
                    return Ok(());
                }

                let udp_packet = match UdpPacket::new_checked(packet.payload()) {
                    Ok(p) => p,
                    Err(err) => {
                        error!(
                            "invalid UDP packet err: {}, src_ip: {}, dst_ip: {}, payload: {:?}",
                            err,
                            packet.src_addr(),
                            packet.dst_addr(),
                            ByteStr::new(packet.payload())
                        );
                        return Ok(());
                    }
                };

                let src_port = udp_packet.src_port();
                let dst_port = udp_packet.dst_port();

                let src_addr = SocketAddr::new(src_ip_addr, src_port);
                let dst_addr = SocketAddr::new(packet.dst_addr(), dst_port);

                let payload = udp_packet.payload();
                trace!(
                    "[TUN] UDP packet {} (unicast? {}) -> {} (unicast? {}) {}",
                    src_addr,
                    !src_non_unicast,
                    dst_addr,
                    !dst_non_unicast,
                    udp_packet
                );

                if let Err(err) = self.udp.handle_packet(src_addr, dst_addr, payload).await {
                    error!("handle UDP packet failed, err: {}, packet: {:?}", err, udp_packet);
                }
            }
            IpProtocol::Icmp | IpProtocol::Icmpv6 => {
                // ICMP is handled by TCP's Interface.
                // smoltcp's interface will always send replies to EchoRequest
                self.tcp.drive_interface_state(frame).await;
            }
            _ => {
                debug!("IP packet ignored (protocol: {:?})", packet.protocol());
                return Ok(());
            }
        }

        Ok(())
    }
}
