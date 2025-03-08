//! A TCP listener for accepting shadowsocks' client connection

use std::{io, net::SocketAddr, sync::Arc};
use arc_swap::{ArcSwap, ArcSwapAny};
use log::{debug};
use once_cell::sync::Lazy;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::task::JoinHandle;
use crate::{
    config::{ServerAddr, ServerConfig, ServerUserManager},
    context::SharedContext,
    crypto::CipherKind,
    net::{AcceptOpts, TcpListener},
    relay::tcprelay::proxy_stream::server::ProxyServerStream,
};

/// A TCP listener for accepting shadowsocks' client connection
#[derive(Debug)]
pub struct ProxyListener {
    listener: TcpListener,
    method: CipherKind,
    key: Box<[u8]>,
    context: SharedContext,
    // user_manager_thing: Arc<RwLock<ServerUserManager>>, // todo make this an ArcSwap!!!
    user_manager_fancy: Arc<ArcSwapAny<Arc<ServerUserManager>>>,
}

static DEFAULT_ACCEPT_OPTS: Lazy<AcceptOpts> = Lazy::new(Default::default);

impl ProxyListener {


    /// Create a `ProxyListener` binding to a specific address
    pub async fn bind(context: SharedContext, svr_cfg: &ServerConfig) -> io::Result<ProxyListener> {
        ProxyListener::bind_with_opts(context, svr_cfg, DEFAULT_ACCEPT_OPTS.clone()).await
    }

    pub fn listen_for_users(&self, mut user_manager_rcv: UnboundedReceiver<ServerUserManager>)
                            -> JoinHandle<()> {
        let um_in = Arc::clone(&self.user_manager_fancy);
        tokio::spawn(async move {
            debug!("Receiving Config....");
            loop {
                let um = user_manager_rcv.recv().await;
                if let Some(um) = um {
                    debug!("TCP Received config from remote ...");
                    um_in.store(Arc::new(um));
                }
            }
        })
    }

    /// Create a `ProxyListener` binding to a specific address with opts
    pub async fn bind_with_opts(
        context: SharedContext,
        svr_cfg: &ServerConfig,
        accept_opts: AcceptOpts,
    ) -> io::Result<ProxyListener> {
        let listener = match svr_cfg.tcp_external_addr() {
            ServerAddr::SocketAddr(sa) => TcpListener::bind_with_opts(sa, accept_opts).await?,
            ServerAddr::DomainName(domain, port) => {
                lookup_then!(&context, domain, *port, |addr| {
                    TcpListener::bind_with_opts(&addr, accept_opts.clone()).await
                })?
                .1
            }
        };
        Ok(ProxyListener::from_listener(context, listener, svr_cfg))
    }

    /// Create a `ProxyListener` from a `TcpListener`
    pub fn from_listener(context: SharedContext, listener: TcpListener, svr_cfg: &ServerConfig) -> ProxyListener {
        ProxyListener {
            listener,
            method: svr_cfg.method(),
            key: svr_cfg.key().to_vec().into_boxed_slice(),
            context,
            // user_manager_thing: Arc::new(RwLock::from(ServerUserManager::default()))
            user_manager_fancy: Arc::new(ArcSwap::new(Arc::new(ServerUserManager::default())))
        }
    }

    /// Accepts a shadowsocks' client connection
    #[inline]
    pub async fn accept(&self) -> io::Result<(ProxyServerStream<TcpStream>, SocketAddr)> {
        self.accept_map(|s| s).await
    }

    /// Accepts a shadowsocks' client connection and maps the accepted `TcpStream` to another stream type
    pub async fn accept_map<F, S>(&self, map_fn: F) -> io::Result<(ProxyServerStream<S>, SocketAddr)>
    where
        F: FnOnce(TcpStream) -> S,
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let (stream, peer_addr) = self.listener.accept().await?;
        let stream = map_fn(stream);
        let stream = ProxyServerStream::from_stream_with_user_manager(
            self.context.clone(),
            stream,
            self.method,
            &self.key,
            Some(self.user_manager_fancy.clone())
        );

        Ok((stream, peer_addr))
    }

    /// Get local binded address
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Get reference to the internal listener
    pub fn get_ref(&self) -> &TcpListener {
        &self.listener
    }

    /// Consumes the `ProxyListener` and return the internal listener
    pub fn into_inner(self) -> TcpListener {
        self.listener
    }
}
