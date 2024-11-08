//! A TCP listener for accepting shadowsocks' client connection

use std::{io, net::SocketAddr, sync::Arc};
use arc_swap::{ArcSwap, ArcSwapAny, ArcSwapOption, Guard};
use arc_swap::access::{Access, DynAccess};
use log::debug;
use once_cell::sync::Lazy;
use tokio::sync::RwLock;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use futures::executor::block_on;
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
    // user_manager: Option<ServerUserManager>,
    // user_manager_thing: Arc<ArcSwapAny<Arc<ArcSwap<ServerUserManager>>>>
    user_manager_thing: Arc<RwLock<ServerUserManager>>, // todo make this an ArcSwap!!! 
    // user_manager_thing: Arc<ArcSwapAny<Arc<ArcSwap<ServerUserManager>>>>
}


static DEFAULT_ACCEPT_OPTS: Lazy<AcceptOpts> = Lazy::new(Default::default);

impl ProxyListener {

    fn user_manager(self)-> Arc<ServerUserManager> {

        //todo this works with no ARC
        // --
        let so = ServerUserManager::default();
        let sso = ArcSwap::from(Arc::new(so));//Arc::new(ArcSwap::from_pointee(so));
        let st = sso.load();
        st.clone()

        // let ss:Arc<ServerUserManager> = self.user_manager_thing.load().clone();
        // let ss:Arc<ServerUserManager> = arc_swap::access::Access::load(&self.user_manager_thing);//.clone();
        // let ss:ServerUserManager = arc_swap::access::Access::load(&self.user_manager_thing);

        // let sss:ServerUserManager = *(ss.clone());
        // drop(ss);

        // ss


    }

    /// Create a `ProxyListener` binding to a specific address
    pub async fn bind(context: SharedContext, svr_cfg: &ServerConfig) -> io::Result<ProxyListener> {
        ProxyListener::bind_with_opts(context, svr_cfg, DEFAULT_ACCEPT_OPTS.clone()).await
    }

    pub fn listen_for_users(&mut self, mut user_manager_rcv: UnboundedReceiver<ServerUserManager>)
                            -> JoinHandle<()> {

        let um_in = Arc::clone(&self.user_manager_thing);

        tokio::spawn(async move {
            /*
              ********************************** todo  DO SOME MAGIC!!! ********************************
              todo just use an RW Lock!! get that working first
             */


            loop {
                let um = user_manager_rcv.recv().await;
                debug!("received config from remote {:?}", um);
                // um_in.store(Arc::new(um));

                match um {
                    Some(userMAN) => {
                        let um = userMAN;
                        debug!("<< write new user manager>>");
                        let s = *um_in.write().await = um;
                    }
                    None => {}
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
            // user_manager_thing: Arc::new(ArcSwap::from(ServerUserManager::default()))
            user_manager_thing: Arc::new(RwLock::from(ServerUserManager::default()))
            // user_manager: svr_cfg.box_user_manager(),
        }
    }

    // pub fn set_user_manager(&mut self, user_manager: Option<ServerUserManager>) {
    //     if let Some(user_manager) = user_manager {
    //         self.user_manager = Some(Box::new(user_manager));
    //     } else {
    //         self.user_manager = None;
    //     }
    // }

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
        //todo now I"M here!!
        // Create a ProxyServerStream and read the target address from it
        // let user_manager_pointer = match self.user_manager.clone() {
        //     Some( user_manager) => Some(&*user_manager.clone()),
        //     None => None
        // };

        let stream = ProxyServerStream::from_stream_with_user_manager(
            self.context.clone(),
            stream,
            self.method,
            &self.key,
            None,
            // Some(self.user_manager())
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
