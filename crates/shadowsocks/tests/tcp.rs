use std::{io::{self}, net::SocketAddr, sync::Arc, thread};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use arc_swap::ArcSwap;
use byte_string::ByteStr;
use futures::future;
use log::info;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::Barrier,
};

use shadowsocks::{
    config::{ServerConfig, ServerType},
    context::Context,
    crypto::CipherKind,
    relay::{
        socks5::Address,
        tcprelay::{
            proxy_stream::ProxyServerStream,
            utils::{copy_from_encrypted, copy_to_encrypted},
        },
    },
    ProxyClientStream, ProxyListener,
};

async fn handle_tcp_tunnel_server_client(
    method: CipherKind,
    mut stream: ProxyServerStream<TcpStream>,
) -> io::Result<()> {
    let addr = stream.handshake().await?;

    let mut remote = {
        let remote = match addr {
            Address::SocketAddress(ref sa) => TcpStream::connect(sa).await?,
            Address::DomainNameAddress(ref dname, port) => TcpStream::connect((dname.as_str(), port)).await?,
        };

        info!("connected to remote {}", addr);
        remote
    };

    let (mut sr, mut sw) = tokio::io::split(stream);
    let (mut mr, mut mw) = remote.split();

    let l2r = copy_from_encrypted(method, &mut sr, &mut mw);
    let r2l = copy_to_encrypted(method, &mut mr, &mut sw);

    tokio::pin!(l2r);
    tokio::pin!(r2l);

    let _ = future::select(l2r, r2l).await;

    info!("TCP tunnel server finished");

    Ok(())
}

async fn handle_tcp_tunnel_local_client(
    context: Arc<Context>,
    svr_cfg: Arc<ServerConfig>,
    mut stream: TcpStream,
) -> io::Result<()> {
    let target_addr = Address::from(("www.example.com".to_owned(), 80));

    let remote = ProxyClientStream::connect(context, &svr_cfg, target_addr).await?;

    let (mut lr, mut lw) = stream.split();
    let (mut sr, mut sw) = tokio::io::split(remote);

    let l2s = copy_to_encrypted(svr_cfg.method(), &mut lr, &mut sw);
    let s2l = copy_from_encrypted(svr_cfg.method(), &mut sr, &mut lw);

    tokio::pin!(l2s);
    tokio::pin!(s2l);

    let _ = future::select(l2s, s2l).await;

    info!("TCP tunnel client finished");

    Ok(())
}

async fn tcp_tunnel_example(
    server_addr: SocketAddr,
    local_addr: SocketAddr,
    password: &str,
    method: CipherKind,
) -> io::Result<()> {
    let svr_cfg_server = ServerConfig::new(server_addr, password, method).unwrap();
    let svr_cfg_local = svr_cfg_server.clone();

    let ctx_server = Context::new_shared(ServerType::Server);
    let ctx_local = Context::new_shared(ServerType::Local);

    let barrier_server = Arc::new(Barrier::new(3));
    let barrier_local = barrier_server.clone();
    let barrier = barrier_local.clone();

    tokio::spawn(async move {
        let svr_cfg_server = Arc::new(svr_cfg_server);

        let listener = ProxyListener::bind(ctx_server, &svr_cfg_server).await.unwrap();
        info!("server listening on {}", listener.local_addr().unwrap());

        barrier_server.wait().await;

        while let Ok((stream, peer_addr)) = listener.accept().await {
            info!("server accepted stream {}", peer_addr);
            tokio::spawn(handle_tcp_tunnel_server_client(svr_cfg_server.method(), stream));
        }
    });

    tokio::spawn(async move {
        let svr_cfg_local = Arc::new(svr_cfg_local);

        let listener = TcpListener::bind(local_addr).await.unwrap();
        info!("local listening on {}", listener.local_addr().unwrap());

        barrier_local.wait().await;

        while let Ok((stream, peer_addr)) = listener.accept().await {
            info!("local accepted stream {}", peer_addr);

            let context = ctx_local.clone();
            let svr_cfg = svr_cfg_local.clone();
            tokio::spawn(handle_tcp_tunnel_local_client(context, svr_cfg, stream));
        }
    });

    barrier.wait().await;

    let mut client = TcpStream::connect(local_addr).await?;

    const HTTP_REQUEST: &[u8] = b"GET / HTTP/1.0\r\nHost: www.example.com\r\nAccept: */*\r\nConnection: close\r\n\r\n";
    client.write_all(HTTP_REQUEST).await?;

    let mut reader = BufReader::new(client);

    let mut buffer = Vec::new();
    reader.read_until(b'\n', &mut buffer).await?;

    println!("{:?}", ByteStr::new(&buffer));

    const HTTP_RESPONSE_STATUS: &[u8] = b"HTTP/1.0 200 OK\r\n";
    assert!(buffer.starts_with(HTTP_RESPONSE_STATUS));

    Ok(())
}

#[cfg(feature = "aead-cipher")]
#[tokio::test]
async fn tcp_tunnel_aead() {
    let _ = env_logger::try_init();

    let server_addr = "127.0.0.1:31001".parse::<SocketAddr>().unwrap();
    let local_addr = "127.0.0.1:31101".parse::<SocketAddr>().unwrap();
    tcp_tunnel_example(server_addr, local_addr, "p$p", CipherKind::AES_128_GCM)
        .await
        .unwrap();
}

#[cfg(feature = "stream-cipher")]
#[tokio::test]
async fn tcp_tunnel_stream() {
    let _ = env_logger::try_init();

    let server_addr = "127.0.0.1:32001".parse::<SocketAddr>().unwrap();
    let local_addr = "127.0.0.1:32101".parse::<SocketAddr>().unwrap();
    tcp_tunnel_example(server_addr, local_addr, "p$p", CipherKind::AES_128_CFB128)
        .await
        .unwrap();
}

#[tokio::test]
async fn tcp_tunnel_none() {
    let _ = env_logger::try_init();

    let server_addr = "127.0.0.1:33001".parse::<SocketAddr>().unwrap();
    let local_addr = "127.0.0.1:33101".parse::<SocketAddr>().unwrap();
    // tcp_tunnel_example(server_addr, local_addr, "p$p", CipherKind::NONE)
    tcp_tunnel_example(server_addr, local_addr, "", CipherKind::NONE)
        .await
        .unwrap();
}

#[cfg(feature = "aead-cipher-2022")]
#[tokio::test]
async fn tcp_tunnel_aead_2022_aes() {
    let _ = env_logger::try_init();

    let server_addr = "127.0.0.1:34001".parse::<SocketAddr>().unwrap();
    let local_addr = "127.0.0.1:34101".parse::<SocketAddr>().unwrap();
    tcp_tunnel_example(
        server_addr,
        local_addr,
        "3L69X4PF2eSL/JSLkoWnXg==",
        CipherKind::AEAD2022_BLAKE3_AES_128_GCM,
    )
    .await
    .unwrap();
}

#[cfg(feature = "aead-cipher-2022")]
#[tokio::test]
async fn tcp_tunnel_aead_2022_chacha20() {
    let _ = env_logger::try_init();

    let server_addr = "127.0.0.1:35001".parse::<SocketAddr>().unwrap();
    let local_addr = "127.0.0.1:35101".parse::<SocketAddr>().unwrap();
    tcp_tunnel_example(
        server_addr,
        local_addr,
        "VUw3mGWIpil2z2DKiyauE2Sp9KyE2ab8dulciawe74o",
        CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305,
    )
    .await
    .unwrap();
}


// #[tokio::test]
// async fn dothing() {
//     #[derive(Debug, Default)]
//     struct Stuff {
//         // ... Stuff in here ...
//     }
//
//     let config = Arc::new(ArcSwap::from_pointee(Stuff::default()));
//
//     // We wrap the ArcSwap into an Arc, so we can share it between threads.
//     let config = ArcSwap::from_pointee(Stuff::default());
//
//     let terminate = Arc::new(AtomicBool::new(false));
//     let mut threads = Vec::new();
//
//     // The configuration thread
//     threads.push(thread::spawn({
//         let config = config;
//         let terminate = Arc::clone(&terminate);
//         move || {
//             while !terminate.load(Ordering::Relaxed) {
//                 thread::sleep(Duration::from_secs(6));
//                 // Actually, load it from somewhere
//                 let new_config = Arc::new(Stuff::default());
//                 config.store(new_config);
//             }
//         }
//     }));
//
//     // The worker thread
//     for _ in 0..10 {
//         threads.push(thread::spawn({
//             let config = Arc::clone(&config.load());
//             let terminate = Arc::clone(&terminate);
//             move || {
//                 while !terminate.load(Ordering::Relaxed) {
//                     // let work = Work::fetch();
//                     let config = *(config.clone());
//                     // work.perform(&config);
//                 }
//             }
//         }));
//     }
//
//     // Terminate gracefully
//     terminate.store(true, Ordering::Relaxed);
//     for thread in threads {
//         thread.join().unwrap();
//     }
// }

