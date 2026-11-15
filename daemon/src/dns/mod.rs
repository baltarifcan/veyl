pub mod cache;
pub mod local;
pub mod msg;
pub mod plain;
pub mod resolver;
pub mod upstream;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, Semaphore};

use crate::log_every;
use resolver::Resolver;

/// Bounds memory under a flood; excess datagrams are dropped.
const MAX_UDP_INFLIGHT: usize = 4096;
const MAX_TCP_CONNS: usize = 512;
const TCP_IDLE: Duration = Duration::from_secs(10);

pub static UDP_DROPPED: AtomicU64 = AtomicU64::new(0);

pub async fn serve_udp(sock: UdpSocket, r: Arc<Resolver>) {
    let sock = Arc::new(sock);
    let sem = Arc::new(Semaphore::new(MAX_UDP_INFLIGHT));
    let mut buf = vec![0u8; 65_535];
    loop {
        let (n, peer) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                log_every!("dns-udp-recv", "dns: UDP receive failed: {}", e);
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
        };
        let Ok(permit) = sem.clone().try_acquire_owned() else {
            UDP_DROPPED.fetch_add(1, Ordering::Relaxed);
            log_every!("dns-udp-drop", "dns: overloaded, dropping UDP queries");
            continue;
        };
        let data = buf[..n].to_vec();
        let sock = sock.clone();
        let r = r.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let reply = r.answer(&data).await;
            if reply.wire.is_empty() {
                return;
            }
            let wire = match &reply.question {
                Some(q) if reply.wire.len() > q.udp_size => msg::truncated_reply(&data, q),
                _ => reply.wire,
            };
            let _ = sock.send_to(&wire, peer).await;
        });
    }
}

pub async fn serve_tcp(listener: TcpListener, r: Arc<Resolver>) {
    let sem = Arc::new(Semaphore::new(MAX_TCP_CONNS));
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                log_every!("dns-tcp-accept", "dns: TCP accept failed: {}", e);
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Ok(permit) = sem.clone().try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let r = r.clone();
        tokio::spawn(async move {
            let _permit = permit;
            tcp_conn(stream, r).await;
        });
    }
}

/// Pipelined: answers are written back as they complete.
async fn tcp_conn(stream: TcpStream, r: Arc<Resolver>) {
    let _ = stream.set_nodelay(true);
    let (mut rd, mut wr) = stream.into_split();
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(32);
    let writer = tokio::spawn(async move {
        while let Some(m) = rx.recv().await {
            let mut out = Vec::with_capacity(m.len() + 2);
            out.extend_from_slice(&(m.len() as u16).to_be_bytes());
            out.extend_from_slice(&m);
            if wr.write_all(&out).await.is_err() {
                break;
            }
        }
        let _ = wr.shutdown().await;
    });
    loop {
        let mut len = [0u8; 2];
        match tokio::time::timeout(TCP_IDLE, rd.read_exact(&mut len)).await {
            Ok(Ok(_)) => {}
            _ => break,
        }
        let n = u16::from_be_bytes(len) as usize;
        let mut data = vec![0u8; n];
        match tokio::time::timeout(TCP_IDLE, rd.read_exact(&mut data)).await {
            Ok(Ok(_)) => {}
            _ => break,
        }
        let r = r.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            let reply = r.answer(&data).await;
            if !reply.wire.is_empty() {
                let _ = tx.send(reply.wire).await;
            }
        });
    }
    drop(tx);
    let _ = writer.await;
}
