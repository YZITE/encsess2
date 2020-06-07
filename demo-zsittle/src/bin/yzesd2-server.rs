#![forbid(deprecated, unsafe_code)]

use futures_channel::mpsc;
use futures_util::lock::BiLock;
use serde::Deserialize;
use std::{net::SocketAddr, pin::Pin, sync::Arc};
use std::task::{Context, Poll};

type DistrOutput = BiLock<yz_encsess::Session>;

enum DistrInner {
    Connect(DistrOutput),
    Disconnect,
    Message(String),
}

struct DistrBlob {
    origin: SocketAddr,
    inner: DistrInner,
}

fn distr_send(distr_in: &mpsc::UnboundedSender<DistrBlob>, origin: SocketAddr, inner: DistrInner) {
    let _ = distr_in.unbounded_send(DistrBlob { origin, inner });
}

struct CustomReadUntil<'a> {
    lock: &'a DistrOutput,
    bytes: &'a mut Vec<u8>,
    until_byte: u8,
}

fn read_until_internal<R: futures_util::io::AsyncBufRead + ?Sized>(
    mut reader: Pin<&mut R>,
    cx: &mut Context<'_>,
    byte: u8,
    buf: &mut Vec<u8>,
    read: &mut usize,
) -> Poll<std::io::Result<usize>> {
    loop {
        let (done, used) = {
            let available = futures_util::ready!(reader.as_mut().poll_fill_buf(cx))?;
            if let Some(i) = memchr::memchr(byte, available) {
                buf.extend_from_slice(&available[..=i]);
                (true, i + 1)
            } else {
                buf.extend_from_slice(available);
                (false, available.len())
            }
        };
        reader.as_mut().consume(used);
        *read += used;
        if done || used == 0 {
            return Poll::Ready(Ok(std::mem::replace(read, 0)));
        }
    }
}

impl<'a> std::future::Future for CustomReadUntil<'a> {
    type Output = std::io::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        use futures_util::ready;
        let this = Pin::into_inner(self);
        let mut l = ready!(this.lock.poll_lock(cx));
        let mut rcnt = 0;
        let ret = ready!(read_until_internal(
            l.as_pin_mut(),
            cx,
            this.until_byte,
            this.bytes,
            &mut rcnt
        ));
        Poll::Ready(ret.map(|_| ()))
    }
}

#[inline]
async fn locked_read_until(
    lock: &DistrOutput,
    bytes: &mut Vec<u8>,
    until_byte: u8,
) -> std::io::Result<()> {
    CustomReadUntil {
        lock,
        bytes,
        until_byte,
    }
    .await
}

async fn write_and_flush(v: &DistrOutput, msg: &str) -> std::io::Result<()> {
    use futures_util::io::AsyncWriteExt;
    let mut l = v.lock().await;
    l.write_all(msg.as_bytes()).await?;
    l.flush().await?;
    Ok(())
}

#[derive(Debug, Deserialize)]
struct ConfigClient {
    pubkey: String,
}

#[derive(Debug, Deserialize)]
struct ServerConfig {
    listen: String,
    privkey: String,
    pubkey: Option<String>, // unused, but practical
    client: Vec<ConfigClient>,
}

async fn distribute(mut distr_out: mpsc::UnboundedReceiver<DistrBlob>) {
    use futures_util::{io::AsyncWriteExt, stream::StreamExt};
    use std::collections::HashMap;
    let mut outputs = HashMap::<SocketAddr, DistrOutput>::new();
    loop {
        while let Some(blob) = distr_out.next().await {
            let DistrBlob { origin, inner } = blob;
            match inner {
                DistrInner::Disconnect => {
                    if let Some(outp) = outputs.remove(&origin) {
                        let _ = outp.lock().await.flush().await;
                    }
                }
                DistrInner::Connect(wr) => {
                    outputs.insert(origin, wr);
                }
                DistrInner::Message(mut msg) => {
                    msg = format!("{}: {}\n", origin.to_string(), msg);
                    print!("{}", msg);
                    let mut new_outputs = HashMap::new();
                    new_outputs.reserve(outputs.len());
                    for (k, v) in std::mem::take(&mut outputs) {
                        if k == origin || write_and_flush(&v, &msg).await.is_ok() {
                            new_outputs.insert(k, v);
                        }
                    }
                    outputs = new_outputs;
                }
            }
        }
    }
}

async fn handle_client(
    distr_in: mpsc::UnboundedSender<DistrBlob>,
    svconfig: &ServerConfig,
    yzconfig: Arc<yz_encsess::Config>,
    stream: smol::Async<std::net::TcpStream>,
    peer_addr: SocketAddr,
) {
    match yz_encsess::Session::new(stream, yzconfig).await {
        Err(x) => eprintln!("[ERROR] {}: session setup failed with: {}", peer_addr, x),
        Ok(x) => {
            let clpubkey = base64::encode(x.get_remote_static().unwrap_or(&[]));
            eprintln!(
                "Accepted client {} with public key = {}",
                peer_addr,
                clpubkey,
            );
            if !svconfig.client.is_empty() {
                if !svconfig.client.iter().any(|i| i.pubkey == clpubkey) {
                    eprintln!(
                        "Rejected client: {} with public key = {} because it isn't whitelisted", peer_addr, clpubkey,
                    );
                    return;
                }
            }
            smol::Task::spawn(async move {
                let (reader, writer) = BiLock::new(x);
                distr_send(&distr_in, peer_addr, DistrInner::Connect(writer));
                let mut line = Vec::new();
                while locked_read_until(&reader, &mut line, b'\n').await.is_ok() {
                    if line.is_empty() {
                        break;
                    }
                    if line.ends_with(&[b'\n']) {
                        line.pop();
                    }
                    distr_send(
                        &distr_in,
                        peer_addr,
                        DistrInner::Message(
                            String::from_utf8(std::mem::take(&mut line))
                                .expect("got invalid utf-8"),
                        ),
                    );
                }
                distr_send(&distr_in, peer_addr, DistrInner::Disconnect);
                println!("Disconnected: {}", peer_addr);
            })
            .detach();
        }
    }
}

#[smol_potat::main]
async fn main() {
    use futures_util::{future::FutureExt, stream::StreamExt};
    tracing_subscriber::fmt::init();

    let args: Vec<_> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("USAGE: yzesd2-server CONFIG.toml");
        std::process::exit(1);
    }

    let cfgf = std::fs::read(&args[1]).expect("unable to read config file");
    let cfgf: ServerConfig = toml::from_slice(&cfgf[..]).expect("unable to parse config file");

    let yzconfig = Arc::new(yz_encsess::Config {
        privkey: yzesd_zsittle::get_private_key(Some(cfgf.privkey.as_str())).into(),
        side: yz_encsess::SideConfig::Server,
    });

    let (s, ctrl_c) = futures_channel::mpsc::unbounded();
    ctrlc::set_handler(move || {
        let _ = s.unbounded_send(());
    })
    .unwrap();

    let listener = smol::Async::<std::net::TcpListener>::bind(cfgf.listen.to_string())
        .expect("unable to listen on port");

    let (distr_in, distr_out) = mpsc::unbounded();
    let distributor = smol::Task::spawn(distribute(distr_out));
    let ctrl_c = ctrl_c.into_future();
    futures_util::pin_mut!(ctrl_c);

    loop {
        let fut_accept = listener.accept().fuse();
        futures_util::pin_mut!(fut_accept);
        futures_util::select! {
            x = ctrl_c => break,
            y = fut_accept => {
                let (stream, peer_addr) = y.expect("accept failed");
                handle_client(distr_in.clone(), &cfgf, Arc::clone(&yzconfig), stream, peer_addr).await;
            }
        };
    }

    std::mem::drop(distr_in);
    distributor.cancel().await;
}
