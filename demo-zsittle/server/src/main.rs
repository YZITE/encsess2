#![forbid(deprecated, unsafe_code)]

use async_executor::Executor;
use easy_parallel::Parallel;
use futures_lite::future;
use futures_util::lock::BiLock;
use serde::Deserialize;
use std::task::{Context, Poll};
use std::{collections::HashMap, net::SocketAddr, pin::Pin, sync::Arc};
use yzesd_zsittle::base64;

struct DistrPeerData {
    sess: BiLock<yz_encsess::Session>,
    name: String,
}

enum DistrInner {
    Connect(DistrPeerData),
    Disconnect,
    Message(String),
}

struct DistrBlob {
    origin: SocketAddr,
    inner: DistrInner,
}

fn distr_send(distr_in: &async_channel::Sender<DistrBlob>, origin: SocketAddr, inner: DistrInner) {
    let _ = distr_in.try_send(DistrBlob { origin, inner });
}

struct CustomReadUntil<'a> {
    lock: &'a BiLock<yz_encsess::Session>,
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
    lock: &BiLock<yz_encsess::Session>,
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

async fn write_and_flush(v: &BiLock<yz_encsess::Session>, msg: &str) -> std::io::Result<()> {
    use futures_util::io::AsyncWriteExt;
    let mut l = v.lock().await;
    l.write_all(msg.as_bytes()).await?;
    l.flush().await?;
    Ok(())
}

#[derive(Debug, Deserialize)]
struct ConfigClient {
    pubkey: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct ServerConfig {
    listen: String,
    privkey: String,
    pubkey: Option<String>, // unused, but practical
    client: Vec<ConfigClient>,
}

async fn distribute(mut distr_out: async_channel::Receiver<DistrBlob>) {
    use futures_util::{io::AsyncWriteExt, stream::StreamExt};
    let mut outputs = HashMap::<SocketAddr, DistrPeerData>::new();
    loop {
        while let Some(blob) = distr_out.next().await {
            let DistrBlob { origin, inner } = blob;
            match inner {
                DistrInner::Disconnect => {
                    if let Some(x) = outputs.remove(&origin) {
                        let _ = x.sess.lock().await.flush().await;
                    }
                }
                DistrInner::Connect(wr) => {
                    outputs.insert(origin, wr);
                }
                DistrInner::Message(mut msg) => {
                    msg = format!(
                        "{}: {}\n",
                        outputs
                            .get(&origin)
                            .map(|x| x.name.to_string())
                            .unwrap_or_else(|| origin.to_string()),
                        msg
                    );
                    print!("{}", msg);
                    let mut new_outputs = HashMap::new();
                    new_outputs.reserve(outputs.len());
                    for (k, v) in std::mem::take(&mut outputs) {
                        if k == origin || write_and_flush(&v.sess, &msg).await.is_ok() {
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
    ex: &Executor,
    distr_in: async_channel::Sender<DistrBlob>,
    svconfig: &ServerConfig,
    yzconfig: Arc<yz_encsess::Config>,
    stream: async_net::TcpStream,
    peer_addr: SocketAddr,
) {
    match yz_encsess::Session::new(stream, yzconfig).await {
        Err(x) => eprintln!("[ERROR] {}: session setup failed with: {}", peer_addr, x),
        Ok(x) => {
            let clpubkey = base64::encode(x.get_remote_static().unwrap_or(&[]));
            let mut peer_name = String::new();
            if svconfig.client.is_empty() {
                eprintln!(
                    "Accepted client {} with public key = {}",
                    peer_addr, clpubkey,
                );
            } else if let Some(x) = svconfig.client.iter().find(|i| i.pubkey == clpubkey) {
                peer_name = x.name.clone();
                eprintln!(
                    "Accepted client {} with public key = {} and user name = {}",
                    peer_addr, clpubkey, peer_name,
                );
            } else {
                eprintln!(
                    "Rejected client: {} with public key = {} because it isn't whitelisted",
                    peer_addr, clpubkey,
                );
                return;
            }
            ex.spawn(async move {
                let (reader, writer) = BiLock::new(x);
                distr_send(
                    &distr_in,
                    peer_addr,
                    DistrInner::Connect(DistrPeerData {
                        sess: writer,
                        name: peer_name,
                    }),
                );
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

fn main() {
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

    let (s, ctrl_c) = async_channel::bounded(2);
    ctrlc::set_handler(move || {
        let _ = s.try_send(());
    })
    .unwrap();

    // spawn multithreaded executor
    let ex = Executor::new();
    let (signal, shutdown) = async_channel::unbounded::<()>();

    Parallel::new()
        .each(0..num_cpus::get(), |_| future::block_on(ex.run(shutdown.recv())))
        .finish(|| { let ex = &ex; future::block_on(async move {
            use futures_util::{future::FutureExt, stream::StreamExt};

            let listener = async_net::TcpListener::bind(cfgf.listen.to_string())
                .await
                .expect("unable to listen on port");

            let (distr_in, distr_out) = async_channel::unbounded();
            let distributor = ex.spawn(distribute(distr_out));
            let ctrl_c = ctrl_c.into_future();
            futures_util::pin_mut!(ctrl_c);

            loop {
                let fut_accept = listener.accept().fuse();
                futures_util::pin_mut!(fut_accept);
                futures_util::select! {
                    x = ctrl_c => break,
                    y = fut_accept => {
                        let (stream, peer_addr) = y.expect("accept failed");
                        handle_client(&ex, distr_in.clone(), &cfgf, Arc::clone(&yzconfig), stream, peer_addr).await;
                    }
                };
            }

            std::mem::drop(distr_in);
            distributor.cancel().await;
            drop(signal);
        })});
}
