#![forbid(deprecated, unsafe_code)]

use async_dup::Mutex;
use futures_channel::mpsc;
use serde::Deserialize;
use std::{collections::HashMap, net::SocketAddr};

struct DistrPeerData {
    sess: async_dup::Arc<Mutex<yz_encsess::Session>>,
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

fn distr_send(distr_in: &mpsc::UnboundedSender<DistrBlob>, origin: SocketAddr, inner: DistrInner) {
    let _ = distr_in.unbounded_send(DistrBlob { origin, inner });
}

async fn write_and_flush(mut v: &Mutex<yz_encsess::Session>, msg: &str) -> std::io::Result<()> {
    use futures_util::io::AsyncWriteExt;
    v.write_all(msg.as_bytes()).await?;
    v.flush().await?;
    Ok(())
}

async fn distribute(mut distr_out: mpsc::UnboundedReceiver<DistrBlob>) {
    use futures_util::{io::AsyncWriteExt, stream::StreamExt};
    let mut outputs = HashMap::<SocketAddr, DistrPeerData>::new();
    loop {
        while let Some(blob) = distr_out.next().await {
            let DistrBlob { origin, inner } = blob;
            match inner {
                DistrInner::Disconnect => {
                    if let Some(mut x) = outputs.remove(&origin) {
                        let _ = x.sess.flush().await;
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

async fn handle_client(
    distr_in: mpsc::UnboundedSender<DistrBlob>,
    svconfig: &ServerConfig,
    yzconfig: std::sync::Arc<yz_encsess::Config>,
    stream: smol::Async<std::net::TcpStream>,
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
            smol::Task::spawn(async move {
                use futures_util::AsyncBufReadExt;
                let mut xm = async_dup::Arc::new(Mutex::new(x));
                distr_send(
                    &distr_in,
                    peer_addr,
                    DistrInner::Connect(DistrPeerData {
                        sess: xm.clone(),
                        name: peer_name,
                    }),
                );
                let mut line = Vec::new();
                while xm.read_line(&mut line).await.is_ok() {
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

    let yzconfig = std::sync::Arc::new(yz_encsess::Config {
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
                handle_client(distr_in.clone(), &cfgf, std::sync::Arc::clone(&yzconfig), stream, peer_addr).await;
            }
        };
    }

    std::mem::drop(distr_in);
    distributor.cancel().await;
}
