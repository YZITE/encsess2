#![forbid(deprecated, unsafe_code)]

use futures_channel::mpsc;
use std::net::SocketAddr;

type DistrOutput = futures_util::io::WriteHalf<yz_encsess::Session>;

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

async fn distribute(mut distr_out: mpsc::UnboundedReceiver<DistrBlob>) {
    use std::collections::HashMap;
    use futures_util::{io::AsyncWriteExt, stream::StreamExt};
    let mut outputs = HashMap::<SocketAddr, DistrOutput>::new();
    loop {
        while let Some(blob) = distr_out.next().await {
            let DistrBlob { origin, inner } = blob;
            match inner {
                DistrInner::Disconnect => {
                    if let Some(mut outp) = outputs.remove(&origin) {
                        let _ = outp.flush().await;
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
                    for (k, mut v) in std::mem::take(&mut outputs) {
                        if k == origin || v.write_all(msg.as_bytes()).await.is_ok() {
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
    config: yz_encsess::Config,
    stream: smol::Async<std::net::TcpStream>,
    peer_addr: SocketAddr,
) {
    use futures_util::io::{AsyncReadExt, AsyncBufReadExt};
    eprintln!("Accepted client: {}", peer_addr);
    match yz_encsess::Session::new(stream, config).await {
        Err(x) => eprintln!("[ERROR] {}: session setup failed with: {}", peer_addr, x),
        Ok(x) => {
            /*
                            tokio::spawn(async move {
                                let mut buffer = YzeSession::get_recv_buffer();
                                let (mut reader, writer) = x.split();
                                distr_send(&distr_in, peer_addr, DistrInner::Connect(writer));
                                while let Ok(blob) = reader.recv_with_buffer(&mut buffer).await {
                                    if blob.is_empty() {
                                        break;
                                    }
                                    if let Ok(line) = std::str::from_utf8(blob) {
                                        distr_send(&distr_in, peer_addr, DistrInner::Message(line.to_string()));
                                    }
                                }
                                distr_send(&distr_in, peer_addr, DistrInner::Disconnect);
                                println!("Disconnected: {}", peer_addr);
                            });

            */

            smol::Task::spawn(async {
                let (mut reader, writer) = x.split();
                distr_send(&distr_in, peer_addr, DistrInner::Connect(writer));
                let mut line = String::new();
                while reader.read_line(&mut line).is_ok() {
                    if line.is_empty() {
                        break;
                    }
                    if line.ends_with('\n') {
                        line.pop();
                    }
                    distr_send(
                        &distr_in,
                        peer_addr,
                        DistrInner::Message(std::mem::take(&mut line)),
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
    use clap::Arg;
    use futures_util::{future::FutureExt, stream::StreamExt};

    let matches = clap::App::new("yzesd-server")
        .version(clap::crate_version!())
        .author("Erik Zscheile <zseri.devel@ytrizja.de>")
        .about("a yz-encsess encrypted session proto demonstration program")
        .arg(
            Arg::with_name("privkey")
                .long("privkey")
                .takes_value(true)
                .help("uses the specified private key (otherwise generate a new one)"),
        )
        .arg(
            Arg::with_name("listen")
                .long("listen")
                .takes_value(true)
                .required(true)
                .help("listen on the specified port (arg = SocketAddr)"),
        )
        .get_matches();

    let config = yz_encsess::Config {
        privkey: yzesd_zsittle::get_private_key(matches.value_of("privkey")).into(),
        side: yz_encsess::SideConfig::Server,
    };

    let (s, ctrl_c) = futures_channel::mpsc::unbounded();
    ctrlc::set_handler(move || {
        let _ = s.unbounded_send(());
    })
    .unwrap();

    let listener = smol::Async::<std::net::TcpListener>::bind(matches.value_of("listen").unwrap())
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
                handle_client(distr_in.clone(), config.clone(), stream, peer_addr).await;
            }
        };
    }

    std::mem::drop(distr_in);
    distributor.cancel();
}
