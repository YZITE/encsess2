#![forbid(deprecated, unsafe_code)]

use serde::Deserialize;
use std::{collections::HashMap, sync::Arc};

#[derive(Debug, Deserialize)]
struct ConfigServer {
    connect: String,
    pubkey: String,
}

#[derive(Debug, Deserialize)]
struct ClientConfig {
    privkey: Option<String>,
    pubkey: Option<String>, // unused, but practical
    server: HashMap<String, ConfigServer>,
}

fn main() {
    tracing_subscriber::fmt::init();

    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("USAGE: yzesd2-client CONFIG.toml SERVER_NAME");
        std::process::exit(1);
    }

    let cfgf = std::fs::read(&args[1]).expect("unable to read config file");
    let cfgf: ClientConfig = toml::from_slice(&cfgf[..]).expect("unable to parse config file");
    let use_server = cfgf.server.get(&args[2]).expect("unknown server specified");

    let config = Arc::new(yz_encsess::Config {
        privkey: yzesd_zsittle::get_private_key(cfgf.privkey.as_ref().map(String::as_str)).into(),
        side: yz_encsess::SideConfig::Client {
            server_pubkey: base64::decode(&use_server.pubkey)
                .expect("got invalid public key")
                .into(),
        },
        dhc: yzesd_zsittle::DFL_DHC,
    });

    async_io::block_on(async move {
        let stream = async_net::TcpStream::connect(&use_server.connect)
            .await
            .expect("unable to connect TCP stream");

        stream
            .set_nodelay(true)
            .expect("unable to activate nodelay");

        use futures_util::io::{self, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
        let sess = yz_encsess::Session::new(stream, config)
            .await
            .expect("unable to establish session");
        let (srd, mut swr) = sess.split();

        // Create async stdin and stdout handles.
        let mut stdin = futures_lite::io::BufReader::new(blocking::Unblock::new(std::io::stdin()));
        let mut stdout = blocking::Unblock::new(std::io::stdout());

        futures_util::future::try_join(
            async move {
                let mut line = String::new();
                while stdin.read_line(&mut line).await.is_ok() {
                    tracing::debug!("line length = {}", line.len());
                    swr.write_all(line.as_bytes()).await?;
                    line.clear();
                    swr.flush().await?;
                }
                Ok(())
            },
            io::copy(srd, &mut stdout),
        )
        .await
        .expect("I/O error");
    });
}
