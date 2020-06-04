#![forbid(deprecated, unsafe_code)]

fn main() {
    use clap::Arg;
    tracing_subscriber::fmt::init();

    let matches = clap::App::new("yzesd-client")
        .version(clap::crate_version!())
        .author("Erik Zscheile <zseri.devel@ytrizja.de>")
        .about("a yz-encsess encrypted session proto demonstration program")
        .arg(
            Arg::with_name("privkey")
                .long("privkey")
                .takes_value(true)
                .help("uses specified private key (otherwise generate a new one)"),
        )
        .arg(
            Arg::with_name("remote-pubkey")
                .long("remote-pubkey")
                .takes_value(true)
                .required(true)
                .help("expect specific public key"),
        )
        .arg(
            Arg::with_name("connect")
                .long("connect")
                .takes_value(true)
                .required(true)
                .help("connect to a remote host (arg = SocketAddr, you should probably specify the IP address here)"),
        )
        .get_matches();

    let config = yz_encsess::Config {
        privkey: yzesd_zsittle::get_private_key(matches.value_of("privkey")).into(),
        side: yz_encsess::SideConfig::Client {
            server_pubkey: base64::decode(matches.value_of("remote-pubkey").unwrap())
                .expect("got invalid public key")
                .into(),
        },
    };

    smol::run(async {
        let stream =
            smol::Async::<std::net::TcpStream>::connect(matches.value_of("connect").unwrap())
                .await
                .expect("unable to connect TCP stream");

        use futures_util::io::{self, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
        let sess = yz_encsess::Session::new(stream, config)
            .await
            .expect("unable to establish session");
        let (srd, mut swr) = sess.split();

        // Create async stdin and stdout handles.
        let mut stdin = futures_util::io::BufReader::new(smol::reader(std::io::stdin()));
        let mut stdout = smol::writer(std::io::stdout());

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
