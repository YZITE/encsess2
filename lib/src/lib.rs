#![forbid(unsafe_code)]

use bytes::BytesMut;
use smol::Async;
use std::future::Future;
use std::net::TcpStream;
use std::pin::Pin;
use std::task::{Context, Poll};
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Zeroize)]
pub enum Side {
    /// Client = Initiator
    Initiator,
    /// Server = Responder
    Responder,
}

#[derive(Clone, Debug)]
pub enum SideConfig {
    Client {
        server_pubkey: Zeroizing<Vec<u8>>,
    },
    Server,
}

impl SideConfig {
    fn side(&self) -> Side {
        match self {
            SideConfig::Client { .. } => Side::Initiator,
            SideConfig::Server => Side::Responder,
        }
    }
}

lazy_static::lazy_static! {
    static ref NOISE_PARAMS: snow::params::NoiseParams
      = "Noise_XK_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
    static ref NOISE_PARAMS_REHS: snow::params::NoiseParams
      = "Noise_KK_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
}

pub struct Config {
    pub privkey: Zeroizing<Vec<u8>>,
    pub side: SideConfig,
}

pub struct Session {
    stream: Async<TcpStream>,
    config: Config,
    tstate: snow::TransportState,
    buf_in: BytesMut,
    buf_out: BytesMut,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("noise protocol error: {0}")]
    Noise(#[from] snow::Error),
}

mod helpers {
    use super::*;

    pub async fn recv(stream: &mut Async<TcpStream>) -> std::io::Result<Zeroizing<Vec<u8>>> {
        use futures_util::io::AsyncReadExt;
        let mut lenbuf = [0u8; 2];
        stream.read_exact(&mut lenbuf).await?;
        let mut data = Zeroizing::new(vec![0u8; u16::from_be_bytes(lenbuf).into()]);
        stream.read_exact(&mut data[..]).await?;
        Ok(data)
    }

    pub async fn send(stream: &mut Async<TcpStream>, buf: &[u8]) -> std::io::Result<()> {
        use futures_util::io::AsyncWriteExt;
        use std::convert::TryFrom;
        let lenbuf = u16::try_from(buf.len())
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "length overflow"))?
            .to_be_bytes();
        stream.write_all(&lenbuf).await?;
        stream.write_all(buf).await?;
        Ok(())
    }

    pub fn finish_builder_with_side<'builder>(
        builder: snow::Builder<'builder>,
        side: Side,
    ) -> Result<snow::HandshakeState, snow::Error> {
        match side {
            Side::Initiator => builder.build_initiator(),
            Side::Responder => builder.build_responder(),
        }
    }

    pub async fn do_handshake(
        stream: &mut Async<TcpStream>,
        mut noise: snow::HandshakeState,
    ) -> Result<snow::TransportState, Error> {
        while !noise.is_handshake_finished() {
            let mut tmp = [0u8; 65535];
            if noise.is_my_turn() {
                let len = noise
                    .write_message(&[], &mut tmp[..])
                    .expect("unable to create noise handshake message");
                send(stream, &tmp[..len]).await?;
            } else {
                let x = recv(stream).await?;
                noise.read_message(&x[..], &mut tmp[..])?;
            }
        }
        Ok(noise.into_transport_mode()?)
    }

    pub fn trf_err2io(x: crate::Error) -> std::io::Error {
        match x {
            crate::Error::Io(e) => e,
            crate::Error::Noise(e) => std::io::Error::new(std::io::ErrorKind::PermissionDenied, e),
        }
    }
}

type IoResLength = std::io::Result<usize>;

impl Session {
    pub async fn new(mut stream: Async<TcpStream>, config: Config) -> Result<Session, Error> {
        let mut builder = snow::Builder::new(NOISE_PARAMS.clone()).local_private_key(&config.privkey[..]);
        if let SideConfig::Client { ref server_pubkey } = &config.side {
            builder = builder.remote_public_key(server_pubkey);
        }

        let tstate = helpers::do_handshake(
            &mut stream,
            helpers::finish_builder_with_side(
                builder,
                config.side.side(),
            )?,
        )
        .await?;

        Ok(Session {
            stream,
            config,
            tstate,
            buf_in: BytesMut::new(),
            buf_out: BytesMut::new(),
        })
    }

    #[inline]
    pub fn get_remote_static(&self) -> Option<&[u8]> {
        self.tstate.get_remote_static()
    }

    async fn cont_pending(&mut self) -> Result<(), Error> {
        const MAX_NONCE_VALUE: u64 = 10;
        if std::cmp::max(self.tstate.sending_nonce(), self.tstate.receiving_nonce())
            < MAX_NONCE_VALUE
        {
            return Ok(());
        }
        let noise = helpers::finish_builder_with_side(
            snow::Builder::new(NOISE_PARAMS_REHS.clone())
                .local_private_key(&self.config.privkey[..])
                .remote_public_key(self.tstate.get_remote_static().unwrap()),
            self.config.side.side(),
        )?;
        self.tstate = helpers::do_handshake(&mut self.stream, noise).await?;
        Ok(())
    }

    async fn helper_read(&mut self) -> Result<(), Error> {
        if self.buf_in.is_empty() {
            self.cont_pending().await?;
            let blob = helpers::recv(&mut self.stream).await?;
            self.buf_in.resize(65535, 0);
            let len = self.tstate.read_message(&blob[..], &mut self.buf_in[..])?;
            self.buf_in.truncate(len);
        }
        Ok(())
    }

    async fn helper_write(&mut self, mut threshold: usize) -> Result<(), Error> {
        const PACKET_MAX_LEN: usize = 65535 - 16 - 1;
        threshold = std::cmp::min(threshold, PACKET_MAX_LEN - 1);
        while self.buf_out.len() > threshold {
            self.cont_pending().await?;
            let mut tmp = [0u8; 65535];
            let inner_len = std::cmp::min(self.buf_out.len(), PACKET_MAX_LEN);
            let len = self
                .tstate
                .write_message(&self.buf_out.split_to(inner_len)[..], &mut tmp[..])?;
            helpers::send(&mut self.stream, &tmp[..len]).await?;
        }
        Ok(())
    }

    async fn real_write(&mut self, buf: &[u8]) -> IoResLength {
        const PACKET_SCHED_LEN: usize = 255;
        self.buf_out.extend_from_slice(buf);
        self.helper_write(PACKET_SCHED_LEN)
            .await
            .map_err(helpers::trf_err2io)?;
        Ok(buf.len())
    }
}

// shamelessly stolen from `crate smol`
fn poll_future<T>(cx: &mut Context<'_>, fut: impl Future<Output = T>) -> Poll<T> {
    futures_util::pin_mut!(fut);
    fut.poll(cx)
}

impl futures_util::io::AsyncRead for Session {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<IoResLength> {
        poll_future(cx, async move {
            let this = self.get_mut();
            this.helper_read().await.map_err(helpers::trf_err2io)?;
            let len = std::cmp::min(buf.len(), this.buf_in.len());
            buf.copy_from_slice(&this.buf_in.split_to(len)[..]);
            Ok(len)
        })
    }

    fn poll_read_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [std::io::IoSliceMut<'_>],
    ) -> Poll<IoResLength> {
        poll_future(cx, async move {
            let this = self.get_mut();
            let mut ret_len = 0usize;
            for i in bufs.iter_mut() {
                this.helper_read().await.map_err(helpers::trf_err2io)?;
                let len = std::cmp::min(i.len(), this.buf_in.len());
                if len == 0 {
                    break;
                }
                i.copy_from_slice(&this.buf_in.split_to(len)[..]);
                ret_len += len;
            }
            Ok(ret_len)
        })
    }
}

impl futures_util::io::AsyncWrite for Session {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<IoResLength> {
        poll_future(cx, self.real_write(buf))
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<IoResLength> {
        poll_future(cx, async move {
            let this = self.get_mut();
            let mut ret_len = 0usize;
            for i in bufs.iter() {
                this.buf_out.extend_from_slice(&(*i)[..]);
                this.helper_write(usize::MAX)
                    .await
                    .map_err(helpers::trf_err2io)?;
                ret_len += i.len();
            }
            this.real_write(&[]).await?;
            Ok(ret_len)
        })
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        poll_future(cx, async move {
            self.get_mut()
                .helper_write(0)
                .await
                .map_err(helpers::trf_err2io)
        })
    }

    #[inline]
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Self::poll_flush(self, cx)
    }
}
