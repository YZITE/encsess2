#![forbid(unsafe_code)]

use bytes::{Buf, BytesMut};
use futures_util::io::{AsyncBufRead, AsyncRead, AsyncWrite, AsyncWriteExt};
use futures_util::{sink::SinkExt, stream::StreamExt};
use smol::Async;
use std::net::TcpStream;
use std::pin::Pin;
use std::task::{Context, Poll};
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Zeroize)]
enum Side {
    /// Client = Initiator
    Initiator,
    /// Server = Responder
    Responder,
}

#[derive(Clone, Debug)]
pub enum SideConfig {
    Client { server_pubkey: Zeroizing<Vec<u8>> },
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

const MAX_U16LEN: usize = 0xffff;

#[derive(Clone, Debug)]
pub struct Config {
    pub privkey: Zeroizing<Vec<u8>>,
    pub side: SideConfig,
}

enum SessionState {
    Handshake(snow::HandshakeState),
    Transport(snow::TransportState),
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("noise protocol error: {0}")]
    Noise(#[from] snow::Error),
}

macro_rules! pollerfwd {
    ($x:expr) => {{
        match futures_util::ready!($x) {
            Ok(x) => x,
            Err(e) => return ::std::task::Poll::Ready(Err(e)),
        }
    }};
}

mod helpers;
mod packet_stream;

use helpers::poll_future;
type IoResLength = std::io::Result<usize>;

pub struct Session {
    parent: packet_stream::PacketStream,
    config: Config,
    state: SessionState,

    buf_in: BytesMut,
    buf_out: BytesMut,
}

#[inline]
pub fn generate_keypair() -> Result<snow::Keypair, Error> {
    Ok(snow::Builder::new(NOISE_PARAMS.clone()).generate_keypair()?)
}

impl Session {
    pub async fn new(stream: Async<TcpStream>, config: Config) -> Result<Session, Error> {
        let mut builder =
            snow::Builder::new(NOISE_PARAMS.clone()).local_private_key(&config.privkey[..]);
        if let SideConfig::Client { ref server_pubkey } = &config.side {
            builder = builder.remote_public_key(server_pubkey);
        }

        let state = SessionState::Handshake(helpers::finish_builder_with_side(
            builder,
            config.side.side(),
        )?);

        let mut this = Session {
            parent: packet_stream::PacketStream::new(stream),
            config,
            state,
            buf_in: BytesMut::new(),
            buf_out: BytesMut::new(),
        };

        // perform handshake without code duplication
        this.cont_pending().await?;

        Ok(this)
    }

    #[inline]
    pub fn get_remote_static(&self) -> Option<&[u8]> {
        match &self.state {
            SessionState::Transport(x) => x.get_remote_static(),
            SessionState::Handshake(x) => x.get_remote_static(),
        }
    }

    async fn cont_pending(&mut self) -> Result<(), Error> {
        const MAX_NONCE_VALUE: u64 = 10;

        // perform all state transitions
        let config = &self.config;
        loop {
            take_mut::take(&mut self.state, |state| match state {
                SessionState::Transport(tr) => {
                    if std::cmp::max(tr.sending_nonce(), tr.receiving_nonce()) < MAX_NONCE_VALUE {
                        SessionState::Transport(tr)
                    } else {
                        SessionState::Handshake(
                            helpers::finish_builder_with_side(
                                snow::Builder::new(NOISE_PARAMS_REHS.clone())
                                    .local_private_key(&config.privkey[..])
                                    .remote_public_key(tr.get_remote_static().unwrap()),
                                config.side.side(),
                            )
                            .expect("unable to build HandshakeState"),
                        )
                    }
                }
                SessionState::Handshake(hs) => {
                    if hs.is_handshake_finished() {
                        SessionState::Transport(
                            hs.into_transport_mode()
                                .expect("unable to build TransportState"),
                        )
                    } else {
                        SessionState::Handshake(hs)
                    }
                }
            });

            // we can now deal with a state which doesn't need to change
            // this function is reentrant, because the state of our state machine is
            // put into self.state

            if let SessionState::Handshake(ref mut noise) = &mut self.state {
                // any `.await?` might yield and nuke `tmp`
                let mut tmp = [0u8; MAX_U16LEN];
                loop {
                    // this might yield, but that's ok
                    SinkExt::<&[u8]>::flush(&mut self.parent).await?;
                    if noise.is_handshake_finished() {
                        break;
                    } else if noise.is_my_turn() {
                        let len = noise
                            .write_message(&[], &mut tmp[..])
                            .expect("unable to create noise handshake message");
                        // this might yield if err, but the item won't get lost
                        self.parent.start_send_unpin(&tmp[..len])?;
                    } else {
                        // this line might yield and nuke `tmp`
                        let _ = match self.parent.next().await {
                            Some(x) => noise.read_message(&(x?)[..], &mut tmp[..])?,
                            None => {
                                return Err(Error::Io(std::io::Error::new(
                                    std::io::ErrorKind::UnexpectedEof,
                                    "eof while handshaking",
                                )))
                            }
                        };
                    }
                }
            } else {
                return Ok(());
            }
        }
    }

    async fn helper_read(&mut self) -> Result<(), Error> {
        if !self.buf_in.is_empty() {
            return Ok(());
        }
        self.cont_pending().await?;
        let parent = &mut self.parent;
        let buf_in = &mut self.buf_in;
        if let SessionState::Transport(ref mut tr) = &mut self.state {
            if let Some(blob) = parent.next().await {
                buf_in.resize(MAX_U16LEN, 0);
                let len = tr
                    .read_message(&(blob?)[..], &mut buf_in[..])
                    .map_err(|x| {
                        buf_in.clear();
                        x
                    })?;
                let padding_len: usize = buf_in.get_u16().into();
                tracing::debug!("got len = {}, padding_len = {}", len, padding_len);
                if padding_len <= len {
                    buf_in.truncate(len - padding_len - 2);
                } else {
                    // do not panic if out-of-bounds
                    buf_in.clear();
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "padding length out of bounds",
                    )
                    .into());
                }
            }
        }
        Ok(())
    }

    async fn helper_write(&mut self, do_full_flush: bool) -> Result<(), Error> {
        // we know about the PacketStream interna and know we don't need to wait for readyness.
        const PACKET_MAX_LEN: usize = MAX_U16LEN - 20 - 1;
        const PAD_TRG_SIZE: usize = 64;
        let threshold = if do_full_flush { 0 } else { PACKET_MAX_LEN - 1 };
        let mut sent_new_data = false;
        tracing::debug!(
            "buffered output len = {}; do full flush = {}",
            self.buf_out.len(),
            do_full_flush
        );
        let mut thrng = rand::thread_rng();
        while self.buf_out.len() > threshold {
            // cont_pending calls flush if necessary
            self.cont_pending().await?;
            if let SessionState::Transport(ref mut tr) = &mut self.state {
                use {bytes::BufMut, std::convert::TryInto};
                let inner_len = std::cmp::min(self.buf_out.len(), PACKET_MAX_LEN);
                let wopad_len = inner_len + 2;
                // padding prefix (20) = 16 (AEAD meta) + 2 (packet length) + 2 (non-padding length)
                let mut padding_len = PAD_TRG_SIZE - ((20 + inner_len) % PAD_TRG_SIZE);
                if (wopad_len + padding_len) > MAX_U16LEN {
                    assert!(padding_len > 0);
                    padding_len -= 1;
                }
                let mut inner_full = Zeroizing::new(Vec::with_capacity(wopad_len + padding_len));
                // we save the padding_len instead of inner_len because the
                // attacker might have lesser info about it
                tracing::debug!("use padding_len = {}", padding_len);
                inner_full.put_u16(padding_len.try_into().unwrap());
                inner_full.extend_from_slice(&self.buf_out[..inner_len]);
                inner_full.resize(wopad_len + padding_len, 0);
                rand::RngCore::fill_bytes(&mut thrng, &mut inner_full[wopad_len..]);
                let mut tmp = [0u8; MAX_U16LEN];
                let len = tr.write_message(&inner_full[..], &mut tmp[..])?;
                // this only works because we know about the PacketStream interna
                // because otherwise it violates the Sink interface
                self.parent.start_send_unpin(&tmp[..len])?;
                self.buf_out.advance(inner_len);
                sent_new_data = true;
            }
        }
        if sent_new_data {
            SinkExt::<&[u8]>::flush(&mut self.parent).await?;
        }
        Ok(())
    }
}

impl AsyncBufRead for Session {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<&[u8]>> {
        poll_future(cx, async move {
            let this = self.get_mut();
            this.helper_read().await.map_err(helpers::trf_err2io)?;
            Ok(&this.buf_in[..])
        })
    }

    #[inline]
    fn consume(self: Pin<&mut Self>, amt: usize) {
        self.get_mut().buf_in.advance(amt)
    }
}

impl AsyncRead for Session {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<IoResLength> {
        let mybuf = pollerfwd!(self.as_mut().poll_fill_buf(cx));
        let len = std::cmp::min(buf.len(), mybuf.len());
        buf[..len].copy_from_slice(&mybuf[..len]);
        self.consume(len);
        Poll::Ready(Ok(len))
    }
}

impl AsyncWrite for Session {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<IoResLength> {
        poll_future(cx, async move {
            self.helper_write(false)
                .await
                .map_err(helpers::trf_err2io)?;
            // we can't simply do this before the partial flush,
            // because we can't 'roll back' in case of yielding or error
            self.buf_out.extend_from_slice(buf);
            Ok(buf.len())
        })
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        poll_future(cx, async move {
            self.get_mut()
                .helper_write(true)
                .await
                .map_err(helpers::trf_err2io)
        })
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        poll_future(cx, async {
            self.flush().await?;
            SinkExt::<&[u8]>::close(&mut self.parent).await
        })
    }
}
