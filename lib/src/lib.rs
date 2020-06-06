#![forbid(unsafe_code)]

use bytes::{Buf, BytesMut};
use futures_util::io::{AsyncBufRead, AsyncRead, AsyncWrite};
use futures_util::{pin_mut, ready, sink::Sink, sink::SinkExt, stream::StreamExt};
use yz_packet_stream::PacketStream;
use smol::Async;
use std::task::{Context, Poll};
use std::{future::Future, net::TcpStream, pin::Pin};
use tracing::debug;
use zeroize::{Zeroize, Zeroizing};

lazy_static::lazy_static! {
    static ref NOISE_PARAMS: snow::params::NoiseParams
      = "Noise_XK_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
    static ref NOISE_PARAMS_REHS: snow::params::NoiseParams
      = "Noise_KK_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
}

macro_rules! pollerfwd {
    ($x:expr) => {{
        match ready!($x) {
            Ok(x) => x,
            Err(e) => return ::std::task::Poll::Ready(Err(e)),
        }
    }};
}

type IoPoll<T> = Poll<std::io::Result<T>>;

const MAX_U16LEN: usize = 0xffff;
const PACKET_MAX_LEN: usize = MAX_U16LEN - 20 - 1;

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

#[derive(Clone, Debug)]
pub struct Config {
    pub privkey: Zeroizing<Vec<u8>>,
    pub side: SideConfig,
}

#[derive(Clone, Copy, Debug)]
enum TrSubState {
    Transport,
    ScheduledHandshake,
    Handshake,
}

enum SessionState {
    Transport(snow::TransportState, TrSubState),
    Handshake(snow::HandshakeState),
}

fn trf_err2io(x: snow::Error) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, x)
}

fn finish_builder_with_side(
    builder: snow::Builder<'_>,
    side: Side,
) -> std::io::Result<snow::HandshakeState> {
    match side {
        Side::Initiator => builder.build_initiator(),
        Side::Responder => builder.build_responder(),
    }
    .map_err(trf_err2io)
}

type PacketTcpStream = PacketStream<Async<TcpStream>>;

pub struct Session {
    parent: PacketTcpStream,
    config: Config,
    state: SessionState,

    buf_in: BytesMut,
    buf_out: BytesMut,
}

#[inline]
pub fn generate_keypair() -> Result<snow::Keypair, snow::Error> {
    Ok(snow::Builder::new(NOISE_PARAMS.clone()).generate_keypair()?)
}

const PAD_TRG_SIZE: usize = 64;

fn helper_send_packet(
    pktstream: &mut PacketTcpStream,
    tr: &mut snow::TransportState,
    pktbuf: &[u8],
) -> std::io::Result<usize> {
    use {bytes::BufMut, std::convert::TryInto};
    let inner_len = std::cmp::min(pktbuf.len(), PACKET_MAX_LEN);
    let wopad_len = inner_len + 2;
    // padding prefix (20) = 16 (AEAD meta) + 2 (packet length) + 2 (non-padding length)
    let mut padding_len = PAD_TRG_SIZE - ((20 + inner_len) % PAD_TRG_SIZE);
    if (wopad_len + padding_len) > MAX_U16LEN {
        assert!(padding_len > 0);
        padding_len -= 1;
    }
    let mut inner_full = Zeroizing::new(Vec::with_capacity(wopad_len + padding_len));
    debug!("use padding_len = {}", padding_len);
    inner_full.put_u16(inner_len.try_into().unwrap());
    inner_full.extend_from_slice(&pktbuf[..inner_len]);
    inner_full.resize(wopad_len + padding_len, 0);
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut inner_full[wopad_len..]);
    let mut tmp = [0u8; MAX_U16LEN];
    let len = tr
        .write_message(&inner_full[..], &mut tmp[..])
        .map_err(trf_err2io)?;
    // this only works because we know about the PacketStream interna
    // because otherwise it violates the Sink interface
    pktstream.start_send_unpin(&tmp[..len])?;
    Ok(inner_len)
}

impl Session {
    pub async fn new(stream: Async<TcpStream>, config: Config) -> std::io::Result<Session> {
        let mut builder =
            snow::Builder::new(NOISE_PARAMS.clone()).local_private_key(&config.privkey[..]);
        if let SideConfig::Client { ref server_pubkey } = &config.side {
            builder = builder.remote_public_key(server_pubkey);
        }

        let state = SessionState::Handshake(finish_builder_with_side(builder, config.side.side())?);

        let mut this = Session {
            parent: PacketStream::new(stream),
            config,
            state,
            buf_in: BytesMut::new(),
            buf_out: BytesMut::new(),
        };

        // perform handshake without code duplication
        this.cont_pending_intern().await?;

        Ok(this)
    }

    #[inline]
    pub fn get_remote_static(&self) -> Option<&[u8]> {
        match &self.state {
            SessionState::Transport(x, _) => x.get_remote_static(),
            SessionState::Handshake(x) => x.get_remote_static(),
        }
    }

    async fn helper_fill_bufin(&mut self) -> std::io::Result<()> {
        if let SessionState::Transport(ref mut tr, ref mut substate) = &mut self.state {
            if let Some(blob) = self.parent.next().await {
                let mut buf_in = self.buf_in.split_off(self.buf_in.len());
                buf_in.resize(MAX_U16LEN, 0);
                let len = tr
                    .read_message(&(blob?)[..], &mut buf_in[..])
                    .map_err(trf_err2io)?;
                let inner_len: usize = buf_in.get_u16().into();
                debug!("got len = {}, inner_len = {}", len, inner_len);
                if inner_len > (len - 2) {
                    // do not panic if out-of-bounds
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "inner length out of bounds",
                    ));
                }
                buf_in.truncate(inner_len);
                if inner_len == 0 {
                    // got a token.
                    use TrSubState as TSS;
                    match substate {
                        TSS::Transport => {
                            // we didn't sent a token ourselves, do it now
                            // we don't need to clear the output buffer
                            helper_send_packet(&mut self.parent, tr, &[])?;
                            SinkExt::<&[u8]>::flush(&mut self.parent).await?;
                        }
                        TSS::ScheduledHandshake => {
                            // we already sent a token ourselves, do nothing
                        }
                        TSS::Handshake => {
                            unreachable!("got a token while preparing for handshake, missing call to cont_pending?");
                        }
                    }
                    *substate = TSS::Handshake;
                    // NOTE: we need to check the substate in poll_fill_buf to be sure
                    // to not return EOF when we are in the Handshake substate
                }
                self.buf_in.unsplit(buf_in);
            }
        }
        Ok(())
    }

    async fn cont_pending_intern(&mut self) -> std::io::Result<()> {
        const MAX_NONCE_VALUE: u64 = 10;

        // perform all state transitions
        loop {
            let config = &self.config;
            let parent = &self.parent;
            let mut need2send_token = false;
            take_mut::take(&mut self.state, |state| match state {
                SessionState::Transport(tr, TrSubState::Transport)
                    if tr.sending_nonce() >= MAX_NONCE_VALUE =>
                {
                    need2send_token = true;
                    SessionState::Transport(tr, TrSubState::ScheduledHandshake)
                }
                SessionState::Transport(tr, TrSubState::Transport)
                    if tr.receiving_nonce() == (MAX_NONCE_VALUE + 1) =>
                {
                    tracing::warn!("expected handshake token from other peer, but didn't get one");
                    SessionState::Transport(tr, TrSubState::Transport)
                }

                SessionState::Transport(tr, TrSubState::Handshake) => {
                    debug!("begin handshake with {:?}", parent);
                    SessionState::Handshake(
                        finish_builder_with_side(
                            snow::Builder::new(NOISE_PARAMS_REHS.clone())
                                .local_private_key(&config.privkey[..])
                                .remote_public_key(tr.get_remote_static().unwrap()),
                            config.side.side(),
                        )
                        .expect("unable to build HandshakeState"),
                    )
                }

                SessionState::Handshake(hs) if hs.is_handshake_finished() => {
                    debug!("finish handshake with {:?}", parent);
                    SessionState::Transport(
                        hs.into_transport_mode()
                            .expect("unable to build TransportState"),
                        TrSubState::Transport,
                    )
                }
                x => x,
            });

            // we can now deal with a state which doesn't need to change
            // this function is reentrant, because the state of our state machine is
            // put into self.state

            match &mut self.state {
                SessionState::Handshake(ref mut noise) => {
                    // any `.await?` might yield and nuke `tmp`
                    let mut tmp = [0u8; MAX_U16LEN];
                    loop {
                        // this might yield, but that's ok
                        SinkExt::<&[u8]>::flush(&mut self.parent).await?;
                        if noise.is_handshake_finished() {
                            break;
                        } else if noise.is_my_turn() {
                            // calculate padding
                            let simdat = noise.simulate_write_message(&[]).unwrap();
                            let padding_len = PAD_TRG_SIZE - (simdat.result_length % PAD_TRG_SIZE);
                            let mut padding = Vec::new();
                            padding.resize(padding_len, 0u8);
                            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut padding[..]);
                            let len = noise
                                .write_message(&padding[..], &mut tmp[..])
                                .expect("unable to create noise handshake message");
                            assert_eq!(len % PAD_TRG_SIZE, 0);
                            // this might yield if err, but the item won't get lost
                            self.parent.start_send_unpin(&tmp[..len])?;
                        } else {
                            // this line might yield and nuke `tmp`
                            let _ = match self.parent.next().await {
                                Some(x) => noise
                                    .read_message(&(x?)[..], &mut tmp[..])
                                    .map_err(trf_err2io)?,
                                None => {
                                    return Err(std::io::Error::new(
                                        std::io::ErrorKind::UnexpectedEof,
                                        "eof while handshaking",
                                    ))
                                }
                            };
                        }
                    }
                }
                SessionState::Transport(ref mut tr, TrSubState::ScheduledHandshake) => {
                    // we don't need to save $need2send_token in TrSubState,
                    // because we have no yield point between setting and checking it
                    if need2send_token {
                        helper_send_packet(&mut self.parent, tr, &[])?;
                        SinkExt::<&[u8]>::flush(&mut self.parent).await?;
                    }
                    // we need to wait until we get a token from the other peer
                    self.helper_fill_bufin().await?;
                }
                _ => return Ok(()),
            }
        }
    }

    fn poll_cont_pending(&mut self, cx: &mut Context<'_>) -> IoPoll<()> {
        let fut = self.cont_pending_intern();
        pin_mut!(fut);
        fut.poll(cx)
    }

    fn poll_helper_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        do_full_flush: bool,
    ) -> IoPoll<()> {
        // we know about the PacketStream interna and know we don't need to wait for readyness.
        let this = Pin::into_inner(self);
        let threshold = if do_full_flush { 0 } else { PACKET_MAX_LEN - 1 };
        let mut sent_new_data = false;
        debug!(
            "buffered output len = {}; do full flush = {}",
            this.buf_out.len(),
            do_full_flush
        );
        while this.buf_out.len() > threshold {
            // cont_pending calls flush if necessary
            pollerfwd!(this.poll_cont_pending(cx));

            if let SessionState::Transport(ref mut tr, TrSubState::Transport) = &mut this.state {
                let inner_len = helper_send_packet(&mut this.parent, tr, &this.buf_out[..])?;
                this.buf_out.advance(inner_len);
                sent_new_data = true;
            } else {
                unreachable!("bug in cont_pending helper: expected yield, got invalid state");
            }
        }
        if sent_new_data {
            let parent = &mut this.parent;
            pin_mut!(parent);
            pollerfwd!(Sink::<&[u8]>::poll_flush(parent, cx));
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncBufRead for Session {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> IoPoll<&[u8]> {
        let this = Pin::into_inner(self);
        if this.buf_in.is_empty() {
            loop {
                pollerfwd!(this.poll_cont_pending(cx));
                {
                    let fut = this.helper_fill_bufin();
                    pin_mut!(fut);
                    pollerfwd!(fut.poll(cx));
                }
                if let SessionState::Transport(_, TrSubState::Transport) = &this.state {
                    break;
                }
                // if we aren't in the Transport/Transport state, re-run cont_pending
            }
        }
        Poll::Ready(Ok(&this.buf_in[..]))
    }

    #[inline]
    fn consume(mut self: Pin<&mut Self>, amt: usize) {
        self.buf_in.advance(amt)
    }
}

impl AsyncRead for Session {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> IoPoll<usize> {
        let mybuf = pollerfwd!(self.as_mut().poll_fill_buf(cx));
        let len = std::cmp::min(buf.len(), mybuf.len());
        buf[..len].copy_from_slice(&mybuf[..len]);
        self.consume(len);
        Poll::Ready(Ok(len))
    }
}

impl AsyncWrite for Session {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> IoPoll<usize> {
        pollerfwd!(self.as_mut().poll_helper_write(cx, false));
        // we can't simply do this before the partial flush,
        // because we can't 'roll back' in case of yielding or error
        self.buf_out.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> IoPoll<()> {
        self.poll_helper_write(cx, true)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> IoPoll<()> {
        pollerfwd!(self.as_mut().poll_flush(cx));
        let parent = &mut self.parent;
        pin_mut!(parent);
        Sink::<&[u8]>::poll_close(parent, cx)
    }
}
