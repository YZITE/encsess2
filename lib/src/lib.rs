#![forbid(unsafe_code)]

use async_net::TcpStream;
use futures_lite::{ready, AsyncBufRead, AsyncRead, AsyncWrite, Stream};
use futures_micro::poll_fn;
use std::task::{Context, Poll};
use std::{io, pin::Pin, sync::Arc};
use tracing::debug;
use yz_packet_stream::PacketStream;
use zeroize::{Zeroize, Zeroizing};

lazy_static::lazy_static! {
    static ref NOISE_PARAMS: snow::params::NoiseParams
      = "Noise_XK_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
    static ref NOISE_PARAMS_REHS: snow::params::NoiseParams
      = "Noise_KK_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
}

type IoPoll<T> = Poll<io::Result<T>>;

const MAX_U16LEN: usize = 0xffff;
const PACKET_MAX_LEN: usize = MAX_U16LEN - 20 - 1;
const MAX_NONCE_VALUE: u64 = 10;

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

#[inline(always)]
fn trf_err2io(x: snow::Error) -> io::Error {
    io::Error::new(io::ErrorKind::Other, x)
}

fn finish_builder_with_side(
    builder: snow::Builder<'_>,
    side: Side,
) -> io::Result<snow::HandshakeState> {
    match side {
        Side::Initiator => builder.build_initiator(),
        Side::Responder => builder.build_responder(),
    }
    .map_err(trf_err2io)
}

type PacketTcpStream = PacketStream<TcpStream>;

#[inline]
pub fn generate_keypair() -> Result<snow::Keypair, snow::Error> {
    Ok(snow::Builder::new(NOISE_PARAMS.clone()).generate_keypair()?)
}

fn helper_send_packet(
    pktstream: &mut PacketTcpStream,
    tr: &mut snow::TransportState,
    pktbuf: &[u8],
) -> io::Result<usize> {
    const PAD_TRG_SIZE: usize = 64;
    use std::convert::TryInto;
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
    inner_full.extend_from_slice(&u16::to_be_bytes(inner_len.try_into().unwrap())[..]);
    inner_full.extend_from_slice(&pktbuf[..inner_len]);
    inner_full.resize(wopad_len + padding_len, 0);
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut inner_full[wopad_len..]);
    let mut tmp = [0u8; MAX_U16LEN];
    let len = tr
        .write_message(&inner_full[..], &mut tmp[..])
        .map_err(trf_err2io)?;
    Pin::new(pktstream).enqueue(&tmp[..len])?;
    Ok(inner_len)
}

pub struct Session {
    parent: PacketTcpStream,
    config: Arc<Config>,
    state: SessionState,

    buf_in: Vec<u8>,
    buf_out: Vec<u8>,
}

impl Session {
    pub async fn new(stream: TcpStream, config: Arc<Config>) -> io::Result<Session> {
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
            buf_in: Vec::new(),
            buf_out: Vec::new(),
        };

        // perform handshake without code duplication
        poll_fn(|cx| this.poll_cont_pending(cx)).await?;

        Ok(this)
    }

    /// Tries to extract the remote party's static public key from the noise state.
    #[inline]
    pub fn remote_static_pubkey(&self) -> Option<&[u8]> {
        match &self.state {
            SessionState::Transport(x, _) => x.get_remote_static(),
            SessionState::Handshake(x) => x.get_remote_static(),
        }
    }

    /// Returns the local address this stream is bound to.
    #[inline]
    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.parent.get_ref().local_addr()
    }

    /// Returns the remote address this stream is connected to.
    #[inline]
    pub fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.parent.get_ref().peer_addr()
    }

    fn poll_helper_fill_bufin(&mut self, cx: &mut Context<'_>) -> IoPoll<()> {
        if let SessionState::Transport(ref mut tr, ref mut substate) = &mut self.state {
            if let Some(blob) = ready!(Pin::new(&mut self.parent).poll_next(cx)) {
                let mut buf_in = Vec::with_capacity(MAX_U16LEN);
                buf_in.resize(MAX_U16LEN, 0);
                let len = tr
                    .read_message(&(blob?)[..], &mut buf_in[..])
                    .map_err(trf_err2io)?;
                let mut inner_len = [0u8; 2usize];
                inner_len.copy_from_slice(&buf_in[..2]);
                let inner_len: usize = u16::from_be_bytes(inner_len).into();
                debug!("got len = {}, inner_len = {}", len, inner_len);
                if inner_len > (len - 2) {
                    // do not panic if out-of-bounds
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "inner length out of bounds",
                    )));
                }
                if inner_len == 0 {
                    // got a token.
                    use TrSubState as TSS;
                    match substate {
                        TSS::Transport => {
                            // we didn't sent a token ourselves, do it now
                            // we don't need to clear the output buffer
                            *substate = TSS::Handshake;
                            helper_send_packet(&mut self.parent, tr, &[])?;
                            ready!(Pin::new(&mut self.parent).poll_flush(cx)?);
                        }
                        TSS::ScheduledHandshake => {
                            // we already sent a token ourselves, do nothing
                            *substate = TSS::Handshake;
                        }
                        TSS::Handshake => {
                            unreachable!("got a token while preparing for handshake, missing call to cont_pending?");
                        }
                    }
                    // NOTE: we need to check the substate in poll_fill_buf to be sure
                    // to not return EOF when we are in the Handshake substate
                } else {
                    self.buf_in.extend_from_slice(&(&buf_in[2..])[..inner_len]);
                }
            }
        }
        Poll::Ready(Ok(()))
    }

    fn poll_cont_pending(&mut self, cx: &mut Context<'_>) -> IoPoll<()> {
        // perform all state transitions
        loop {
            let config = &self.config;
            let parent = &self.parent;
            match &mut self.state {
                SessionState::Transport(ref mut tr, ref mut subst @ TrSubState::Transport)
                    if tr.sending_nonce() >= MAX_NONCE_VALUE =>
                {
                    // we don't need to save $need2send_token in TrSubState,
                    // because we have no yield point between setting and checking it
                    *subst = TrSubState::ScheduledHandshake;
                    helper_send_packet(&mut self.parent, tr, &[])?;
                    ready!(Pin::new(&mut self.parent).poll_flush(cx)?);
                }

                SessionState::Transport(tr, TrSubState::ScheduledHandshake) => {
                    // we need to wait until we get a token from the other peer
                    if tr.receiving_nonce() == (MAX_NONCE_VALUE + 1) {
                        tracing::warn!("expected handshake token from other peer, but didn't get one");
                    }
                    ready!(self.poll_helper_fill_bufin(cx)?);
                }

                SessionState::Transport(tr, TrSubState::Handshake) => {
                    debug!("begin handshake with {:?}", parent);
                    self.state = SessionState::Handshake(
                        finish_builder_with_side(
                            snow::Builder::new(NOISE_PARAMS_REHS.clone())
                                .local_private_key(&config.privkey[..])
                                .remote_public_key(tr.get_remote_static().unwrap()),
                            config.side.side(),
                        )
                        .expect("unable to build HandshakeState"),
                    );
                }

                SessionState::Handshake(hs) if hs.is_handshake_finished() => {
                    debug!("finish handshake with {:?}", parent);
                    take_mut::take(&mut self.state, |state| {
                        let (tr, subst) = match state {
                            SessionState::Handshake(hs) => (
                                hs.into_transport_mode()
                                    .expect("unable to build TransportState"),
                                TrSubState::Transport,
                            ),
                            SessionState::Transport(tr, subst) => (tr, subst),
                        };
                        SessionState::Transport(tr, subst)
                    });
                }

                _ => {}
            }

            // we can now deal with a state which doesn't need to change
            // this function is reentrant, because the state of our state machine is
            // put into self.state

            match &mut self.state {
                SessionState::Handshake(ref mut noise) => {
                    // any `ready!` might yield and nuke `tmp`
                    let mut tmp = [0u8; MAX_U16LEN];
                    loop {
                        // this might yield, but that's ok
                        ready!(Pin::new(&mut self.parent).poll_flush(cx)?);
                        if noise.is_handshake_finished() {
                            break;
                        } else if noise.is_my_turn() {
                            let len = noise
                                .write_message(&[], &mut tmp[..])
                                .expect("unable to create noise handshake message");
                            // this might yield if err, but the item won't get lost
                            Pin::new(&mut self.parent).enqueue(&tmp[..len])?;
                        } else {
                            // this line might yield and nuke `tmp`
                            match ready!(Pin::new(&mut self.parent).poll_next(cx)) {
                                Some(x) => {
                                    let _ = noise
                                        .read_message(&(x?)[..], &mut tmp[..])
                                        .map_err(trf_err2io)?;
                                }
                                None => {
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::UnexpectedEof,
                                        "eof while handshaking",
                                    )));
                                }
                            }
                        }
                    }
                }
                SessionState::Transport(_, TrSubState::ScheduledHandshake) | SessionState::Transport(_, TrSubState::Handshake) => {}
                SessionState::Transport(_, TrSubState::Transport) => return Poll::Ready(Ok(())),
            }
        }
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
            ready!(this.poll_cont_pending(cx)?);

            if let SessionState::Transport(ref mut tr, TrSubState::Transport) = &mut this.state {
                let inner_len = helper_send_packet(&mut this.parent, tr, &this.buf_out[..])?;
                let _ = this.buf_out.drain(..inner_len);
                sent_new_data = true;
            } else {
                unreachable!("bug in cont_pending helper: expected yield, got invalid state");
            }
        }
        if sent_new_data {
            ready!(Pin::new(&mut this.parent).poll_flush(cx)?);
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncBufRead for Session {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> IoPoll<&[u8]> {
        let this = Pin::into_inner(self);
        while this.buf_in.is_empty() {
            ready!(this.poll_cont_pending(cx)?);
            ready!(this.poll_helper_fill_bufin(cx)?);
            if let SessionState::Transport(_, TrSubState::Transport) = &this.state {
                break;
            }
            // if we aren't in the Transport/Transport state, re-run cont_pending
        }
        Poll::Ready(Ok(&this.buf_in[..]))
    }

    #[inline]
    fn consume(mut self: Pin<&mut Self>, amt: usize) {
        let _ = self.buf_in.drain(..amt);
    }
}

impl AsyncRead for Session {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> IoPoll<usize> {
        let mybuf = ready!(self.as_mut().poll_fill_buf(cx)?);
        let len = std::cmp::min(buf.len(), mybuf.len());
        buf[..len].copy_from_slice(&mybuf[..len]);
        self.consume(len);
        Poll::Ready(Ok(len))
    }
}

impl AsyncWrite for Session {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> IoPoll<usize> {
        ready!(self.as_mut().poll_helper_write(cx, false)?);
        // we can't simply do this before the partial flush,
        // because we can't 'roll back' in case of yielding or error
        self.buf_out.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> IoPoll<()> {
        self.poll_helper_write(cx, true)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> IoPoll<()> {
        ready!(self.as_mut().poll_flush(cx)?);
        Pin::new(&mut self.parent).poll_close(cx)
    }
}
