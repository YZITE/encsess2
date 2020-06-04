use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures_util::io::{AsyncRead, AsyncWrite};
use futures_util::{pin_mut, ready, sink::Sink, stream::Stream};
use smol::Async;
use std::net::TcpStream;
use std::pin::Pin;
use std::task::{Context, Poll};
use tracing::debug;

pub struct PacketStream {
    stream: Async<TcpStream>,
    buf_in: BytesMut,
    buf_out: BytesMut,
    in_xpdlen: Option<usize>,
}

impl PacketStream {
    pub fn new(stream: Async<TcpStream>) -> Self {
        Self {
            stream,
            buf_in: BytesMut::new(),
            buf_out: BytesMut::new(),
            in_xpdlen: None,
        }
    }
}

impl Stream for PacketStream {
    type Item = std::io::Result<Bytes>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = Pin::into_inner(self);

        loop {
            if this.buf_in.len() >= 2 && this.in_xpdlen.is_none() {
                this.in_xpdlen = Some(this.buf_in.get_u16().into());
            }
            if let Some(expect_len) = this.in_xpdlen {
                if this.buf_in.len() >= expect_len {
                    // we are done, if we reach this,
                    // the length spec was already removed from buf_xin
                    this.in_xpdlen = None;
                    return Poll::Ready(Some(Ok(this.buf_in.split_to(expect_len).freeze())));
                }
            }

            // we need more data
            // the `read` might yield, and it should not leave any part of
            // `this` in an invalid state
            // assumption: `read` only yields if it has not read (and dropped) anything yet.
            let mut rdbuf = [0u8; crate::MAX_U16LEN];
            let stream = &mut this.stream;
            pin_mut!(stream);
            match ready!(stream.poll_read(cx, &mut rdbuf)) {
                Err(e) => return Poll::Ready(Some(Err(e))),
                Ok(0) => {
                    debug!("received EOF");
                    return Poll::Ready(None);
                }
                Ok(len) => {
                    debug!("received {} bytes", len);
                    this.buf_in.extend_from_slice(&rdbuf[..len]);
                }
            }
        }
    }
}

type SinkYield = Poll<Result<(), std::io::Error>>;

impl<B: AsRef<[u8]>> Sink<B> for PacketStream {
    type Error = std::io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> SinkYield {
        if self.buf_out.len() > u16::MAX.into() {
            pollerfwd!(Sink::<B>::poll_flush(self, cx));
        }
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: B) -> Result<(), std::io::Error> {
        use std::convert::TryInto;
        let buf_out = &mut self.get_mut().buf_out;
        let item = item.as_ref();
        buf_out.put_u16(item.len().try_into().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "length overflow")
        })?);
        buf_out.extend_from_slice(item);
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> SinkYield {
        let this = Pin::into_inner(self);
        let buf_out = &mut this.buf_out;
        let stream = &mut this.stream;
        pin_mut!(stream);
        // this part is easier... we just need to wait until all data is written
        while !buf_out.is_empty() {
            // every call to `write` might yield, and we must be sure to not send
            // data two times, and thus invalidating the data stream
            // assumption: `write` only yields if it has not written anything yet
            let len = pollerfwd!(stream.as_mut().poll_write(cx, &buf_out[..]));
            debug!("sent {} bytes", len);
            // drop written part
            buf_out.advance(len);
        }
        stream.poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> SinkYield {
        pollerfwd!(Sink::<B>::poll_flush(self.as_mut(), cx));
        let stream = &mut self.stream;
        pin_mut!(stream);
        stream.poll_close(cx)
    }
}
