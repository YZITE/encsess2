use crate::helpers::poll_future;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures_util::{io::AsyncWrite, pin_mut, sink::Sink, stream::Stream};
use smol::Async;
use std::net::TcpStream;
use std::pin::Pin;
use std::task::{Context, Poll};

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

    async fn recv(&mut self) -> std::io::Result<Option<Bytes>> {
        loop {
            if self.buf_in.len() >= 2 && self.in_xpdlen.is_none() {
                self.in_xpdlen = Some(self.buf_in.get_u16().into());
            }
            if let Some(expect_len) = self.in_xpdlen {
                if self.buf_in.len() >= expect_len {
                    // we are done, if we reach this,
                    // the length spec was already removed from buf_xin
                    self.in_xpdlen = None;
                    return Ok(Some(self.buf_in.split_to(expect_len).freeze()));
                }
            }

            // we need more data
            let mut rdbuf = [0u8; 8192];
            // the `read` might yield, and it should not leave any part of
            // `self` in an invalid state
            // assumption: `read` only yields if it has not read (and dropped) anything yet.
            use futures_util::io::AsyncReadExt;
            let len = self.stream.read(&mut rdbuf).await?;
            if len == 0 {
                return Ok(None);
            }
            self.buf_in.extend_from_slice(&rdbuf[..len]);
        }
    }

    /// you can call this function alternatively to `poll_ready`
    async fn flush_and_ready(&mut self) -> std::io::Result<()> {
        use futures_util::io::AsyncWriteExt;
        // this part is easier... we just need to wait until all data is written
        while !self.buf_out.is_empty() {
            // every call to `write` might yield, and we must be sure to not send
            // data two times, and thus invalidating the data stream
            // assumption: `write` only yields if it has not written anything yet.
            let len = self.stream.write(&self.buf_out[..]).await?;
            // drop written part
            let _ = self.buf_out.split_to(len);
        }
        self.stream.flush().await?;
        Ok(())
    }
}

impl Stream for PacketStream {
    type Item = std::io::Result<Bytes>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        poll_future(cx, async move {
            match self.get_mut().recv().await {
                Ok(o) => o.map(Ok),
                Err(e) => Some(Err(e)),
            }
        })
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

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> SinkYield {
        poll_future(cx, self.get_mut().flush_and_ready())
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> SinkYield {
        pollerfwd!(Sink::<B>::poll_flush(self.as_mut(), cx));
        let stream = &mut self.stream;
        pin_mut!(stream);
        stream.poll_close(cx)
    }
}
