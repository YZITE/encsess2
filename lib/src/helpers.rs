use std::future::Future;
use std::task::{Context, Poll};

use super::Side;

pub(crate) fn finish_builder_with_side(
    builder: snow::Builder<'_>,
    side: Side,
) -> Result<snow::HandshakeState, snow::Error> {
    match side {
        Side::Initiator => builder.build_initiator(),
        Side::Responder => builder.build_responder(),
    }
}

pub fn trf_err2io(x: crate::Error) -> std::io::Error {
    match x {
        crate::Error::Io(e) => e,
        crate::Error::Noise(e) => std::io::Error::new(std::io::ErrorKind::PermissionDenied, e),
    }
}

// shamelessly stolen from `crate smol`
pub fn poll_future<T>(cx: &mut Context<'_>, fut: impl Future<Output = T>) -> Poll<T> {
    futures_util::pin_mut!(fut);
    fut.poll(cx)
}
