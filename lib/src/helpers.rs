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

#[inline]
pub fn trf_err2io(x: impl Into<crate::Error>) -> std::io::Error {
    match x.into() {
        crate::Error::Io(e) => e,
        crate::Error::Noise(e) => std::io::Error::new(std::io::ErrorKind::PermissionDenied, e),
    }
}
