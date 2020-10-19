use secrecy::{zeroize::Zeroize, CloneableSecret, DebugSecret, Secret};

#[derive(Clone, Zeroize)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[zeroize(drop)]
pub struct Key(Vec<u8>);

impl CloneableSecret for Key {}
impl DebugSecret for Key {}

#[cfg(feature = "serde")]
impl SerializableSecret for Key {}

impl std::ops::Deref for Key {
    type Target = [u8];
    #[inline(always)]
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

pub type SecretKey = Secret<Key>;

#[inline]
pub fn new_key(data: Vec<u8>) -> SecretKey {
    // we can do this because data is heap-allocated
    Secret::new(Key(data))
}
