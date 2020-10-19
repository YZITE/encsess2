#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub enum DHChoice {
    #[cfg_attr(feature = "serde", serde(rename = "25519"))]
    Ed25519,
    #[cfg_attr(feature = "serde", serde(rename = "448"))]
    Ed448,
}

impl From<snow::params::DHChoice> for DHChoice {
    fn from(x: snow::params::DHChoice) -> DHChoice {
        use snow::params::DHChoice as SnDhc;
        match x {
            SnDhc::Curve25519 => DHChoice::Ed25519,
            SnDhc::Ed448 => DHChoice::Ed448,
        }
    }
}

impl From<DHChoice> for snow::params::DHChoice {
    fn from(x: DHChoice) -> Self {
        use snow::params::DHChoice as SnDhc;
        match x {
            DHChoice::Ed25519 => SnDhc::Curve25519,
            DHChoice::Ed448 => SnDhc::Ed448,
        }
    }
}
