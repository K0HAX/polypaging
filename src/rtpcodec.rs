use crate::consts::*;
use clap::ValueEnum;

/// Paging supports two codecs, select the one you are using
#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum CodecFlag {
    /// G711µ
    G711u,

    /// G722
    G722,
}

impl CodecFlag {
    pub fn to_u8(&self) -> u8 {
        match self {
            CodecFlag::G711u => G711U,
            CodecFlag::G722 => G722,
        }
    }
}

impl std::fmt::Display for CodecFlag {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            CodecFlag::G711u => write!(f, "G711µ [0x00]"),
            CodecFlag::G722 => write!(f, "G722  [0x09]"),
        }
    }
}
