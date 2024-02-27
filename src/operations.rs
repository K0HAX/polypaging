use crate::consts::*;

/// Per-packet OpCode used by Poly phones to determine which type of packet this is
#[derive(Copy, Clone)]
pub enum OpCode {
    Alert,
    Transmit,
    End,
}

impl OpCode {
    pub fn to_u8(&self) -> u8 {
        match self {
            OpCode::Alert => OP_ALERT,
            OpCode::Transmit => OP_TRANSMIT,
            OpCode::End => OP_END,
        }
    }
}

impl std::fmt::Display for OpCode {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            OpCode::Alert => write!(f, "Alert [0x0f]"),
            OpCode::Transmit => write!(f, "Transmit [0x10]"),
            OpCode::End => write!(f, "End [0xff]"),
        }
    }
}
