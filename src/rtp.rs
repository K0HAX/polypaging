/// Array of bytes that make up the raw RTP payload
#[derive(Clone)]
pub struct RtpPayload {
    pub data: Vec<u8>,
}

impl std::fmt::UpperHex for RtpPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut fmt_string = String::new();
        for byte in &self.data {
            let byte_string: String = format!("{:X}", byte);
            fmt_string.push_str(byte_string.as_str());
        }

        write!(f, "{}", fmt_string)
    }
}
