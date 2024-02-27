use crate::operations::OpCode;
use crate::rtp::RtpPayload;
use crate::rtpcodec::CodecFlag;
use crate::session::SessionInfo;
use ascii;

/// Header and trailer packets in-memory representation
#[derive(Copy, Clone)]
pub struct PacketNoPayload<'a> {
    pub(crate) opcode: OpCode,
    pub(crate) session: SessionInfo<'a>,
}

/// Payload packets in-memory representation
#[derive(Clone)]
pub struct PacketWithPayload<'a> {
    pub(crate) opcode: OpCode,
    pub(crate) session: SessionInfo<'a>,
    pub(crate) codec: CodecFlag,
    pub(crate) flags: u8,
    pub(crate) samplecount: u32,
    pub(crate) payload: RtpPayload,
}

/// Packets both with and without a payload must implement these traits
pub trait Packet {
    fn print(&self) -> Result<(), Box<dyn std::error::Error>>;
    fn debug(&self);
    fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>>;
}

/* Begin CallerIdLength Error */
/// Incorrect Caller ID Length error
#[derive(Debug, Clone)]
struct CallerIdLength;

impl std::fmt::Display for CallerIdLength {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "The Caller ID must be 13 characters or fewer")
    }
}

impl std::error::Error for CallerIdLength {}
/* End CallerIdLength Error */

/// Implement the Packet trait for PacketNoPayload
impl Packet for PacketNoPayload<'_> {
    /// This method will print the contents of the packet in a nice way using println!()
    fn print(&self) -> Result<(), Box<dyn std::error::Error>> {
        let callerid_ascii_result: Result<&ascii::AsciiStr, ascii::AsAsciiStrError> =
            ascii::AsciiStr::from_ascii(self.session.callerid);
        let callerid_ascii = match callerid_ascii_result {
            Ok(cid_result) => cid_result,
            Err(error) => return Err(Box::new(error)),
        };
        let mut callerid_bytes: [u8; 13] = [0; 13];
        let mut i = 0;
        if callerid_ascii.len() > 13 {
            return Err(Box::new(CallerIdLength));
        }
        for b in callerid_ascii.as_bytes() {
            callerid_bytes[i] = *b;
            i = i + 1;
        }
        println!("OpCode           : {}", self.opcode);
        println!("Channel Number   : {}", self.session.channelnum);
        println!("Host Serial      : {:X}", self.session.hostserial);
        println!("Caller ID Length : {}", self.session.callerid_len);
        println!("Caller ID        : {}", callerid_ascii);
        println!("=====================");
        Ok(())
    }

    /// This method will send the contents of the packet to log::debug in a nice way
    fn debug(&self) {
        log::debug!("OpCode           : {}", self.opcode);
        log::debug!("Channel Number   : {}", self.session.channelnum);
        log::debug!("Host Serial      : {:X}", self.session.hostserial);
        log::debug!("Caller ID Length : {}", self.session.callerid_len);
        log::debug!("Caller ID        : {}", self.session.callerid);
        log::debug!("=====================");
    }

    /// This method converts the packet struct to an array of u8 bytes to be transmitted over the
    /// network
    fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut value: Vec<u8> = Vec::new();
        value.push(self.opcode.to_u8());
        value.push(self.session.channelnum);
        for serial_byte in transform_u32_to_u8_array(self.session.hostserial) {
            value.push(serial_byte);
        }
        value.push(self.session.callerid_len);
        let callerid_ascii_result: Result<&ascii::AsciiStr, ascii::AsAsciiStrError> =
            ascii::AsciiStr::from_ascii(self.session.callerid);
        let callerid_ascii = match callerid_ascii_result {
            Ok(cid_result) => cid_result,
            Err(error) => return Err(Box::new(error)),
        };
        let mut callerid_bytes: [u8; 13] = [0; 13];
        let mut i = 0;
        if callerid_ascii.len() > 13 {
            return Err(Box::new(CallerIdLength));
        }
        for b in callerid_ascii.as_bytes() {
            callerid_bytes[i] = *b;
            i = i + 1;
        }
        for callerid_byte in &callerid_bytes {
            value.push(*callerid_byte);
        }
        // End Caller ID //

        Ok(value)
    }
}

/// Implement the Packet trait for PacketWithPayload
impl Packet for PacketWithPayload<'_> {
    /// This method will print the contents of the packet in a nice way using println!()
    fn print(&self) -> Result<(), Box<dyn std::error::Error>> {
        let callerid_ascii_result: Result<&ascii::AsciiStr, ascii::AsAsciiStrError> =
            ascii::AsciiStr::from_ascii(self.session.callerid);
        let callerid_ascii = match callerid_ascii_result {
            Ok(cid_result) => cid_result,
            Err(error) => return Err(Box::new(error)),
        };
        let mut callerid_bytes: [u8; 13] = [0; 13];
        let mut i = 0;
        if callerid_ascii.len() > 13 {
            return Err(Box::new(CallerIdLength));
        }
        for b in callerid_ascii.as_bytes() {
            callerid_bytes[i] = *b;
            i = i + 1;
        }
        println!("OpCode           : {}", self.opcode);
        println!("Channel Number   : {}", self.session.channelnum);
        println!("Host Serial      : {:X}", self.session.hostserial);
        println!("Caller ID Length : {}", self.session.callerid_len);
        println!("Caller ID        : {}", self.session.callerid);
        println!("Codec            : {}", self.codec);
        println!("Flags            : {}", self.flags);
        println!("Sample Count     : {}", self.samplecount);
        println!("Payload          : {:X}", self.payload);
        println!("=====================");
        Ok(())
    }

    /// This method will send the contents of the packet to log::debug in a nice way
    fn debug(&self) {
        log::debug!("OpCode           : {}", self.opcode);
        log::debug!("Channel Number   : {}", self.session.channelnum);
        log::debug!("Host Serial      : {:X}", self.session.hostserial);
        log::debug!("Caller ID Length : {}", self.session.callerid_len);
        log::debug!("Caller ID        : {}", self.session.callerid);
        log::debug!("Codec            : {}", self.codec);
        log::debug!("Flags            : {}", self.flags);
        log::debug!("Sample Count     : {}", self.samplecount);
        log::debug!("Payload          : {:X}", self.payload);
        log::debug!("=====================");
    }

    /// This method converts the packet struct to an array of u8 bytes to be transmitted over the
    /// network
    fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut value: Vec<u8> = Vec::new();
        value.push(self.opcode.to_u8());
        value.push(self.session.channelnum);
        for serial_byte in transform_u32_to_u8_array(self.session.hostserial) {
            value.push(serial_byte);
        }
        value.push(self.session.callerid_len);
        let callerid_ascii_result: Result<&ascii::AsciiStr, ascii::AsAsciiStrError> =
            ascii::AsciiStr::from_ascii(self.session.callerid);
        let callerid_ascii = match callerid_ascii_result {
            Ok(cid_result) => cid_result,
            Err(error) => return Err(Box::new(error)),
        };
        let mut callerid_bytes: [u8; 13] = [0; 13];
        let mut i = 0;
        if callerid_ascii.len() > 13 {
            return Err(Box::new(CallerIdLength));
        }
        for b in callerid_ascii.as_bytes() {
            callerid_bytes[i] = *b;
            i = i + 1;
        }
        for callerid_byte in &callerid_bytes {
            value.push(*callerid_byte);
        }
        value.push(self.codec.to_u8());
        value.push(self.flags);
        for sample_byte in transform_u32_to_u8_array(self.samplecount) {
            value.push(sample_byte);
        }
        for payload_byte in self.payload.data.clone() {
            value.push(payload_byte);
        }

        Ok(value)
    }
}

impl PacketWithPayload<'_> {
    pub fn from_buffer<'a>(
        session: SessionInfo<'a>,
        codec: CodecFlag,
        flags: u8,
        sample_count: &mut u32,
        mut last_chunk: Vec<u8>,
        buffer: &[u8],
    ) -> (Vec<u8>, PacketWithPayload<'a>) {
        // read up to 80 bytes
        let payload_len = buffer.len();
        let mut this_payload: Vec<u8> = Vec::new();
        let mut packet_payload: Vec<u8> = Vec::new();
        if last_chunk.len() != 0 {
            this_payload.append(&mut last_chunk.clone());
        };

        last_chunk.truncate(0);
        log::debug!("Payload Length: {payload_len}");
        assert!(payload_len <= 80);
        for packet_byte in buffer {
            packet_payload.push(packet_byte.clone());
            this_payload.push(packet_byte.clone());
        }
        for packet in packet_payload.clone() {
            last_chunk.push(packet);
        }
        let rtp_payload = RtpPayload {
            data: this_payload.clone(),
        };
        *sample_count += 160u32;
        let payload_packet = PacketWithPayload {
            opcode: OpCode::Transmit,
            session: session,
            codec: codec,
            flags: flags,
            samplecount: *sample_count,
            payload: rtp_payload,
        };
        (last_chunk, payload_packet)
    }
}

/// Transform hostserial to [u8, u8, u8, u8]
fn transform_u32_to_u8_array(x: u32) -> [u8; 4] {
    let b1: u8 = ((x >> 24) & 0xff) as u8;
    let b2: u8 = ((x >> 16) & 0xff) as u8;
    let b3: u8 = ((x >> 8) & 0xff) as u8;
    let b4: u8 = (x & 0xff) as u8;
    return [b1, b2, b3, b4];
}

// Begin Functions //
/// Helper function to get a new PacketNoPayload object for the "Alert" OpCode
pub fn get_alert(session: SessionInfo) -> PacketNoPayload {
    PacketNoPayload {
        opcode: OpCode::Alert,
        session: session,
    }
}

/// Helper function to get a new PacketNoPayload object for the "End" OpCode
pub fn get_end(session: SessionInfo) -> PacketNoPayload {
    PacketNoPayload {
        opcode: OpCode::End,
        session: session,
    }
}

/// Helper function to get an array of PacketWithPayload(s) to transmit the payload_bytes
/// this function splits the payload_bytes into 80 byte chunks and orders them appropriately for
/// Poly phone consumption
pub fn get_payload<'a>(
    session: SessionInfo<'a>,
    codec: CodecFlag,
    flags: u8,
    payload_bytes: &Vec<u8>,
) -> Vec<PacketWithPayload<'a>> {
    let mut result: Vec<PacketWithPayload> = Vec::new();

    let payload_len = payload_bytes.len();
    let chunk_num = payload_len / 80;
    log::debug!("Length: {}", payload_len);
    log::debug!("Chunks: {}", chunk_num);

    let mut last_chunk: Vec<u8> = Vec::new();
    let mut sample_count = 0u32;
    let mut this_payload: Vec<u8> = Vec::new();
    let mut packet_payload: Vec<u8> = Vec::new();
    for n in 0..payload_len {
        let this_byte: u8 = payload_bytes[n];
        if n % 80 == 0 {
            if n != 0 {
                this_payload.truncate(0);
                if last_chunk.len() != 0 {
                    this_payload.append(&mut last_chunk);
                };
                this_payload.append(&mut packet_payload.clone());
                last_chunk.truncate(0);
                for packet in packet_payload.clone() {
                    last_chunk.push(packet);
                }
                let rtp_payload = RtpPayload {
                    data: this_payload.clone(),
                };
                let payload_packet = PacketWithPayload {
                    opcode: OpCode::Transmit,
                    session: session,
                    codec: codec,
                    flags: flags,
                    samplecount: sample_count,
                    payload: rtp_payload,
                };
                result.push(payload_packet);
            }
            packet_payload.truncate(0);
            sample_count += 160u32;
        }
        packet_payload.push(this_byte);
    }

    result
}

/// Helper function to get an array of another array of bytes, from get_payload to transmit the
/// actual packets rather than the internal representation of an array of PacketWithPayload(s)
pub fn get_payload_packets(
    session: SessionInfo,
    codec: CodecFlag,
    flags: u8,
    data: &Vec<u8>,
) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    let mut result: Vec<Vec<u8>> = Vec::new();

    let payload_packets: Vec<PacketWithPayload> = get_payload(session, codec, flags, data);

    for packet_result in payload_packets {
        let t_bytes = packet_result.to_bytes()?;
        result.push(t_bytes);
    }

    Ok(result)
}

/// Public function to get the alert packet as array of bytes.
pub fn get_alert_packets(session: &SessionInfo) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let alert: PacketNoPayload = get_alert(*session);
    alert.to_bytes()
}

/// Public functinon to get the end packet as an array of bytes.
pub fn get_end_packets(session: &SessionInfo) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let end_packet: PacketNoPayload = get_end(*session);
    end_packet.to_bytes()
}

/// Public function to get a single payload packet as an array of bytes.
/// Takes the payload as a [u8; 80], aka, an 80 byte array
/// Must also include the last chunk of payload. On the first packet, the last_chunk must equal the payload_chunk
pub fn get_payload_packet(
    session: &SessionInfo,
    payload_chunk: &[u8; 80],
    last_chunk: &[u8; 80],
    codec: CodecFlag,
    flags: u8,
    sample_count: &mut u32,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut result: Vec<PacketWithPayload> = Vec::new();
    let mut this_payload: Vec<u8> = Vec::new();
    let mut packet_payload: Vec<u8> = Vec::new();
    let mut tmp_last_chunk: Vec<u8> = last_chunk.to_vec();
    this_payload.append(&mut tmp_last_chunk);
    this_payload.append(&mut packet_payload.clone());
    let rtp_payload = RtpPayload {
        data: this_payload.clone(),
    };
    *sample_count += 160u32;
    let payload_packet = PacketWithPayload {
        opcode: OpCode::Transmit,
        session: session.clone(),
        codec: codec,
        flags: flags,
        samplecount: *sample_count,
        payload: rtp_payload,
    };
    result.push(payload_packet);
    for n in 0..payload_chunk.len() {
        let this_byte: u8 = payload_chunk[n];
        packet_payload.push(this_byte);
    }
    result[0].to_bytes()
}
