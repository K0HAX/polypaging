use ascii;
use clap::ValueEnum;
use log;
use std::net::Ipv4Addr;
use std::str;
use std::{process, thread, time};
use tokio::net::UdpSocket;

// Begin RTP Specific Code //
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
// End RTP Specific Code //

// Begin PolyPaging Specific Code //
/// Per-packet OpCode used by Poly phones to determine which type of packet this is
#[derive(Copy, Clone)]
enum OpCode {
    Alert,
    Transmit,
    End,
}

impl OpCode {
    fn to_u8(&self) -> u8 {
        match self {
            OpCode::Alert => 0x0fu8,
            OpCode::Transmit => 0x10u8,
            OpCode::End => 0xffu8,
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

/// Paging supports two codecs, select the one you are using
#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum CodecFlag {
    /// G711µ
    G711u,

    /// G722
    G722,
}

impl CodecFlag {
    fn to_u8(&self) -> u8 {
        match self {
            CodecFlag::G711u => 0x00u8,
            CodecFlag::G722 => 0x09u8,
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

/// This information doesn't change during a session, so we can pass it by ref to other functions
/// in this library
#[derive(Copy, Clone)]
pub struct SessionInfo<'a> {
    pub channelnum: u8,
    pub hostserial: u32,
    pub callerid_len: u8,
    pub callerid: &'a str,
}

/// Header and trailer packets in-memory representation
#[derive(Copy, Clone)]
pub struct PacketNoPayload<'a> {
    opcode: OpCode,
    session: SessionInfo<'a>,
}

/// Payload packets in-memory representation
#[derive(Clone)]
pub struct PacketWithPayload<'a> {
    opcode: OpCode,
    session: SessionInfo<'a>,
    codec: CodecFlag,
    flags: u8,
    samplecount: u32,
    payload: RtpPayload,
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

/* Begin ChannelOutOfRange Error */
/// Channel out of range error
#[derive(Debug, Clone)]
struct ChannelOutOfRange;

impl std::fmt::Display for ChannelOutOfRange {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "The channel must be between 1 and 50.")
    }
}

impl std::error::Error for ChannelOutOfRange {}
/* End ChannelOutOfRange Error */

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

// FileBytes //
/// This object holds the actual data of a file in memory
pub struct FileBytes {
    pub contents: Vec<u8>,
}

impl FileBytes {
    /// Create a new FileBytes using the contents of a file referenced by filename as its data
    pub fn from_file(filename: &str) -> Result<FileBytes, std::io::Error> {
        let result = std::fs::read(filename);
        match result {
            Ok(filebytes) => Ok(FileBytes {
                contents: filebytes,
            }),
            Err(error) => return Err(error),
        }
    }

    pub fn from_bytes(data: Vec<u8>) -> Result<FileBytes, std::io::Error> {
        Ok(FileBytes { contents: data })
    }
}

impl std::fmt::UpperHex for FileBytes {
    /// Format a FileBytes object as a string of upper-case hex bytes for debugging
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut fmt_string = String::new();
        for byte in &self.contents {
            let byte_string: String = format!("{:02X}", byte);
            fmt_string.push_str(byte_string.as_str());
        }

        write!(f, "{}", fmt_string)
    }
}

// Begin Functions //
/// Transform hostserial to [u8, u8, u8, u8]
fn transform_u32_to_u8_array(x: u32) -> [u8; 4] {
    let b1: u8 = ((x >> 24) & 0xff) as u8;
    let b2: u8 = ((x >> 16) & 0xff) as u8;
    let b3: u8 = ((x >> 8) & 0xff) as u8;
    let b4: u8 = (x & 0xff) as u8;
    return [b1, b2, b3, b4];
}

/// Helper function to get a new SessionInfo object
pub fn get_session(
    channel_num: u8,
    host_serial: u32,
    caller_id: &str,
) -> Result<SessionInfo, Box<dyn std::error::Error>> {
    let callerid_len = 13u8;
    if (channel_num > 50) || (channel_num < 1) {
        return Err(Box::new(ChannelOutOfRange));
    }
    Ok(SessionInfo {
        channelnum: channel_num,
        hostserial: host_serial,
        callerid_len: callerid_len,
        callerid: caller_id,
    })
}

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

/// Public function to println!() (mostly) what the do_transmit function would do, but don't actually
/// transmit any packets
pub fn do_print(file_bytes: &FileBytes, callerid: &str, codec: CodecFlag, channel: u8) {
    let alert_gap = time::Duration::from_millis(30);
    let session: SessionInfo =
        get_session(channel, 0x00000000u32, &callerid).unwrap_or_else(|err| {
            println!("Problem getting session info: {err}");
            process::exit(1);
        });
    let alert: PacketNoPayload = get_alert(session);
    let end: PacketNoPayload = get_end(session);

    /* Begin! */
    for _ in 0..31 {
        thread::sleep(alert_gap);
        //let alert_printable: PrintableU8Vec = PrintableU8Vec(alert.to_bytes().unwrap());
        //println!("{:02X}", alert_printable);
        alert.print().unwrap_or_else(|err| {
            println!("Problem printing alert: {err}");
            process::exit(1);
        });
    }
    ////////////////

    /* Payload! */
    let payload_packets: Vec<PacketWithPayload> =
        get_payload(session, codec, 0u8, &file_bytes.contents);

    for payload_packet in payload_packets {
        //let payload_printable: PrintableU8Vec = PrintableU8Vec(payload_packet.clone());
        //println!("{:02X}", payload_printable);
        payload_packet.print().unwrap_or_else(|err| {
            println!("Problem printing payload packet: {err}");
            process::exit(1);
        });
    }
    ////////////////

    /* End! */
    for _ in 0..12 {
        thread::sleep(alert_gap);
        //let end_printable: PrintableU8Vec = PrintableU8Vec(end.to_bytes().unwrap());
        //println!("{:02X}", end_printable);
        end.print().unwrap_or_else(|err| {
            println!("Problem printing end packet: {err}");
            process::exit(1);
        });
    }
}

/// Transmit a file, passed in as &FileBytes, to Poly phones via IP multicast. This function
/// handles all parsing and timing, as well as IGMP setup to join the multicast group.
pub async fn do_transmit(
    file_bytes: FileBytes,
    callerid: String,
    codec: CodecFlag,
    channel: u8,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let alert_gap = time::Duration::from_millis(30);
    let join_gap = time::Duration::from_millis(500);
    let tx_gap = time::Duration::from_millis(10);
    let session: SessionInfo =
        get_session(channel, 0x00000000u32, &callerid).unwrap_or_else(|err| {
            println!("Problem getting session info: {err}");
            process::exit(1);
        });
    let alert: PacketNoPayload = get_alert(session);
    let end: PacketNoPayload = get_end(session);

    let payload_packets: Vec<Vec<u8>> =
        get_payload_packets(session, codec, 0u8, &file_bytes.contents).unwrap_or_else(|err| {
            println!("Problem generating payload packets: {err}");
            process::exit(1);
        });

    let sock = UdpSocket::bind("0.0.0.0:5001").await?;
    let remote_addr = "224.0.1.116:5001";
    let v4_mcast_addr = Ipv4Addr::new(224, 0, 1, 116);
    let v4_local_addr = Ipv4Addr::new(0, 0, 0, 0);
    sock.connect(remote_addr).await?;
    sock.join_multicast_v4(v4_mcast_addr, v4_local_addr)?;

    thread::sleep(join_gap);

    /* Begin! */
    let alert_bytes: Vec<u8> = alert.to_bytes().unwrap_or_else(|err| {
        println!("Problem getting alert packet bytes: {err}");
        process::exit(1);
    });
    alert.debug();
    for _ in 0..31 {
        sock.send(&alert_bytes).await?;
        thread::sleep(alert_gap);
    }
    ////////////////

    /* Payload! */
    for payload_packet in payload_packets {
        let payload_bytes: Vec<u8> = payload_packet.clone();
        sock.send(&payload_bytes).await?;
        thread::sleep(tx_gap);
    }
    ////////////////

    /* End! */
    end.debug();
    let end_bytes: Vec<u8> = end.to_bytes().unwrap_or_else(|err| {
        println!("Problem getting end packet bytes: {err}");
        process::exit(1);
    });
    for _ in 0..12 {
        sock.send(&end_bytes).await?;
        thread::sleep(alert_gap);
    }
    Ok(())
}

// End Functions //

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn good_session() {
        let result = get_session(49u8, 0x00000000u32, "CallerID").unwrap();
        assert_eq!(result.channelnum, 49u8);
        assert_eq!(result.hostserial, 0x00000000u32);
        assert_eq!(result.callerid_len, 13u8);
        assert_eq!(result.callerid, "CallerID");
    }

    #[test]
    fn good_alert() {
        let session = get_session(49u8, 0x00000000u32, "CallerID").unwrap();
        let result = get_alert(session);

        assert_eq!(result.session.channelnum, 49u8);
        assert_eq!(result.session.hostserial, 0x00000000u32);
        assert_eq!(result.session.callerid_len, 13u8);
        assert_eq!(result.session.callerid, "CallerID");
        assert!(matches!(result.opcode, OpCode::Alert));
    }

    #[test]
    fn good_alert_packet() {
        let session = get_session(49u8, 0x00000000u32, "CallerID").unwrap();
        let result = get_alert_packets(&session).unwrap();
        assert_eq!(
            result,
            [15, 49, 0, 0, 0, 0, 13, 67, 97, 108, 108, 101, 114, 73, 68, 0, 0, 0, 0, 0]
        )
    }

    #[test]
    fn good_end() {
        let session = get_session(49u8, 0x00000000u32, "CallerID").unwrap();
        let result = get_end(session);

        assert_eq!(result.session.channelnum, 49u8);
        assert_eq!(result.session.hostserial, 0x00000000u32);
        assert_eq!(result.session.callerid_len, 13u8);
        assert_eq!(result.session.callerid, "CallerID");
        assert!(matches!(result.opcode, OpCode::End));
    }

    #[test]
    fn good_end_packet() {
        let session = get_session(49u8, 0x00000000u32, "CallerID").unwrap();
        let result = get_end_packets(&session).unwrap();
        assert_eq!(
            result,
            [255, 49, 0, 0, 0, 0, 13, 67, 97, 108, 108, 101, 114, 73, 68, 0, 0, 0, 0, 0]
        )
    }

    #[test]
    fn good_payload() {
        let session = get_session(49u8, 0x00000000u32, "CallerID").unwrap();
        let payload: Vec<u8> = b"\xDE\x7A\xF2\x77\xDC\xF2\xF5\xDB\x71\xDE\xB2\xAF\xB9\xB4\x9F\x9D\xF6\xF3\xED\x72\xF2\xAE\xB6\xF6\xF9\xF7\xDC\xDE\xF8\x7E\xF4\xB1\xBA\xF7\xDC\xDE\x76\xF8\xB1\xF4\xFA\xF7\xBA\xDE\xFC\xFA\xDE\xF8\xBC\x7E\xB6\xDE\xF3\xF6\xF4\xFC\xF6\xB2\xF6\x74\xDB\xBE\x9B\xDE\x7A\xDE\xFA\xB7\xF7\x7A\xB7\xFC\xF7\xFE\xFA\x76\xB7\xF6\xF7\xF7\x00".to_vec();
        let result_packet = get_payload(session, CodecFlag::G722, 0u8, &payload);
        let result = result_packet[0].to_bytes().unwrap();
        // 0x10 = Transmit
        // 0x31 = channel 49
        // 8 bytes for serial number
        // 0x0d = 13 (The Caller ID length is ALWAYS 13 bytes)
        // <13 byte Caller ID>
        // 0x09 = G722
        // 0x000000 = flags
        // 0xA0 = 160 (sample)
        let check_bytes: Vec<u8> = b"\x10\x31\x00\x00\x00\x00\x0dCallerID\x00\x00\x00\x00\x00\x09\x00\x00\x00\x00\xA0\xDE\x7A\xF2\x77\xDC\xF2\xF5\xDB\x71\xDE\xB2\xAF\xB9\xB4\x9F\x9D\xF6\xF3\xED\x72\xF2\xAE\xB6\xF6\xF9\xF7\xDC\xDE\xF8\x7E\xF4\xB1\xBA\xF7\xDC\xDE\x76\xF8\xB1\xF4\xFA\xF7\xBA\xDE\xFC\xFA\xDE\xF8\xBC\x7E\xB6\xDE\xF3\xF6\xF4\xFC\xF6\xB2\xF6\x74\xDB\xBE\x9B\xDE\x7A\xDE\xFA\xB7\xF7\x7A\xB7\xFC\xF7\xFE\xFA\x76\xB7\xF6\xF7\xF7".to_vec();
        assert_eq!(result, check_bytes);
    }

    #[test]
    fn good_payload_packet() {
        let session = get_session(49u8, 0x00000000u32, "CallerID").unwrap();
        let payload_chunk: [u8; 80] = *b"\xDE\x7A\xF2\x77\xDC\xF2\xF5\xDB\x71\xDE\xB2\xAF\xB9\xB4\x9F\x9D\xF6\xF3\xED\x72\xF2\xAE\xB6\xF6\xF9\xF7\xDC\xDE\xF8\x7E\xF4\xB1\xBA\xF7\xDC\xDE\x76\xF8\xB1\xF4\xFA\xF7\xBA\xDE\xFC\xFA\xDE\xF8\xBC\x7E\xB6\xDE\xF3\xF6\xF4\xFC\xF6\xB2\xF6\x74\xDB\xBE\x9B\xDE\x7A\xDE\xFA\xB7\xF7\x7A\xB7\xFC\xF7\xFE\xFA\x76\xB7\xF6\xF7\xF7";
        let last_chunk: [u8; 80] = *b"\xDE\x7A\xF2\x77\xDC\xF2\xF5\xDB\x71\xDE\xB2\xAF\xB9\xB4\x9F\x9D\xF6\xF3\xED\x72\xF2\xAE\xB6\xF6\xF9\xF7\xDC\xDE\xF8\x7E\xF4\xB1\xBA\xF7\xDC\xDE\x76\xF8\xB1\xF4\xFA\xF7\xBA\xDE\xFC\xFA\xDE\xF8\xBC\x7E\xB6\xDE\xF3\xF6\xF4\xFC\xF6\xB2\xF6\x74\xDB\xBE\x9B\xDE\x7A\xDE\xFA\xB7\xF7\x7A\xB7\xFC\xF7\xFE\xFA\x76\xB7\xF6\xF7\xF7";
        let codec = CodecFlag::G722;
        let flags: u8 = 0u8;
        let mut sample_count: u32 = 0u32;
        let result = get_payload_packet(
            &session,
            &payload_chunk,
            &last_chunk,
            codec,
            flags,
            &mut sample_count,
        )
        .unwrap();
        let check_bytes: Vec<u8> = b"\x10\x31\x00\x00\x00\x00\x0dCallerID\x00\x00\x00\x00\x00\x09\x00\x00\x00\x00\xA0\xDE\x7A\xF2\x77\xDC\xF2\xF5\xDB\x71\xDE\xB2\xAF\xB9\xB4\x9F\x9D\xF6\xF3\xED\x72\xF2\xAE\xB6\xF6\xF9\xF7\xDC\xDE\xF8\x7E\xF4\xB1\xBA\xF7\xDC\xDE\x76\xF8\xB1\xF4\xFA\xF7\xBA\xDE\xFC\xFA\xDE\xF8\xBC\x7E\xB6\xDE\xF3\xF6\xF4\xFC\xF6\xB2\xF6\x74\xDB\xBE\x9B\xDE\x7A\xDE\xFA\xB7\xF7\x7A\xB7\xFC\xF7\xFE\xFA\x76\xB7\xF6\xF7\xF7".to_vec();
        assert_eq!(result, check_bytes);
    }

    #[test]
    #[should_panic]
    fn bad_callerid() {
        let session = get_session(49u8, 0x00000000u32, "CallerID12345678").unwrap();
        let payload: Vec<u8> = b"\xDE\x7A\xF2\x77\xDC\xF2\xF5\xDB\x71\xDE\xB2\xAF\xB9\xB4\x9F\x9D\xF6\xF3\xED\x72\xF2\xAE\xB6\xF6\xF9\xF7\xDC\xDE\xF8\x7E\xF4\xB1\xBA\xF7\xDC\xDE\x76\xF8\xB1\xF4\xFA\xF7\xBA\xDE\xFC\xFA\xDE\xF8\xBC\x7E\xB6\xDE\xF3\xF6\xF4\xFC\xF6\xB2\xF6\x74\xDB\xBE\x9B\xDE\x7A\xDE\xFA\xB7\xF7\x7A\xB7\xFC\xF7\xFE\xFA\x76\xB7\xF6\xF7\xF7\x00".to_vec();
        let result_packet = get_payload(session, CodecFlag::G722, 0u8, &payload);
        let result = result_packet[0].to_bytes().unwrap();
        // 0x10 = Transmit
        // 0x31 = channel 49
        // 8 bytes for serial number
        // 0x0d = 13 (The Caller ID length is ALWAYS 13 bytes)
        // <13 byte Caller ID>
        // 0x09 = G722
        // 0x000000 = flags
        // 0xA0 = 160 (sample)
        let check_bytes: Vec<u8> = b"\x10\x31\x00\x00\x00\x00\x0dCallerID\x00\x00\x00\x00\x00\x09\x00\x00\x00\x00\xA0\xDE\x7A\xF2\x77\xDC\xF2\xF5\xDB\x71\xDE\xB2\xAF\xB9\xB4\x9F\x9D\xF6\xF3\xED\x72\xF2\xAE\xB6\xF6\xF9\xF7\xDC\xDE\xF8\x7E\xF4\xB1\xBA\xF7\xDC\xDE\x76\xF8\xB1\xF4\xFA\xF7\xBA\xDE\xFC\xFA\xDE\xF8\xBC\x7E\xB6\xDE\xF3\xF6\xF4\xFC\xF6\xB2\xF6\x74\xDB\xBE\x9B\xDE\x7A\xDE\xFA\xB7\xF7\x7A\xB7\xFC\xF7\xFE\xFA\x76\xB7\xF6\xF7\xF7".to_vec();
        assert_eq!(result, check_bytes);
    }
}
