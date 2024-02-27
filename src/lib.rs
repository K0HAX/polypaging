use crate::packet::{
    get_alert, get_end, get_payload, get_payload_packets, Packet, PacketNoPayload,
    PacketWithPayload,
};
use crate::rtpcodec::CodecFlag;
use crate::session::{get_session, SessionInfo};

use log;
use std::io::BufRead;
use std::net::Ipv4Addr;
use std::str;
use std::{process, thread, time};
use tokio::net::UdpSocket;

pub mod consts;
pub mod operations;
pub mod packet;
pub mod rtp;
pub mod rtpcodec;
pub mod session;

// Begin RTP Specific Code //
// End RTP Specific Code //

// Begin PolyPaging Specific Code //

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

pub fn do_print_stream<R: BufRead>(
    file_handle: &mut R,
    callerid: String,
    codec: CodecFlag,
    channel: u8,
) {
    let alert_gap = time::Duration::from_millis(30);
    let tx_gap = time::Duration::from_millis(10);
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
    let mut buffer = [0u8; 80];
    let mut sample_count = 0u32;
    let mut last_chunk: Vec<u8> = vec![];
    loop {
        let buf_len = file_handle.read(&mut buffer).unwrap();
        if buf_len == 0 {
            break;
        }
        let payload_packet: PacketWithPayload;
        (last_chunk, payload_packet) = PacketWithPayload::from_buffer(
            session,
            codec,
            0u8,
            &mut sample_count,
            last_chunk,
            &buffer,
        );
        payload_packet.print().unwrap_or_else(|err| {
            println!("Problem printing payload packet: {err}");
            process::exit(1);
        });
        thread::sleep(tx_gap);
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
    sock.set_multicast_ttl_v4(64)
        .expect("set_multicast_ttl_v4 call failed");
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

pub async fn do_transmit_stream<R: BufRead>(
    file_handle: &mut R,
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

    let sock = UdpSocket::bind("0.0.0.0:5001").await?;
    let remote_addr = "224.0.1.116:5001";
    sock.set_multicast_ttl_v4(64)
        .expect("set_multicast_ttl_v4 call failed");
    let v4_mcast_addr = Ipv4Addr::new(224, 0, 1, 116);
    let v4_local_addr = Ipv4Addr::new(0, 0, 0, 0);
    sock.connect(remote_addr).await?;
    sock.join_multicast_v4(v4_mcast_addr, v4_local_addr)?;

    thread::sleep(join_gap);

    let alert_bytes: Vec<u8> = alert.to_bytes().unwrap_or_else(|err| {
        println!("Problem getting alert packet bytes: {err}");
        process::exit(1);
    });
    alert.debug();
    for _ in 0..31 {
        sock.send(&alert_bytes).await?;
        thread::sleep(alert_gap);
    }

    let mut buffer = [0u8; 80];
    let mut sample_count = 0u32;
    let mut last_chunk: Vec<u8> = Vec::new();
    loop {
        let buf_len = file_handle.read(&mut buffer).unwrap();
        if buf_len == 0 {
            break;
        }
        log::debug!("Buffer Length: {buf_len}");
        let payload_packet: PacketWithPayload;
        (last_chunk, payload_packet) = PacketWithPayload::from_buffer(
            session,
            codec,
            0u8,
            &mut sample_count,
            last_chunk,
            &buffer,
        );
        log::debug!("Sample Count: {sample_count}");
        let payload_bytes: Vec<u8> = payload_packet.to_bytes().unwrap();
        sock.send(&payload_bytes).await?;
        thread::sleep(tx_gap);
    }

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
        assert!(matches!(result.opcode, crate::operations::OpCode::Alert));
    }

    #[test]
    fn good_alert_packet() {
        let session = get_session(49u8, 0x00000000u32, "CallerID").unwrap();
        let result = crate::packet::get_alert_packets(&session).unwrap();
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
        assert!(matches!(result.opcode, crate::operations::OpCode::End));
    }

    #[test]
    fn good_end_packet() {
        let session = get_session(49u8, 0x00000000u32, "CallerID").unwrap();
        let result = crate::packet::get_end_packets(&session).unwrap();
        assert_eq!(
            result,
            [255, 49, 0, 0, 0, 0, 13, 67, 97, 108, 108, 101, 114, 73, 68, 0, 0, 0, 0, 0]
        )
    }

    #[test]
    fn good_payload() {
        let session = get_session(49u8, 0x00000000u32, "CallerID").unwrap();
        let payload: Vec<u8> = b"\xDE\x7A\xF2\x77\xDC\xF2\xF5\xDB\x71\xDE\xB2\xAF\xB9\xB4\x9F\x9D\xF6\xF3\xED\x72\xF2\xAE\xB6\xF6\xF9\xF7\xDC\xDE\xF8\x7E\xF4\xB1\xBA\xF7\xDC\xDE\x76\xF8\xB1\xF4\xFA\xF7\xBA\xDE\xFC\xFA\xDE\xF8\xBC\x7E\xB6\xDE\xF3\xF6\xF4\xFC\xF6\xB2\xF6\x74\xDB\xBE\x9B\xDE\x7A\xDE\xFA\xB7\xF7\x7A\xB7\xFC\xF7\xFE\xFA\x76\xB7\xF6\xF7\xF7\x00".to_vec();
        let result_packet = crate::packet::get_payload(session, CodecFlag::G722, 0u8, &payload);
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
        let result = crate::packet::get_payload_packet(
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
        let result_packet = crate::packet::get_payload(session, CodecFlag::G722, 0u8, &payload);
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
