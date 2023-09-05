use pcap::{Packet, PacketCodec, PacketHeader};

/// Represents a owned packet
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketOwned {
    pub header: PacketHeader,
    pub data: Box<[u8]>
}

#[cfg(all(target_env = "musl", target_arch = "mips", target_os = "linux", target_endian = "little"))]
pub fn fix_packet(packet: Packet) -> PacketOwned {
    struct ActualHeader {
        tv_sec: i64,
        tv_usec: i64,
        caplen: u32,
        len: u32
    }

    let actual_header: &ActualHeader;
    let data: &[u8];

    unsafe {
        actual_header = &*(packet.header as *const _ as *const ActualHeader);
        data = std::slice::from_raw_parts(packet.data as *const _ as *const u8, actual_header.caplen as usize);
    }

    let new_header = PacketHeader {
        ts: libc::timeval {
            tv_sec: actual_header.tv_sec as i32,
            tv_usec: actual_header.tv_usec as i32,
        },
        caplen: actual_header.caplen,
        len: actual_header.len,
    };

    PacketOwned {
        header: new_header,
        data: data.into()
    }
}


#[cfg(not(all(target_env = "musl", target_arch = "mips", target_os = "linux", target_endian = "little")))]
pub fn fix_packet(packet: Packet) -> PacketOwned {
    PacketOwned {
        header: *packet.header,
        data: packet.data.into(),
    }
}


pub struct FixHeaderCodec;

impl PacketCodec for FixHeaderCodec {
    type Item = PacketOwned;
    fn decode(&mut self, packet: Packet) -> Self::Item {
        fix_packet(packet)
    }
}
