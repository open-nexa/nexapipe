use std::net::Ipv4Addr;

/// IP protocol numbers
pub const IPPROTO_TCP: u8 = 6;

/// IPv4 packet
#[derive(Debug, Clone)]
pub struct Ipv4Packet {
    pub src_addr: Ipv4Addr,
    pub dst_addr: Ipv4Addr,
    pub protocol: u8,
    pub payload: Vec<u8>,
}

impl Ipv4Packet {
    /// Parses an IPv4 packet from raw bytes
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 20 {
            return None;
        }

        let version_ihl = data[0];
        let version = version_ihl >> 4;
        let ihl = (version_ihl & 0x0F) as usize * 4;

        if version != 4 || ihl < 20 || data.len() < ihl {
            return None;
        }

        let total_len = u16::from_be_bytes([data[2], data[3]]);
        let protocol = data[9];
        let src_addr = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
        let dst_addr = Ipv4Addr::new(data[16], data[17], data[18], data[19]);

        let end = (total_len as usize).min(data.len());
        let payload = data[ihl..end].to_vec();

        Some(Self {
            src_addr,
            dst_addr,
            protocol,
            payload,
        })
    }
}

/// TCP flags
pub mod tcp_flags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
}

/// TCP packet
#[derive(Debug, Clone)]
pub struct TcpPacket {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    pub flags: u8,
    pub window: u16,
    pub payload: Vec<u8>,
}

impl TcpPacket {
    /// Parses a TCP packet from raw bytes
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 20 {
            return None;
        }

        let src_port = u16::from_be_bytes([data[0], data[1]]);
        let dst_port = u16::from_be_bytes([data[2], data[3]]);
        let seq_num = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let ack_num = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let data_offset = ((data[12] >> 4) as usize) * 4;
        let flags = data[13];
        let window = u16::from_be_bytes([data[14], data[15]]);

        if data_offset < 20 || data.len() < data_offset {
            return None;
        }

        let payload = if data_offset < data.len() {
            data[data_offset..].to_vec()
        } else {
            Vec::new()
        };

        Some(Self {
            src_port,
            dst_port,
            seq_num,
            ack_num,
            flags,
            window,
            payload,
        })
    }

    /// Builds a TCP packet (without the IP layer)
    pub fn build(&self) -> Vec<u8> {
        let data_offset = 20u8; // 5 * 4 = 20 bytes (no options)
        let total_len = data_offset as usize + self.payload.len();
        let mut packet = Vec::with_capacity(total_len);

        // Source Port
        packet.extend_from_slice(&self.src_port.to_be_bytes());
        // Destination Port
        packet.extend_from_slice(&self.dst_port.to_be_bytes());
        // Sequence Number
        packet.extend_from_slice(&self.seq_num.to_be_bytes());
        // Acknowledgment Number
        packet.extend_from_slice(&self.ack_num.to_be_bytes());
        // Data Offset (5 words) + Reserved + Flags
        packet.push((data_offset / 4) << 4);
        packet.push(self.flags);
        // Window Size
        packet.extend_from_slice(&self.window.to_be_bytes());
        // Checksum (placeholder)
        packet.extend_from_slice(&[0x00, 0x00]);
        // Urgent Pointer
        packet.extend_from_slice(&[0x00, 0x00]);
        // Payload
        packet.extend_from_slice(&self.payload);

        packet
    }

    /// Builds a complete IP+TCP packet (with correct checksums)
    pub fn build_with_ip(
        &self,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        identification: u16,
    ) -> Vec<u8> {
        let tcp_data = self.build();
        let tcp_len = tcp_data.len();

        // Build the IP packet (checksum filled in later)
        let ip_total_len = 20 + tcp_len;
        let mut ip_packet = Vec::with_capacity(ip_total_len);

        // IP header
        ip_packet.push(0x45); // Version=4, IHL=5
        ip_packet.push(0x00); // DSCP=0, ECN=0
        ip_packet.extend_from_slice(&(ip_total_len as u16).to_be_bytes());
        ip_packet.extend_from_slice(&identification.to_be_bytes());
        ip_packet.extend_from_slice(&[0x40, 0x00]); // Don't Fragment
        ip_packet.push(64); // TTL
        ip_packet.push(IPPROTO_TCP); // Protocol
        ip_packet.extend_from_slice(&[0x00, 0x00]); // Checksum placeholder
        ip_packet.extend_from_slice(&src_ip.octets());
        ip_packet.extend_from_slice(&dst_ip.octets());

        // TCP data
        ip_packet.extend_from_slice(&tcp_data);

        // Compute the TCP checksum (including the pseudo header)
        let tcp_checksum = tcp_checksum(&ip_packet[20..], src_ip, dst_ip);
        let tcp_checksum_pos = 20 + 16; // IP header(20) + TCP checksum offset(16)
        ip_packet[tcp_checksum_pos] = (tcp_checksum >> 8) as u8;
        ip_packet[tcp_checksum_pos + 1] = (tcp_checksum & 0xFF) as u8;

        // Compute the IP checksum
        let ip_chk = ip_checksum(&ip_packet[..20]);
        ip_packet[10] = (ip_chk >> 8) as u8;
        ip_packet[11] = (ip_chk & 0xFF) as u8;

        ip_packet
    }
}

/// Compute the IP header checksum
fn ip_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header.len() {
        sum += u16::from_be_bytes([header[i], header[i + 1]]) as u32;
        i += 2;
    }
    if i < header.len() {
        sum += (header[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Computes the TCP checksum (including the pseudo header)
fn tcp_checksum(tcp_data: &[u8], src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> u16 {
    let tcp_len = tcp_data.len() as u32;
    let mut sum: u32 = 0;

    // Pseudo header
    let src_octets = src_ip.octets();
    let dst_octets = dst_ip.octets();
    sum += u16::from_be_bytes([src_octets[0], src_octets[1]]) as u32;
    sum += u16::from_be_bytes([src_octets[2], src_octets[3]]) as u32;
    sum += u16::from_be_bytes([dst_octets[0], dst_octets[1]]) as u32;
    sum += u16::from_be_bytes([dst_octets[2], dst_octets[3]]) as u32;
    sum += IPPROTO_TCP as u32;
    sum += tcp_len;

    // TCP data
    let mut i = 0;
    while i + 1 < tcp_data.len() {
        sum += u16::from_be_bytes([tcp_data[i], tcp_data[i + 1]]) as u32;
        i += 2;
    }
    if i < tcp_data.len() {
        sum += (tcp_data[i] as u32) << 8;
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}
