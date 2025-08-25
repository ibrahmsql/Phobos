//! Packet crafting and manipulation module

use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::packet::udp::{MutableUdpPacket, UdpPacket};
use pnet::packet::Packet;
use rand::Rng;
use std::net::Ipv4Addr;

/// TCP packet builder for crafting custom TCP packets
pub struct TcpPacketBuilder {
    source_ip: Ipv4Addr,
    dest_ip: Ipv4Addr,
    source_port: u16,
    dest_port: u16,
    flags: u8,
    seq_num: u32,
    ack_num: u32,
    window_size: u16,
    ip_id: u16,
    padding: Option<usize>,
    mtu: Option<u16>,
    bad_checksum: bool,
}

impl TcpPacketBuilder {
    pub fn new(source_ip: Ipv4Addr, dest_ip: Ipv4Addr, source_port: u16, dest_port: u16) -> Self {
        let mut rng = rand::thread_rng();
        Self {
            source_ip,
            dest_ip,
            source_port,
            dest_port,
            flags: 0,
            seq_num: rng.gen(),
            ack_num: 0,
            window_size: 65535,
            ip_id: rng.gen(),
            padding: None,
            mtu: None,
            bad_checksum: false,
        }
    }
    
    pub fn flags(mut self, flags: u8) -> Self {
        self.flags = flags;
        self
    }
    
    pub fn syn(mut self) -> Self {
        self.flags |= TcpFlags::SYN as u8;
        self
    }
    
    pub fn ack(mut self) -> Self {
        self.flags |= TcpFlags::ACK as u8;
        self
    }
    
    pub fn fin(mut self) -> Self {
        self.flags |= TcpFlags::FIN as u8;
        self
    }
    
    pub fn rst(mut self) -> Self {
        self.flags |= TcpFlags::RST as u8;
        self
    }
    
    pub fn psh(mut self) -> Self {
        self.flags |= TcpFlags::PSH as u8;
        self
    }
    
    pub fn urg(mut self) -> Self {
        self.flags |= TcpFlags::URG as u8;
        self
    }
    
    pub fn seq_num(mut self, seq_num: u32) -> Self {
        self.seq_num = seq_num;
        self
    }
    
    pub fn ack_num(mut self, ack_num: u32) -> Self {
        self.ack_num = ack_num;
        self
    }
    
    pub fn window_size(mut self, window_size: u16) -> Self {
        self.window_size = window_size;
        self
    }
    
    /// Set source port (for stealth)
    pub fn source_port(&mut self, port: u16) {
        self.source_port = port;
    }
    
    /// Set sequence number (for stealth)
    pub fn sequence_number(&mut self, seq: u32) {
        self.seq_num = seq;
    }
    
    /// Set IP ID (for stealth)
    pub fn ip_id(&mut self, id: u16) {
        self.ip_id = id;
    }
    
    /// Add packet padding (for stealth)
    pub fn add_padding(&mut self, padding: usize) {
        self.padding = Some(padding);
    }
    
    /// Set custom MTU (for stealth)
    pub fn set_mtu(&mut self, mtu: u16) {
        self.mtu = Some(mtu);
    }
    
    /// Use bad checksum for evasion
    pub fn use_bad_checksum(&mut self, bad: bool) {
        self.bad_checksum = bad;
    }
    
    /// Build the complete IP + TCP packet
    pub fn build(self) -> Vec<u8> {
        const IP_HEADER_LEN: usize = 20;
        let tcp_header_len = 20 + self.padding.unwrap_or(0);
        let total_len = IP_HEADER_LEN + tcp_header_len;
        
        // Apply MTU limit if specified
        let final_len = if let Some(mtu) = self.mtu {
            std::cmp::min(total_len, mtu as usize)
        } else {
            total_len
        };
        
        let mut packet_buf = vec![0u8; final_len];
        
        // Build IP header
        {
            let mut ip_packet = MutableIpv4Packet::new(&mut packet_buf[..IP_HEADER_LEN]).unwrap();
            ip_packet.set_version(4);
            ip_packet.set_header_length(5); // 5 * 4 = 20 bytes
            ip_packet.set_dscp(0);
            ip_packet.set_ecn(0);
            ip_packet.set_total_length(final_len as u16);
            ip_packet.set_identification(self.ip_id); // Use custom IP ID
            ip_packet.set_flags(2); // Don't fragment
            ip_packet.set_fragment_offset(0);
            ip_packet.set_ttl(64);
            ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
            ip_packet.set_source(self.source_ip);
            ip_packet.set_destination(self.dest_ip);
            
            // Calculate and set IP checksum
            let checksum = pnet::packet::ipv4::checksum(&ip_packet.to_immutable());
            ip_packet.set_checksum(checksum);
        }
        
        // Build TCP header
        {
            let tcp_len = final_len - IP_HEADER_LEN;
            if tcp_len >= 20 {
                let mut tcp_packet = MutableTcpPacket::new(&mut packet_buf[IP_HEADER_LEN..IP_HEADER_LEN + std::cmp::min(tcp_len, 20)]).unwrap();
                tcp_packet.set_source(self.source_port);
                tcp_packet.set_destination(self.dest_port);
                tcp_packet.set_sequence(self.seq_num);
                tcp_packet.set_acknowledgement(self.ack_num);
                tcp_packet.set_data_offset(5); // 5 * 4 = 20 bytes
                tcp_packet.set_flags(self.flags as u16);
                tcp_packet.set_window(self.window_size);
                tcp_packet.set_urgent_ptr(0);
                
                // Calculate and set TCP checksum
                let checksum = if self.bad_checksum {
                    0xFFFF // Intentionally bad checksum for evasion
                } else {
                    pnet::packet::tcp::ipv4_checksum(
                        &tcp_packet.to_immutable(),
                        &self.source_ip,
                        &self.dest_ip,
                    )
                };
                tcp_packet.set_checksum(checksum);
                
                // Add padding if specified
                if let Some(padding) = self.padding {
                    let padding_start = IP_HEADER_LEN + 20;
                    let padding_end = std::cmp::min(padding_start + padding, final_len);
                    for i in padding_start..padding_end {
                        packet_buf[i] = 0x00; // NOP padding
                    }
                }
            }
        }
        
        packet_buf
    }
}

/// UDP packet builder for crafting custom UDP packets
pub struct UdpPacketBuilder {
    source_ip: Ipv4Addr,
    dest_ip: Ipv4Addr,
    source_port: u16,
    dest_port: u16,
    payload: Vec<u8>,
}

impl UdpPacketBuilder {
    pub fn new(source_ip: Ipv4Addr, dest_ip: Ipv4Addr, source_port: u16, dest_port: u16) -> Self {
        Self {
            source_ip,
            dest_ip,
            source_port,
            dest_port,
            payload: Vec::new(),
        }
    }
    
    pub fn payload(mut self, payload: Vec<u8>) -> Self {
        self.payload = payload;
        self
    }
    
    /// Build the complete IP + UDP packet
    pub fn build(self) -> Vec<u8> {
        const IP_HEADER_LEN: usize = 20;
        const UDP_HEADER_LEN: usize = 8;
        let total_len = IP_HEADER_LEN + UDP_HEADER_LEN + self.payload.len();
        
        let mut packet_buf = vec![0u8; total_len];
        
        // Build IP header
        {
            let mut ip_packet = MutableIpv4Packet::new(&mut packet_buf[..IP_HEADER_LEN]).unwrap();
            ip_packet.set_version(4);
            ip_packet.set_header_length(5);
            ip_packet.set_dscp(0);
            ip_packet.set_ecn(0);
            ip_packet.set_total_length(total_len as u16);
            ip_packet.set_identification(rand::thread_rng().gen());
            ip_packet.set_flags(2);
            ip_packet.set_fragment_offset(0);
            ip_packet.set_ttl(64);
            ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
            ip_packet.set_source(self.source_ip);
            ip_packet.set_destination(self.dest_ip);
            
            let checksum = pnet::packet::ipv4::checksum(&ip_packet.to_immutable());
            ip_packet.set_checksum(checksum);
        }
        
        // Build UDP header and payload
        {
            let udp_len = UDP_HEADER_LEN + self.payload.len();
            let mut udp_packet = MutableUdpPacket::new(&mut packet_buf[IP_HEADER_LEN..IP_HEADER_LEN + udp_len]).unwrap();
            udp_packet.set_source(self.source_port);
            udp_packet.set_destination(self.dest_port);
            udp_packet.set_length(udp_len as u16);
            udp_packet.set_payload(&self.payload);
            
            let checksum = pnet::packet::udp::ipv4_checksum(
                &udp_packet.to_immutable(),
                &self.source_ip,
                &self.dest_ip,
            );
            udp_packet.set_checksum(checksum);
        }
        
        packet_buf
    }
}

/// Packet parser for analyzing received packets
pub struct PacketParser;

impl PacketParser {
    /// Parse a TCP packet and extract relevant information
    pub fn parse_tcp_response(packet: &[u8]) -> Option<TcpResponse> {
        if packet.len() < 20 {
            return None;
        }
        
        let ip_packet = Ipv4Packet::new(packet)?;
        if ip_packet.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
            return None;
        }
        
        let ip_header_len = (ip_packet.get_header_length() as usize) * 4;
        let tcp_packet = TcpPacket::new(&packet[ip_header_len..])?;
        
        Some(TcpResponse {
            source_ip: ip_packet.get_source(),
            dest_ip: ip_packet.get_destination(),
            source_port: tcp_packet.get_source(),
            dest_port: tcp_packet.get_destination(),
            flags: tcp_packet.get_flags() as u8,
            seq_num: tcp_packet.get_sequence(),
            ack_num: tcp_packet.get_acknowledgement(),
            window_size: tcp_packet.get_window(),
        })
    }
    
    /// Parse a UDP packet and extract relevant information
    pub fn parse_udp_response(packet: &[u8]) -> Option<UdpResponse> {
        if packet.len() < 20 {
            return None;
        }
        
        let ip_packet = Ipv4Packet::new(packet)?;
        if ip_packet.get_next_level_protocol() != IpNextHeaderProtocols::Udp {
            return None;
        }
        
        let ip_header_len = (ip_packet.get_header_length() as usize) * 4;
        let udp_packet = UdpPacket::new(&packet[ip_header_len..])?;
        
        Some(UdpResponse {
            source_ip: ip_packet.get_source(),
            dest_ip: ip_packet.get_destination(),
            source_port: udp_packet.get_source(),
            dest_port: udp_packet.get_destination(),
            length: udp_packet.get_length(),
            payload: udp_packet.payload().to_vec(),
        })
    }
    
    /// Parse an ICMP packet and extract relevant information
    pub fn parse_icmp_response(packet: &[u8]) -> Option<IcmpResponse> {
        if packet.len() < 20 {
            return None;
        }
        
        let ip_packet = Ipv4Packet::new(packet)?;
        
        // Check if it's an ICMP packet
        if ip_packet.get_next_level_protocol() != IpNextHeaderProtocols::Icmp {
            return None;
        }
        
        let icmp_payload = ip_packet.payload();
        if icmp_payload.len() < 8 {
            return None;
        }
        
        let icmp_type = icmp_payload[0];
        let icmp_code = icmp_payload[1];
        
        Some(IcmpResponse {
            source_ip: ip_packet.get_source(),
            dest_ip: ip_packet.get_destination(),
            icmp_type,
            icmp_code,
            payload: icmp_payload[8..].to_vec(),
        })
    }
}

/// TCP response structure
#[derive(Debug, Clone)]
pub struct TcpResponse {
    pub source_ip: Ipv4Addr,
    pub dest_ip: Ipv4Addr,
    pub source_port: u16,
    pub dest_port: u16,
    pub flags: u8,
    pub seq_num: u32,
    pub ack_num: u32,
    pub window_size: u16,
}

impl TcpResponse {
    pub fn is_syn_ack(&self) -> bool {
        (self.flags & (TcpFlags::SYN as u8 | TcpFlags::ACK as u8)) == (TcpFlags::SYN as u8 | TcpFlags::ACK as u8)
    }
    
    pub fn is_rst(&self) -> bool {
        (self.flags & TcpFlags::RST as u8) != 0
    }
    
    pub fn is_ack(&self) -> bool {
        (self.flags & TcpFlags::ACK as u8) != 0
    }
}

/// UDP response structure
#[derive(Debug, Clone)]
pub struct UdpResponse {
    pub source_ip: Ipv4Addr,
    pub dest_ip: Ipv4Addr,
    pub source_port: u16,
    pub dest_port: u16,
    pub length: u16,
    pub payload: Vec<u8>,
}

/// ICMP response structure
#[derive(Debug, Clone)]
pub struct IcmpResponse {
    pub source_ip: Ipv4Addr,
    pub dest_ip: Ipv4Addr,
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub payload: Vec<u8>,
}

impl IcmpResponse {
    /// Check if this is a port unreachable message
    pub fn is_port_unreachable(&self, target_ip: std::net::Ipv4Addr, _target_port: u16) -> bool {
        // ICMP Type 3 (Destination Unreachable), Code 3 (Port Unreachable)
        self.icmp_type == 3 && self.icmp_code == 3 && self.dest_ip == target_ip
    }
}