use etherparse::PacketHeaders;
//use super::super::error::Error;
use pcap::{Packet};
use etherparse::IpHeader::Version4;
use etherparse::TransportHeader::Tcp;
use std::collections::HashMap;
use std::iter::FromIterator;

use pcap::Error as pcap_error;

#[derive(PartialEq, Eq, Hash, Debug)]
pub struct ConnectInfo {
    pub source_ip: [u8; 4],
    pub destination_ip: [u8; 4],
    pub source_port: u16,
    pub destination_port: u16,
}

impl std::fmt::Display for ConnectInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}:{} -> {}:{}",
               self.source_ip.iter().map(|x| x.to_string()).collect::<Vec<String>>().join("."),
               self.source_port,
               self.destination_ip.iter().map(|x| x.to_string()).collect::<Vec<String>>().join("."),
               self.destination_port)
    }
}


#[derive(Debug, Eq, PartialEq)]
pub struct PacketInfo {
    pub conn_info: ConnectInfo,
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub sequence_number: u32,
    pub acknowledgment_number: u32,
    pub pkt_len: usize,
    pub payload: Vec<u8>,
}

//#[derive(Debug)]
//struct CommonSingleTraffic {
//    conn_info: ConnectInfo,
//    total_flow: u64,
//}

pub fn produce_packet(pkt: &Packet) -> Result<PacketInfo, pcap_error> {
//    println!("Packet Len: {:?}", pkt.len());
//    let pi: PacketInfo;
    match PacketHeaders::from_ethernet_slice(pkt) {
        Err(value) => Err(pcap_error::PcapError(format!("The packet can not parse to TCP packet.\n{:?}", value))),
        Ok(value) => {
//            println!("link: {:?}", value.link);
//            println!("vlan: {:?}", value.vlan);
//            println!("ip: {:?}", value.ip);
//            println!("transport: {:?}", value.transport);
//            println!("payload: {:?}", value.payload);
            let payload = value.clone().payload;
            if let Version4(ipv4) = value.ip.unwrap() {
                if let Tcp(tcp) = value.transport.unwrap() {
//                    println!("{:?}", payload);
                    return Ok(PacketInfo {
                        conn_info: ConnectInfo {
                            source_ip: ipv4.source,
                            destination_ip: ipv4.destination,
                            source_port: tcp.source_port,
                            destination_port: tcp.destination_port,
                        },
                        syn: tcp.syn,
                        ack: tcp.ack,
                        fin: tcp.fin,
                        sequence_number: tcp.sequence_number,
                        acknowledgment_number: tcp.acknowledgment_number,
                        pkt_len: pkt.len(),
                        payload: payload.to_vec(),
                    });
                }
            }
            Err(pcap_error::PcapError(format!("The packet can not parse to IP packet.\n{:?}", pkt)))
        }
    }
}

pub type ConnectTraffic = HashMap<ConnectInfo, u64>;

pub trait ShowTraffic {
    fn show(&self, limit: u32);
}

impl ShowTraffic for ConnectTraffic {
    fn show(&self, limit: u32) {
        let mut num = 0u32;
        let mut v = Vec::from_iter(self);
        v.sort_by(|&(_, a), &(_, b)| b.cmp(&a));
        for (conn_info, traffic) in v {
            if num >= limit && limit != 0 {
                break
            }
            num += 1;
            println!("{} : {}", conn_info, format_traffic(*traffic));
        }
    }
}

pub fn format_traffic(traffic: u64) -> String {
    let units = ["Bytes", "KB", "MB", "GB", "TB", "PB", "EB", "ZB"];
    let mut num = traffic as f64;
    for unit in &units {
        if num < 1024.0 {
            return format!("{:.3} {}", num, unit);
        }
        num /= 1024.0
    }
    format!("{:.3} {}", num, units[units.len()-1])
}