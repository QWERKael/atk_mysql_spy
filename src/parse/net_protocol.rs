use nom::*;

#[derive(Debug)]
pub struct Ethernet2 {
    dst_mac: Vec<u8>,
    src_mac: Vec<u8>,
    ethernet_type: EthernetType,
    payload: Vec<u8>,
}

#[derive(Debug)]
pub enum EthernetType {
    IP = 0x0800,
    ARP = 0x0806,
    RARP = 0x8035,
    Unknown,
}

impl From<u16> for EthernetType {
    fn from(type_code: u16) -> EthernetType {
        match type_code {
            0x0800 => EthernetType::IP,
            0x0806 => EthernetType::ARP,
            0x8035 => EthernetType::RARP,
            _ => EthernetType::Unknown,
        }
    }
}

named!(parse_ethernet2_protocol<&[u8], Ethernet2>, do_parse!(
    dst_mac: take!(6) >>
    src_mac: take!(6) >>
    ethernet_type: be_u16 >>
    payload: rest >>
    (Ethernet2{
        dst_mac: dst_mac.to_vec(),
        src_mac: src_mac.to_vec(),
        ethernet_type: EthernetType::from(ethernet_type),
        payload: payload.to_vec(),
    })
));

pub fn ethernet2_parser(data: &[u8]) -> Ethernet2 {
    parse_ethernet2_protocol(data).unwrap().1
}
