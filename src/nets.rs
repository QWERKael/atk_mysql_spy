use pcap::{Device, Capture};
//use super::parse::net_protocol;
use super::error::Error;
use super::statistics::connection_traffic::*;
use std::collections::HashMap;



pub fn capture_package(dev: Device, timeout: i32, bpf: &str) -> Result<(), Error> {
    let cap = Capture::from_device(dev)?.timeout(timeout);
    let mut cap = cap.open()?;
    let _ = cap.filter(bpf)?;
    let mut single_traffic: ConnectTraffic = HashMap::new();
    while let Ok(packet) = cap.next() {
        let pi = produce_packet(&packet)?;
        *single_traffic.entry(pi.conn_info).or_insert(0u64) += pi.pkt_len as u64;
        single_traffic.show();
//        println!("received packet! {:?}", packet);
//        let ethernet2 = net_protocol::ethernet2_parser(packet.data);
//        println!("{:?}", ethernet2);

//        println!("len of packet: {}", packet.header.len);
//        let a = packet.data.(Ipv4);

//        println!("IP {:?}", packet.data);
    }
    Ok(())
}

pub fn get_device(dev_name: Option<&str>) -> Result<Device, Error> {
    let dev = match dev_name {
        None => Device::lookup()?,
        Some(dev) => get_device_from_name(dev)?,
    };
    Ok(dev)
}

fn get_device_from_name(dev_name: &str) -> Result<Device, Error> {
    let dev_list = Device::list()?;
    for dev in dev_list {
        if dev.name == dev_name {
            return Ok(dev);
        }
    }
    Err(Error::from(String::from("Can not find the specified device")))
//    Err(std::error::Error
}




