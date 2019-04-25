use pcap::{Device, Capture, Error};
use super::parse::net_protocol;


pub fn capture_package(dev: Device, timeout: i32, bpf: &str) -> Result<(), Error> {
    let cap = Capture::from_device(dev)?.timeout(timeout);
    let mut cap = cap.open()?;
    let _ = cap.filter(bpf)?;
    while let Ok(packet) = cap.next() {
        println!("received packet! {:?}", packet);
        let ethernet2 = net_protocol::ethernet2_parser(packet.data);
        println!("{:?}", ethernet2);
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
    Err(Error::PcapError(String::from("Can not find the specified device")))
}



