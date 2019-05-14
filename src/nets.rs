use pcap::{Device, Capture};
use super::error::Error;
use super::packets::*;

pub fn capture_package(dev: Device, timeout: i32, bpf: &str) -> Result<(), Error> {
    let cap = Capture::from_device(dev)?.timeout(timeout);
    let mut cap = cap.open()?.setnonblock()?;
    let _ = cap.filter(bpf)?;

    get_packet(cap)
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
}




