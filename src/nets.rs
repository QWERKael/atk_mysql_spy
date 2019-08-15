use pcap::{Device, Capture};
use super::error::Error;
use super::packets::*;
use super::config::OPT;

/// 抓取指定设备的网络包
pub fn capture_package(dev: Device, timeout: i32, bpf: &str) -> Result<(), Error> {
    let cap = Capture::from_device(dev)?.timeout(timeout);
    let mut cap = cap.open()?.setnonblock()?;
    // 根据BPF过滤包
    let _ = cap.filter(bpf)?;
    let ps = get_packet_stream(cap,  SimpleDumpCodec{})?;
    if OPT.stype == String::from("conn") {
        process_packet_stream(ps, connections_traffic_statistics)?;
    } else if OPT.stype == String::from("sql") {
        process_packet_stream(ps, sql_traffic_statistics)?;
    } else if OPT.stype == String::from("raw-utf8") {
        process_packet_stream(ps, raw_utf8_print)?;
    }
    Ok(())
}

/// 列出所有的设备
pub fn show_devices() -> Result<(), Error> {
    let dev_list = Device::list()?;
    for dev in dev_list {
        info!("{}", dev.name)
    }
    Ok(())
}

/// 获取指定设备
pub fn get_device(dev_name: Option<&str>) -> Result<Device, Error> {
    let dev = match dev_name {
        None => Device::lookup()?,
        Some(dev) => get_device_from_name(dev)?,
    };
    Ok(dev)
}

/// 根据设备名称获取指定设备
fn get_device_from_name(dev_name: &str) -> Result<Device, Error> {
    let dev_list = Device::list()?;
    for dev in dev_list {
        if dev.name == dev_name {
            return Ok(dev);
        }
    }
    Err(Error::from(String::from("Can not find the specified device")))
}




