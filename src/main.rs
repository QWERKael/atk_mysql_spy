#[macro_use]
extern crate log;
extern crate env_logger;

use env_logger::Builder;
use log::LevelFilter;
use std::io::Write;
use error::Error;
use atk_mysql_spy::*;
use config::OPT;

fn run() -> Result<(), Error> {
    if OPT.show_devs {
        return show_devices()
    }
    let dev = get_device(Some(&OPT.dev[..]))?;
    info!("{:?}", dev);
    capture_package(dev, 0, &OPT.bpf[..])
}

fn main() {
//    env_logger::init();
    Builder::new()
        .format(|buf, record| {
            writeln!(buf,
                     "{}",
                     record.args()
            )
        })
        .filter(None, LevelFilter::Info)
        .init();
    match run() {
//        Ok(_) => println!("\n-------------\nCompletion!"),
        Ok(_) => info!("\n-------------\nCompletion!"),
        Err(e) => info!("{:?}", e),
    };
}