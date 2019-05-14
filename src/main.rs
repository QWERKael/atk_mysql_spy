use error::Error;
use atk_mysql_spy::*;

fn run() -> Result<(), Error> {
    let opt = get_config();
    let dev = get_device(Some("lo"))?;
    println!("{:?}", dev);
    capture_package(dev, 0, &opt.bpf[..])
}

fn main() {
    match run() {
        Ok(_) => println!("Completion!"),
        Err(e) => println!("{:?}", e),
    };
}