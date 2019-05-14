use error::Error;
use atk_mysql_spy::*;

fn run() -> Result<(), Error> {
    let dev = get_device(Some("lo"))?;
    println!("{:?}", dev);
    capture_package(dev, 0, "tcp port 3306")
}

fn main() {
    match run() {
        Ok(_) => println!("Completion!"),
        Err(e) => println!("{:?}", e),
    };
}