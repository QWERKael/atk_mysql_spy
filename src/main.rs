use error::Error;
use atk_mysql_spy::*;
use config::OPT;

fn run() -> Result<(), Error> {
    if OPT.show_devs {
        return show_devices()
    }
    let dev = get_device(Some(&OPT.dev[..]))?;
    println!("{:?}", dev);
    capture_package(dev, 0, &OPT.bpf[..])
}

fn main() {
    match run() {
        Ok(_) => println!("\n-------------\nCompletion!"),
        Err(e) => println!("{:?}", e),
    };
}