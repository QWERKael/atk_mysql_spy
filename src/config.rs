use structopt::StructOpt;
use lazy_static::*;

#[derive(StructOpt, Debug)]
#[structopt(name = "ATK MySQL SPY", author = "QWERKael <d9311@126.com>", version = "0.1 alpha")]
pub struct Opt {
    /// Berkeley Packet Filter
    #[structopt(long = "bpf", default_value = "tcp port 3306")]
    pub bpf: String,
    /// Specify a network device
    #[structopt(long = "dev", default_value = "lo")]
    pub dev: String,
    /// Limit the number of output
    #[structopt(long = "limit", default_value = "10")]
    pub limit: u32,
    /// Show network devices
    #[structopt(long = "show-devs")]
    pub show_devs: bool,
}

pub fn get_config() -> Opt {
    let opt = Opt::from_args();
    println!("{:?}\n-------------\n", opt);
    opt
}

lazy_static! {
    pub static ref OPT: Opt = get_config();
}

//pub fn get_config2() {
//    let opt = Opt::from_args();
//    println!("{:?}\n-------------\n", opt);
//    opt
//}