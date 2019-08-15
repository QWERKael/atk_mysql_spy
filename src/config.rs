use structopt::StructOpt;
use lazy_static::*;

#[derive(StructOpt, Debug)]
#[structopt(name = "ATK MySQL SPY", author = "QWERKael <d9311@126.com>", version = "0.1 alpha")]
pub struct Opt {
    /// Berkeley Packet Filter
    #[structopt(long = "bpf", default_value = "tcp port 3306")]
    pub bpf: String,
    /// Specify a network device
    #[structopt(long = "dev", default_value = "eth0")]
    pub dev: String,
    /// Limit the number of output
    #[structopt(long = "limit", default_value = "10")]
    pub limit: u32,
    /// Show network devices
    #[structopt(long = "show-devs")]
    pub show_devs: bool,
    /// Specify the server ip
    #[structopt(long = "server-ip", default_value = "127.0.0.1")]
    pub server_ip: String,
    /// Specify the server port
    #[structopt(long = "server-port", default_value = "3306")]
    pub server_port: u16,
    /// Specify the staticstics type("sql" or "conn" or "raw-utf8")
    #[structopt(long = "stype", default_value = "raw-utf8")]
    pub stype: String,
    /// The interval between print
    #[structopt(long = "interval", default_value = "3")]
    pub interval: u64,
}

pub fn get_config() -> Opt {
    let opt = Opt::from_args();
    info!("{:?}\n-------------\n", opt);
    opt
}

pub fn string2ip(ip_str: &String) -> [u8; 4] {
    let i = ip_str.split(".").map(|x| x.parse().unwrap_or(0u8)).collect::<Vec<u8>>();
    [i[0], i[1], i[2], i[3]]
}

lazy_static! {
    pub static ref OPT: Opt = get_config();
}