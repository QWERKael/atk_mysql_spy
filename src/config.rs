use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(name = "ATK MySQL SPY", author = "QWERKael <d9311@126.com>", version = "0.1 alpha")]
pub struct Opt {
    /// Berkeley Packet Filter
    #[structopt(long = "bpf", default_value = "tcp port 3306")]
    pub bpf: String,
}

pub fn get_config() -> Opt {
    let opt = Opt::from_args();
    println!("{:?}", opt);
    opt
}