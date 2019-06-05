use tokio::timer::Interval;
use futures::{future, stream, Future, Stream, Sink};
use futures::future::lazy;
use futures::sync::mpsc;
use std::time::Duration;

extern crate futures;
extern crate tokio_core;
use pcap::tokio::PacketCodec;
use tokio_core::reactor::Core;
use std::collections::HashMap;
use super::statistics::connection_traffic::*;
use super::statistics::sql_traffic::*;
use pcap::{ Capture, Active, Packet};
use pcap::Error as pcap_error;
use super::error::Error;
use super::config::*;
use self::pcap::tokio::PacketStream;
use super::config::OPT;

extern crate pcap;

pub enum DumpCodecs {
    SimpleDumpCodec,
}

pub struct SimpleDumpCodec;

impl PacketCodec for SimpleDumpCodec{
    type Type = PacketInfo;

    fn decode<'p>(&mut self, packet: Packet<'p>) -> Result<Self::Type, pcap_error> {
        produce_packet(&packet)
    }
}

pub fn get_packet_stream(cap: Capture<Active>, c: SimpleDumpCodec) -> Result<PacketStream<Active, SimpleDumpCodec>, Error> {
    let core = Core::new().unwrap();
    let handle = core.handle();
    cap.stream(&handle, c).map_err(|_| Error::from(String::from("Can not find get packet stream")))
}

pub fn process_packet_stream(ps: PacketStream<Active, SimpleDumpCodec>, receiver_task: fn(mpsc::Receiver<PacketInfo>)) -> Result<(), Error>
{
    tokio::run(lazy(move || {
        let (tx, rx) = mpsc::channel::<PacketInfo>(1_024);
        receiver_task(rx);
        tokio::spawn({
            ps.fold(tx, |tx, pi| {
                tx.send(pi)
                    .map_err(|_| pcap_error::PcapError(String::from("send tx error")))
            })
                .map(|_| ()).map_err(|_| ())
        })
    }));
    Ok(())
}

pub fn connections_traffic_statistics(rx: mpsc::Receiver<PacketInfo>)
{
    #[derive(Eq, PartialEq)]
    enum Item {
        Value(PacketInfo),
        Tick,
        Done,
    }

    tokio::spawn({
        let tick_dur = Duration::from_secs(OPT.interval);

        let interval = Interval::new_interval(tick_dur)
            .map(|_| Item::Tick)
            .map_err(|_| ());

        let items = rx.map(Item::Value)
            .chain(stream::once(Ok(Item::Done)))
            .select(interval)
            .take_while(|item| future::ok(*item != Item::Done));

        let single_traffic: ConnectTraffic = HashMap::new();
        items.fold(single_traffic, |mut st, item| {
            match item {
                Item::Value(pi) => {
                    *st.entry(pi.conn_info).or_insert(0u64) += pi.pkt_len as u64;
                    future::ok(st)
                }
                Item::Tick => {
                    println!("------------------");
                    st.show(OPT.limit);

                    future::ok(st)
                }
                _ => {
                    println!("Get nothing");
                    unreachable!()
                }
            }
        })
            .map(|_| ())
    });
}

pub fn sql_traffic_statistics(rx: mpsc::Receiver<PacketInfo>)
{
    #[derive(Eq, PartialEq)]
    enum Item {
        Value(PacketInfo),
        Tick,
        Done,
    }

    tokio::spawn({
        let mut last_cc = ClientCommand{
            command_type: CommandType::Unknown,
            command_content: String::from(""),
        };

        let tick_dur = Duration::from_secs(OPT.interval);

        let interval = Interval::new_interval(tick_dur)
            .map(|_| Item::Tick)
            .map_err(|_| ());

        let items = rx.map(Item::Value)
            .chain(stream::once(Ok(Item::Done)))
            .select(interval)
            .take_while(|item| future::ok(*item != Item::Done));

        let single_traffic: SQLTraffic = HashMap::new();
        items.fold(single_traffic, move |mut st, item| {
            match item {
                Item::Value(pi) => {
                    // 当捕获的包的payload不为空时进行解析
                    if pi.payload.len() > 0 {
                        // 当流量方向为 client --> server 时进行解析
                        if pi.conn_info.destination_ip == string2ip(&OPT.server_ip) && pi.conn_info.destination_port == OPT.server_port {
                            let mp = parse_client_packet(&pi.payload).unwrap().1;
                            if let MySQLPacketContent::ClientCommand(cc) = mp.mysql_packet_content {
                                last_cc = cc.fingerprint();
                            } else if let MySQLPacketContent::ClientAuth(_) = mp.mysql_packet_content {
                                last_cc = ClientCommand{
                                    command_type: CommandType::Unknown,
                                    command_content: String::from(""),
                                };
                            }
                        }
                        *st.entry(last_cc.clone()).or_insert(0u64) += pi.pkt_len as u64;
                    }
                    future::ok(st)
                }
                Item::Tick => {
                    println!("------------------");
                    st.show(OPT.limit);

                    future::ok(st)
                }
                _ => {
                    println!("Get nothing");
                    unreachable!()
                }
            }
        })
            .map(|_| ())
    });
}

pub fn raw_utf8_print(rx: mpsc::Receiver<PacketInfo>)
{
    tokio::spawn({
        rx.for_each(
            |pi| {
                if pi.payload.len() > 0 {
                    println!("{}", String::from_utf8_lossy(&pi.payload[..]))
                }
                Ok(())
            }
        )
    });
}