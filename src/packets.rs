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
use pcap::{ Capture, Active, Packet};
use pcap::Error as pcap_error;
use super::error::Error;

extern crate pcap;

pub struct SimpleDumpCodec;

impl PacketCodec for SimpleDumpCodec{
    type Type = PacketInfo;

    fn decode<'p>(&mut self, packet: Packet<'p>) -> Result<Self::Type, pcap_error> {
        produce_packet(&packet)
    }
}

pub fn get_packet(cap: Capture<Active>) -> Result<(), Error> {
    let core = Core::new().unwrap();
    let handle = core.handle();
    let s = cap.stream(&handle, SimpleDumpCodec{})?;

    tokio::run(lazy(|| {
    let (tx, rx) = mpsc::channel::<PacketInfo>(1_024);
    tokio::spawn(bg_task(rx));
    tokio::spawn({
        s.fold(tx, |tx, pi| {
            tx.send(pi)
                .map_err(|_| pcap_error::PcapError(String::from("send tx error")))
        })
            .map(|_| ()).map_err(|_| ())

    })
    }));
    Ok(())
}

fn bg_task(rx: mpsc::Receiver<PacketInfo>)
           -> impl Future<Item = (), Error = ()>
{
    #[derive(Eq, PartialEq)]
    enum Item {
        Value(PacketInfo),
        Tick,
        Done,
    }

    let tick_dur = Duration::from_secs(3);

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
                st.show();

                future::ok(st)
            }
            _ => {
                println!("Get nothing");
                unreachable!()
            }
        }
    })
        .map(|_| ())
}