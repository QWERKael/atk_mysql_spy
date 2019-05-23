use nom::*;
use std::collections::HashMap;
use super::connection_traffic::*;
use std::iter::FromIterator;

//fn main() {
//    let raw: [u8; 19] = [15, 0, 0, 0, 3, 115, 104, 111, 119, 32, 100, 97, 116, 97, 98, 97, 115, 101, 115];
////    let raw: [u8; 5] = [1, 0, 0, 0, 1];
////    let raw: [u8; 168] = [164, 0, 0, 1, 133, 166, 255, 1, 0, 0, 0, 1, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 114, 111, 111, 116, 0, 1, 0, 99, 97, 99, 104, 105, 110, 103, 95, 115, 104, 97, 50, 95, 112, 97, 115, 115, 119, 111, 114, 100, 0, 102, 4, 95, 112, 105, 100, 5, 51, 49, 57, 51, 56, 9, 95, 112, 108, 97, 116, 102, 111, 114, 109, 6, 120, 56, 54, 95, 54, 52, 3, 95, 111, 115, 5, 76, 105, 110, 117, 120, 12, 95, 99, 108, 105, 101, 110, 116, 95, 110, 97, 109, 101, 8, 108, 105, 98, 109, 121, 115, 113, 108, 15, 95, 99, 108, 105, 101, 110, 116, 95, 118, 101, 114, 115, 105, 111, 110, 6, 56, 46, 48, 46, 49, 53, 12, 112, 114, 111, 103, 114, 97, 109, 95, 110, 97, 109, 101, 5, 109, 121, 115, 113, 108];
//    let res = parse_client_packet(&raw).unwrap();
//    println!("{:?}", res.1);
//    println!("{:?}", res.0);
//}

pub type SQLTraffic = HashMap<ClientCommand, u64>;

impl ShowTraffic for SQLTraffic {
    fn show(&self, limit: u32) {
        let mut num = 0u32;
        let mut v = Vec::from_iter(self);
        v.sort_by(|&(_, a), &(_, b)| b.cmp(&a));
        for (cc, traffic) in v {
            if num >= limit && limit != 0 {
                break
            }
            num += 1;
            println!("{} : {}", cc, format_traffic(*traffic));
        }
    }
}

#[derive(Debug)]
pub struct MySQLPacket {
    pub mysql_packet_info: MySQLPacketInfo,
    pub mysql_packet_content: MySQLPacketContent,
}

#[derive(Debug)]
pub struct MySQLPacketInfo {
    pub packet_len: u64,
    pub sequence_id: u8,
}

#[derive(Debug)]
pub enum MySQLPacketContent {
    ServerAuth(ServerAuth),
    ClientAuth(ClientAuth),
    ClientCommand(ClientCommand),
}

#[derive(Debug)]
pub struct ServerAuth {
    pub raw: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum CommandType {
    ComSleep = 0x00,
    ComQuit = 0x01,
    ComInitDb = 0x02,
    ComQuery = 0x03,
    ComFieldList = 0x04,
    ComCreateDb = 0x05,
    ComDropDb = 0x06,
    ComRefresh = 0x07,
    ComShutdown = 0x08,
    ComStatistics = 0x09,
    ComProcessInfo = 0x0a,
    ComConnect = 0x0b,
    ComProcessKill = 0x0c,
    ComDebug = 0x0d,
    ComPing = 0x0e,
    ComTime = 0x0f,
    ComDelayedInsert = 0x10,
    ComChangeUser = 0x11,
    ComBinlogDump = 0x12,
    ComTableDump = 0x13,
    ComConnectOut = 0x14,
    ComRegisterSlave = 0x15,
    ComStmtPrepare = 0x16,
    ComStmtExecute = 0x17,
    ComStmtSendLongData = 0x18,
    ComStmtClose = 0x19,
    ComStmtReset = 0x1a,
    ComSetOption = 0x1b,
    ComStmtFetch = 0x1c,
    ComDaemon = 0x1d,
    ComBinlogDumpGtid = 0x1e,
    ComResetConnection = 0x1f,
    Unknown,
}

impl From<u8> for CommandType {
    fn from(type_code: u8) -> Self {
        match type_code {
            0x00 => CommandType::ComSleep,
            0x01 => CommandType::ComQuit,
            0x02 => CommandType::ComInitDb,
            0x03 => CommandType::ComQuery,
            0x04 => CommandType::ComFieldList,
            0x05 => CommandType::ComCreateDb,
            0x06 => CommandType::ComDropDb,
            0x07 => CommandType::ComRefresh,
            0x08 => CommandType::ComShutdown,
            0x09 => CommandType::ComStatistics,
            0x0a => CommandType::ComProcessInfo,
            0x0b => CommandType::ComConnect,
            0x0c => CommandType::ComProcessKill,
            0x0d => CommandType::ComDebug,
            0x0e => CommandType::ComPing,
            0x0f => CommandType::ComTime,
            0x10 => CommandType::ComDelayedInsert,
            0x11 => CommandType::ComChangeUser,
            0x12 => CommandType::ComBinlogDump,
            0x13 => CommandType::ComTableDump,
            0x14 => CommandType::ComConnectOut,
            0x15 => CommandType::ComRegisterSlave,
            0x16 => CommandType::ComStmtPrepare,
            0x17 => CommandType::ComStmtExecute,
            0x18 => CommandType::ComStmtSendLongData,
            0x19 => CommandType::ComStmtClose,
            0x1a => CommandType::ComStmtReset,
            0x1b => CommandType::ComSetOption,
            0x1c => CommandType::ComStmtFetch,
            0x1d => CommandType::ComDaemon,
            0x1e => CommandType::ComBinlogDumpGtid,
            0x1f => CommandType::ComResetConnection,
            _ => CommandType::Unknown,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct ClientCommand {
    pub command_type: CommandType,
    pub command_content: String,
}

impl std::fmt::Display for ClientCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}: {}",
               self.command_type,
               self.command_content)
    }
}

#[derive(Debug)]
pub struct ClientAuth {
    pub raw: Vec<u8>,
}



named!(pub parse_length_encoded_integer< &[u8], Option<u64>>, do_parse! (
first_byte: le_u8 >>
length_encoded_integer: switch! (value!(first_byte),
    251 => value!(None) |
    252 => map!(le_u16, |x| Some(u64::from(x))) |
    253 => map!(le_u32, |x| Some(u64::from(x))) |
    254 => map!(le_u64, |x| Some(u64::from(x))) |
    255 => value!(None) |
    _ => value!(Some(u64::from(first_byte)))
) >>
(length_encoded_integer)
));

named!(pub parse_mysql_packet_info< &[u8], MySQLPacketInfo>, do_parse! (
packet_len: map!(le_u24, u64::from) >>
sequence_id: le_u8 >>
(MySQLPacketInfo{packet_len: packet_len, sequence_id: sequence_id})
));

named!(pub parse_client_command< &[u8], MySQLPacketContent>, do_parse! (
command_type: le_u8 >>
command_content: rest >>
(MySQLPacketContent::ClientCommand(ClientCommand{command_type: CommandType::from(command_type), command_content: if command_type == 3 {String::from_utf8(command_content.to_vec()).unwrap()} else {String::from("")}}))
));

named!(pub parse_client_auth< &[u8], MySQLPacketContent>, do_parse! (
raw: rest >>
(MySQLPacketContent::ClientAuth(ClientAuth{raw: raw.to_vec()}))
));

named!(pub parse_server_auth< &[u8], MySQLPacketContent>, do_parse! (
raw: rest >>
(MySQLPacketContent::ServerAuth(ServerAuth{raw: raw.to_vec()}))
));

named!(pub parse_client_packet< &[u8], MySQLPacket>, do_parse! (
mysql_packet_info: parse_mysql_packet_info >>
mysql_packet_content: switch!(
value!(mysql_packet_info.sequence_id),
0 => call!(parse_client_command) |
_ => call!(parse_client_auth)
) >>
(MySQLPacket{mysql_packet_info: mysql_packet_info, mysql_packet_content: mysql_packet_content})
));