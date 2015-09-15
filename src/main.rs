#![allow(dead_code)]
#[macro_use] extern crate enum_primitive;
#[macro_use] extern crate bitflags;
extern crate byteorder;
extern crate clap;
extern crate num;
extern crate pcap;
extern crate users;

mod serial;
use serial::{CephMsg, CephPrimitive};
mod crypto;

use byteorder::{BigEndian, ReadBytesExt};
use clap::{App, Arg};
use num::FromPrimitive;
use pcap::{Capture, Device};

use std::io::Cursor;
use std::net::{Ipv4Addr, Ipv6Addr};

#[cfg(test)]
mod tests{
    use std::io::Cursor;
    use std::net::{Ipv4Addr};

    #[test]
    fn test_packet_parsing(){
        let mut v4_packet2: Vec<u8> = vec![
            0x00 ,0x16 ,0x3e ,0x4c ,0x7b ,0xa0 , //Dst MAC
            0x00 ,0x16 ,0x3e ,0x53 ,0x4e ,0xf2 , //Src MAC
            0x08 ,0x00, //IP TYPE 14
            0x45 ,0x00 ,0x01 ,0x24 ,0x52 ,0xf6 ,0x40 ,0x00 ,0x40 ,0x06 ,0xcb ,0xeb , //26
            0x0a ,0x00, 0x03, 0x63 , //SRC IP //30
            0x0a ,0x00 ,0x03 ,0x90 , //DST IP //34
            0xea ,0x6d , //SRC port //36
            0x1a ,0x90 , //DST port //38
            0x38 ,0xdc ,0xc2 ,0x31 , //42
            0x66 ,0xd4 ,0x41 ,0xae , //46
            0x80 ,0x18 ,0x00 ,0xf5 , //50
            0x1c ,0x09 ,0x00 ,0x00 , //54
            0x01 ,0x01 ,0x08 ,0x0a,  //58
            0x00 ,0x05 ,0x24 ,0x07 , //62
            0x00 ,0x05 ,0x14 ,0x27 , //66
            0x07 ,0x02 ,0x00 ,0x00 , //70
            0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x03 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x2a , //84
            0x00 ,0x3f ,0x00, 0x04 ,0x00 ,0x99 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x0c , //98
            0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x08 ,0x9a ,0x11 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 , //112
            0x03 ,0x00 ,0x00 ,0x00, 0x54 ,0x3b ,0x7e ,0x6a ,

            0x00 ,0x00 ,0x00 ,0x00 ,0x5a ,0x00 , //CephOsdOperation 126
            0x00 ,0x00 ,0x24 ,0x00 ,0x00 ,0x00 ,0x14 ,0x7e ,0xf3 ,0x55 ,0xf0 ,0x88 ,0x81 ,0x32 , //140
            0x00 ,

            0x00 ,0x00 ,0x00 ,0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x03, 0x1c, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8f, 0x8d, 0x49, 0x97, 0xff, 0xff,
            0xff, 0xff, 0x02, 0x00, 0x00, 0x00, 0x68, 0x77, 0x01, 0x00, 0x02, 0x22, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21,
            0xed, 0x70, 0x12, 0xf6, 0x00, 0x00, 0x00, 0x00, 0x81, 0x44, 0x0c, 0xd5, 0x01, 0xe1,
            0xac, 0x17, 0x8e, 0x5a, 0xd0, 0x6c, 0x05];

        let mut v4_packet: Vec<u8> = vec![
            0, 22, 62, 76, 123, 160, //Dst Mac
            0, 22, 62, 83, 78, 242, //Src mac
            8, 0, //Ethertype
            69, 0, //IP header Packet
            0, 235, 160, 122, 64, 0, 64, 6,
            251, 204,//New position
            10, 0, 3, 99, //src ip
            10, 0, 3, 144, //dst ip
            173, 186, 26, 133, 86, 2, 236, 160, 131, 235, 201, 242, 128, 24, 11, 227, 27,
            208, 0, 0, 1, 1, 8, 10, 4, 202, 237, 131, 4, 202, 237, 87, 7, 67, 255, 1, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 6, 196, 0, 1, 0, 108, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 232, 89, 107, 135, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 3, 1, 82, 0, 0, 0, 0, 176, 158, 40
        ];
        let mut cursor = Cursor::new(&v4_packet2[..]);
        let packer_header = super::parse_etherframe(&mut cursor).unwrap();
        //assert_eq!(packer_header.src_port, 44474);
        //assert_eq!(packer_header.dst_port, 6789);
        //assert_eq!(packer_header.src_v4addr, Ipv4Addr(10,0,3,99));
        //assert_eq!(packer_header.dst_v4addr, Ipv4Addr(10,0,3,144));
        let result = super::dissect_msgr(&mut cursor);
        println!("Result: {:?}", result);
    }
}

fn get_device()->String{
    let matches = App::new("decode_ceph")
                      .author("Chris Holcombe, chris.holcombe@canonical.com")
                      .about("Analyzes Ceph in real time")
                      .arg(Arg::with_name("NET")
                           .short("i")
                           .long("interface")
                           .help("The network device to monitor Ceph traffic on")
                           .takes_value(true)
                       )
                      .get_matches();
    let device = matches.value_of("NET").unwrap_or("");
    return device.to_string();
}

fn check_user()->Result<(), ()>{
    let current_user = users::get_current_uid();
    if current_user != 0 {
        println!("This program must be run by root to access the network devices");
        return Err(());
    }
    return Ok(());
}

#[derive(Debug)]
pub struct PacketHeader{
    pub src_port: u16,
    pub dst_port: u16,

    pub src_v4addr: Option<Ipv4Addr>,
    pub dst_v4addr: Option<Ipv4Addr>,

    pub src_v6addr: Option<Ipv6Addr>,
    pub dst_v6addr: Option<Ipv6Addr>,
}

fn read_v4ip<'a>(cursor: &mut Cursor<&'a [u8]>)->Result<Ipv4Addr, serial::SerialError>{
        let a = try!(cursor.read_u8());
        let b = try!(cursor.read_u8());
        let c = try!(cursor.read_u8());
        let d = try!(cursor.read_u8());

        let ip = Ipv4Addr::new(a,b,c,d);
        return Ok(ip);
}

fn read_v6ip<'a>(cursor: &mut Cursor<&'a [u8]>)->Result<Ipv6Addr, serial::SerialError>{
        let a = try!(cursor.read_u16::<BigEndian>());
        let b = try!(cursor.read_u16::<BigEndian>());
        let c = try!(cursor.read_u16::<BigEndian>());
        let d = try!(cursor.read_u16::<BigEndian>());
        let e = try!(cursor.read_u16::<BigEndian>());
        let f = try!(cursor.read_u16::<BigEndian>());
        let g = try!(cursor.read_u16::<BigEndian>());
        let h = try!(cursor.read_u16::<BigEndian>());

        let ip = Ipv6Addr::new(a,b,c,d,e,f,g,h);
        return Ok(ip);
}

//Takes a cursor to a byte array and parses ip info from it
fn parse_etherframe<'a>(cursor: &mut Cursor<&'a [u8]>)->Result<PacketHeader, serial::SerialError>{
    cursor.set_position(12);
    let ethertype = try!(cursor.read_u16::<BigEndian>());

    if ethertype == 0x0800{
        let mut current_pos = cursor.position();
        cursor.set_position(current_pos + 12);

        let src_ip = try!(read_v4ip(cursor));
        let dst_ip = try!(read_v4ip(cursor));

        let src_port = try!(cursor.read_u16::<BigEndian>());
        let dst_port = try!(cursor.read_u16::<BigEndian>());

        //Skip the TCP header bullshit
        current_pos = cursor.position();
        println!("Current position {}", current_pos);
        cursor.set_position(current_pos + 28);
        println!("Skipping to {}", cursor.position());

        return Ok(
            PacketHeader{
                src_port: src_port,
                dst_port: dst_port,
                src_v4addr: Some(src_ip),
                dst_v4addr: Some(dst_ip),
                src_v6addr: None,
                dst_v6addr: None,
            }
        );
    }else if  ethertype == 0x86DD{
        //let mut current_pos = cursor.position();
        //cursor.set_position(current_pos + 12);

        let src_ip = try!(read_v6ip(cursor));
        let dst_ip = try!(read_v6ip(cursor));

        let src_port = try!(cursor.read_u16::<BigEndian>());
        let dst_port = try!(cursor.read_u16::<BigEndian>());

        //Skip the TCP header bullshit
        let current_pos = cursor.position();
        cursor.set_position(current_pos + 160);

        return Ok(
            PacketHeader{
                src_port: src_port,
                dst_port: dst_port,
                src_v4addr: None,
                dst_v4addr: None,
                src_v6addr: Some(src_ip),
                dst_v6addr: Some(dst_ip),
            }
        );
    }else{
        return Err(serial::SerialError::new(format!("Unknown Packet type: {}", ethertype)));
    }
}

fn dissect_new<'a>(cursor: &mut Cursor<&'a [u8]>){
    let result = serial::EntityAddr::read_from_wire(cursor);
    if result.is_ok(){
        println!("New? {:?}", result);
    }
}

fn check_for_connect<'a>(cursor: &mut Cursor<&'a [u8]>){
    let mut banner_vec:Vec<u8> = Vec::new();
    for _ in 0..8{
        let b = cursor.read_u8().unwrap();
        banner_vec.push(b);
    }
    let s = String::from_utf8(banner_vec).unwrap();
    println!("Ceph connect: {}", s);
}

fn dissect_msg_op<'a>(msg_type: serial::CephMsgType, cursor: &mut Cursor<&'a [u8]>){
    match msg_type{
        serial::CephMsgType::MsgPaxos => {

        },
        serial::CephMsgType::MsgOsdMap => {

        },
        serial::CephMsgType::MsgOsdOp => {
            println!("dissecting cephosdoperation at pos: {}", cursor.position());
            let result = serial::CephOsdOperation::read_from_wire(cursor);
            println!("Result: {:?}", result);
        },
        serial::CephMsgType::MsgOsdOpreply => {

        },
        serial::CephMsgType::MsgWatchNotify => {

        },
        serial::CephMsgType::MsgForward => {

        },
        serial::CephMsgType::MsgRoute => {

        },
        serial::CephMsgType::MsgMonCommand => {

        },
        serial::CephMsgType::MsgMonCommandAck => {

        },
        serial::CephMsgType::MsgLog => {

        },
        serial::CephMsgType::MsgLogAck => {

        },
        serial::CephMsgType::MsgClass => {

        },
        serial::CephMsgType::MsgClassAck => {

        },
        serial::CephMsgType::MsgGetpoolstats  => {

        },
        serial::CephMsgType::MsgGetpoolstatsreply => {

        },
        serial::CephMsgType::MsgMonGlobalId => {

        },
        serial::CephMsgType::MsgMonScrub => {

        },
        serial::CephMsgType::MsgMonElection => {

        },
        serial::CephMsgType::MsgMonPaxos => {

        },
        serial::CephMsgType::MsgMonProbe=> {

        },
        serial::CephMsgType::MsgMonJoin => {

        },
        serial::CephMsgType::MsgMonSync => {

        },
        serial::CephMsgType::MsgOsdPing => {

        },
        serial::CephMsgType::MsgOsdBoot => {

        },
        serial::CephMsgType::MsgOsdFailure => {

        },
        serial::CephMsgType::MsgOsdAlive => {

        },
        serial::CephMsgType::MsgOsdMarkMeDown => {

        },
        serial::CephMsgType::MsgOsdSubop => {

        },
        serial::CephMsgType::MsgOsdSubopreply => {

        },
        serial::CephMsgType::MsgOsdPgtemp => {

        },
        serial::CephMsgType::MsgOsdPgNotify => {

        },
        serial::CephMsgType::MsgOsdPgQuery => {

        },
        serial::CephMsgType::MsgOsdPgSummary => {

        },
        serial::CephMsgType::MsgOsdPgLog => {

        },
        serial::CephMsgType::MsgOsdPgRemove => {

        },
        serial::CephMsgType::MsgOsdPgInfo => {

        },
        serial::CephMsgType::MsgOsdPgTrim => {

        },
        serial::CephMsgType::MsgPgstats => {

        },
        serial::CephMsgType::MsgPgstatsack => {

        },
        serial::CephMsgType::MsgOsdPgCreate => {

        },
        serial::CephMsgType::MsgRemoveSnaps => {

        },
        serial::CephMsgType::MsgOsdScrub => {

        },
        serial::CephMsgType::MsgOsdPgMissing => {

        },
        serial::CephMsgType::MsgOsdRepScrub => {

        },
        serial::CephMsgType::MsgOsdPgScan => {

        },
        serial::CephMsgType::MsgOsdPgBackfill => {

        },
        serial::CephMsgType::MsgCommand => {

        },
        serial::CephMsgType::MsgCommandReply => {

        },
        serial::CephMsgType::MsgOsdBackfillReserve=> {

        },
        serial::CephMsgType::MsgOsdRecoveryReserve=> {

        },
        serial::CephMsgType::MsgOsdPgPush => {

        },
        serial::CephMsgType::MsgOsdPgPull => {

        },
        serial::CephMsgType::MsgOsdPgPushReply=> {

        },
        serial::CephMsgType::MsgOsdEcWrite => {

        },
        serial::CephMsgType::MsgOsdEcWriteReply=> {

        },
        serial::CephMsgType::MsgOsdEcRead => {

        },
        serial::CephMsgType::MsgOsdEcReadReply => {

        },
        serial::CephMsgType::MsgOsdRepop => {

        },
        serial::CephMsgType::MsgOsdRepopreply => {

        },
        serial::CephMsgType::MsgTimecheck => {

        },
        serial::CephMsgType::MsgMonHealth => {

        },
        serial::CephMsgType::MsgCrcData => {

        },
        serial::CephMsgType::MsgCrcHeader => {

        },
        serial::CephMsgType::MsgDataPing => {

        },
        serial::CephMsgType::MsgNop =>  {

        },
    }
}
//MSGR is Ceph's outer message protocol
fn dissect_msgr<'a>(cursor: &mut Cursor<&'a [u8]>)->Result<(), serial::SerialError>{
    let tag_bytes = try!(cursor.read_u8());
    println!("TAG Bytes: {}", &tag_bytes);
    if tag_bytes == 63 {
        //This might be a Ceph banner message
        check_for_connect(cursor);
        return Ok(());
    }
    if tag_bytes == 0{
        dissect_new(cursor);
    }
    let tag = serial::CephMsg::from_u8(tag_bytes);
    if tag.is_some(){
        println!("Found a frontend ceph msg: {:?}", tag);
        let result = serial::CephMsgrMsg::read_from_wire(cursor);
        if result.is_ok(){
            println!("CephMsgrMsg: {:?}", result);
            dissect_msg_op(result.unwrap().header.msg_type, cursor);
        }
    }
    let cmt = serial::CephMsgType::from_u8(tag_bytes);

    if cmt.is_some(){
        println!("Found a backend ceph msg: {:?}", cmt);
    }

/*
    match tag{
        CephMsg::Ready => {
            println!("READY");
        },
        CephMsg::Reset => {
            println!("RESET");
        },
        CephMsg::Wait => {
            println!("WAIT");
        },
        CephMsg::RetrySession => {
            println!("RetrySession");
        },
        CephMsg::RetryGlobal => {
            println!("RetryGlobal");
        },
        CephMsg::Close => {
            println!("CLOSE");
        },
        CephMsg::Msg => {
            println!("MSG");
        },
        CephMsg::Ack => {
            let seq_num = try!(cursor.read_u64::<LittleEndian>());
            println!("ACK: seq number: {}", seq_num);
        },
        CephMsg::KeepAlive => {
            println!("KeepAlive");
        },
        CephMsg::BadProtocolVersion => {},
        CephMsg::BadAuthorizer => {},
        CephMsg::InsufficientFeatures => {
            println!("InsufficientFeatures");
        },
        CephMsg::Seq => {
            println!("SEQ");
        },
        CephMsg::KeepAlive2 => {
            println!("KEEP_ALIVE2");
        },
        CephMsg::KeepAlive2Ack => {
            println!("KEEP_ALIVE2_ACK");
        },
    };
    */
    return Ok(());
}

fn main() {
    match check_user(){
        Ok(_) => {},
        Err(_) =>{
            return;
        }
    };

    let device = get_device();

    let dev_list = match Device::list(){
        Ok(l) => l,
        Err(e) => {
            println!("Unable to list network devices.  Error: {}", e);
            return;
        }
    };

    println!("Validating network device");
    for dev_device in dev_list{
        if dev_device.name == device{
            println!("Found Network device: {:?}", device);
            println!("Setting up capture");
            let mut cap = Capture::from_device(dev_device).unwrap() //open the device
                          .promisc(true)
                          .snaplen(250)
                          .timeout(60000) //60 seconds
                          .open() //activate the handle
                          .unwrap(); //assume activation worked
            println!("Setting up filter");
            //Grab both monitor and OSD traffic
            match cap.filter("tcp portrange 6789-7300"){
                Ok(_) => {
                    println!("Filter successful");
                },
                Err(e) => {
                    println!("Invalid capture filter. Error: {:?}", e);
                    return;
                }
            }
            println!("Datalinks supported: {:?}", cap.list_datalinks().unwrap());
            println!("Current LinkType: {:?}", cap.get_datalink());

            println!("Waiting for packets");
            //Grab some packets :)
            while let Some(packet) = cap.next() {
                let data = packet.data;
                let mut cursor = Cursor::new(&data[..]);
                let packet_header = parse_etherframe(&mut cursor);
                let result = dissect_msgr(&mut cursor);
                if result.is_ok(){
                    if packet_header.is_ok(){
                        let p = packet_header.unwrap();
                        println!("Src: {}:{} Dst: {}:{}",
                            p.src_v4addr.unwrap(),
                            p.src_port,
                            p.dst_v4addr.unwrap(),
                            p.dst_port);
                    }
                    println!("CEPH TAG: {:?}", result);
                }
            }
        }
    }
}
