extern crate byteorder;
extern crate crc;
extern crate nom;
extern crate num;
extern crate time;
extern crate uuid;

//Crates
use self::byteorder::{BigEndian, LittleEndian, WriteBytesExt};
use self::crc::Hasher32;
use self::nom::{GetOutput, le_u8, le_i16, le_u16, le_i32, le_u32, le_u64, be_u16};
use self::nom::IResult::Done;
use self::num::FromPrimitive;
use self::uuid::{ParseError, Uuid};

//Std libs
use std::io;
use std::io::{ErrorKind};
use std::io::prelude::*;
use std::net::{Ipv4Addr,Ipv6Addr,TcpStream};
use std::string::FromUtf8Error;
//There will be no padding between the elements and the elements will be sent in the order they appear

#[cfg(test)]
mod tests{
    use std::io::Cursor;
    use std::io::prelude::*;
    use std::net::{Ipv4Addr,TcpStream};
    use super::CephPrimitive;
    use crypto;

    //Replay captured data and test results
    #[test]
    fn test_connect(){
        //Connect to monitor port
        let mut stream = TcpStream::connect("10.0.3.244:6789").unwrap();
        let mut buf: Vec<u8> = Vec::new();
        //recv banner
        (&mut stream).take(9).read_to_end(&mut buf).unwrap();
        println!("Banner received: {}", String::from_utf8(buf).unwrap()); //we're on a roll :D

        //send banner
        println!("Writing banner back to Ceph");
        let mut bytes_written = super::send_banner(&mut stream).unwrap();
        println!("Wrote {} bytes back to Ceph", bytes_written);

        //Send sockaddr_storage
        let my_addr = super::EntityAddr{
            port: 0,
            nonce: 100,
            addr: Some(super::Addr::v4addr(Ipv4Addr::new(192,168,1,6))),
        };
        let my_addr_bytes = my_addr.write_to_wire().unwrap();
        bytes_written = stream.write(&my_addr_bytes).unwrap();
        println!("Wrote {} sock_addr bytes back to Ceph", bytes_written);

        //Get server sockaddr_storage
        let mut server_addr_reply_buffer = Vec::new();
        (&mut stream).take(136).read_to_end(&mut server_addr_reply_buffer).unwrap();
        let server_entity_addr = super::EntityAddr::read_from_wire(&server_addr_reply_buffer);
        println!("Server entity_addr: {:?}", server_entity_addr);

        let connect = super::CephMsgConnect{
            features: super::CEPH_CLIENT_DEFAULT, //Wireshark is showing not all bits are set
            host_type: super::CephEntity::Client,
            global_seq: 1,
            connect_seq: 0,
            protocol_version: super::Protocol::MonProtocol,
            authorizer_protocol: super::CephAuthProtocol::CephAuthUnknown,
            authorizer_len: 0,
            flags: 1u8<<0, //TODO I think this means lossy
            authorizer: Vec::new(),
        };
        let connect_bytes = connect.write_to_wire().unwrap();
        println!("Writing CephMsgConnect to Ceph {:?}", &connect_bytes);
        bytes_written = stream.write(&connect_bytes).unwrap();
        println!("Wrote {} CephMsgConnect bytes", bytes_written);

        //Is this another sockaddr_storage response from the server??
        let mut bogus_buffer = Vec::new();
        (&mut stream).take(136).read_to_end(&mut bogus_buffer).unwrap();
        println!("Bogus data? bytes: {:?}", &bogus_buffer);

        //Get the connection reply
        let mut msg_reply_buffer = Vec::new();
        (&mut stream).take(26).read_to_end(&mut msg_reply_buffer).unwrap();
        println!("Ceph Msg Reply bytes: {:?}", &msg_reply_buffer);

        //Decode it
        let ceph_msg_reply = super::CephMsgConnectReply::read_from_wire(&msg_reply_buffer);
        println!("CephMsgConnectReply: {:?}", ceph_msg_reply);

        //Create a KeepAlive2
        let keep_alive = super::CephMsgKeepAlive2::new();
        let keep_alive_bytes = keep_alive.write_to_wire().unwrap();

        //Send it
        println!("Writing KeepAlive2 to Ceph {:?}", &keep_alive_bytes);
        bytes_written = stream.write(&keep_alive_bytes).unwrap();
        println!("Wrote {:?} KeepAlive2 bytes", bytes_written);

        //I think I need to setup the authorizer stuff now and negotiate a cephx connection
        //Write a ceph msg of type C_CEPH_MSG_AUTH
        let auth_msg = super::AuthMessage{
            paxos_msg: super::PaxosMessage{
                version: 0,
                mon: -1,
                mon_tid: 0,
            },
            protocol: super::CephAuthProtocol::CephAuthUnknown,
            supported_protocols: vec![super::CephAuthProtocol::CephAuthCephx],
            entity_name: super::CephEntityName{
                entity_type: super::CephEntity::Client,
                id: "admin",
            },
            global_id: 0,
            encoding_version: 1,
            map_epoch: 0,
        };

        let ceph_msgr_auth_msg = super::CephMsgrMsg {
            tag: super::CephMsg::Msg,
            header: super::CephMsgHeader{
                sequence_num: 1,
                transaction_id: 0,
                msg_type: super::CephMsgType::MsgAuth,
                priority: super::CephPriority::Default,
                version: 1,
                front_len: 60,
                middle_len: 0,
                data_len: 0,
                data_off: 0,
                entity_name: super::CephSourceName{
                    entity_type: super::CephEntity::Client,
                    num: 18446744073709551615 //TODO Why is this the max u64?
                },
                compat_version: 1,
                reserved: 0,
                crc: 0, //TODO: how do I calculate this?
            },
            msg: vec![super::Message::Auth(auth_msg)],
            footer: super::CephMsgFooter{
                front_crc: 0, //TODO: how do I calculate this?
                middle_crc: 0,
                data_crc: 0,
                crypto_sig: 0,
                flags: 0,
            },
        };


        let auth_msg_bytes = ceph_msgr_auth_msg.write_to_wire().unwrap();
        println!("auth_msg_bytes {:?}", &auth_msg_bytes);
        bytes_written = stream.write(&auth_msg_bytes).unwrap();
        println!("Wrote {:?} auth bytes", bytes_written);

        let mut keep_alive2_buffer = Vec::new();
        (&mut stream).take(9).read_to_end(&mut keep_alive2_buffer).unwrap();
        let keep_alive2_reply = super::CephMsgKeepAlive2::read_from_wire(&keep_alive2_buffer);
        println!("Got KeepAlive2: {:?}", keep_alive2_reply);

        let mut keep_alive2_ack_buffer = Vec::new();
        (&mut stream).take(9).read_to_end(&mut keep_alive2_ack_buffer).unwrap();
        println!("KeepAlive2Ack {:?}", &keep_alive2_ack_buffer);
        let keep_alive2_ack = super::CephMsgKeepAlive2Ack::read_from_wire(&keep_alive2_ack_buffer);
        println!("Got KeepAlive2Ack: {:?}", keep_alive2_ack);
        //Then MonMap
        //Then AuthReplyMessage

        //let auth_client_ticket = crypto::AuthTicket::new(600.0);
        //let auth_ticket_bytes = auth_client_ticket.write_to_wire().unwrap();

        //  p->a : principal, principal_addr.  authenticate me!
        //bytes_written = stream.write(&auth_ticket_bytes).unwrap();
    }

    #[test]
    fn test_connect_reply(){

    }

    #[test]
    fn test_decode_cephx(){
        //Client msg to the server
        let mut auth_packet: Vec<u8> = vec![
            0x07, //CephMsg
            0x01, //Ready
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x11,0x00,0x7f,0x00,0x01,0x00,0x3c,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x08,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x01,0x00,0x00,0x00,0x69,
            0x4b,0xab,0xe2,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x1e,0x00,0x00,0x00,0x01,0x01,0x00,0x00,0x00,
            0x02,0x00,0x00,0x00,0x08,0x00,0x00,0x00,0x05,0x00,0x00,0x00,0x61,0x64,0x6d,0x69,0x6e,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xc5,0x48,0x27,0x28,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01
        ];
        let msg = super::CephMsgrMsg::read_from_wire(&auth_packet);
        println!("{:?}", msg);

        //Ceph sends back an CephMsgTagAck

        //Then we get the reply
        //Ok now the reply from the server
        let mut auth_packet_reply: Vec<u8> = vec![
            0x07,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x12,0x00,0xc4,0x00,0x01,0x00,0xce,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x01,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x58,
            0x31,0xba,0x7c,

            0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x13,0x10,0x00,0x00,0x00,0x00,0x00,0x00,0xb6,
            0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x01,0x01,0x00,0x00,0x00,0x20,0x00,0x00,
            0x00,0x01,0x30,0x00,0x00,0x00,0x4f,0xb3,0x63,0x3f,0x60,0x5f,0xf9,0x6c,0x3f,0x90,0xeb,
            0x4b,0x00,0xa2,0x6d,0x7f,0x47,0xb5,0xb8,0x16,0xf2,0x35,0xda,0xd0,0xf3,0xdb,0xb6,0xb9,
            0x53,0x79,0xbf,0x48,0x21,0xa9,0x9b,0x05,0x6d,0xa3,0xbb,0xda,0x07,0xe5,0xdb,0x72,0xf4,
            0xb4,0xa6,0x68,0x00,0x6d,0x00,0x00,0x00,0x01,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x60,0x00,0x00,0x00,0x68,0x17,0xd5,0xda,0xec,0xd2,0x9c,0xdd,0xce,0x89,0xd4,0x55,0xa0,
            0x21,0x45,0x9e,0x75,0xef,0xee,0x6f,0x89,0x5d,0x2c,0x6c,0x44,0x39,0x27,0x74,0x3b,0x48,
            0xb5,0x31,0xfd,0x3f,0xeb,0xe2,0xb6,0x38,0xd8,0x52,0xc7,0x99,0xbe,0x75,0x80,0x83,0x07,
            0x0b,0x52,0xaa,0x3a,0x3c,0xd9,0x4f,0xa5,0x41,0x0f,0xc3,0xe8,0xee,0x57,0x25,0x2e,0x0c,
            0x76,0x47,0xfb,0x13,0x57,0x6d,0x2c,0xbf,0x1d,0xec,0x27,0xe8,0xf6,0x87,0xcf,0x0d,0x28,
            0x83,0xe8,0x88,0x9d,0xce,0xe5,0x66,0xfa,0xd0,0x02,0xca,0x54,0x91,0xf4,0x08,0x00,0x00,
            0x00,0x00,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x13,0x10,0x00,0x00,0x00,0x00,0x00,
            0x00,0xb6,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x01,0x01,0x00,0x00,0x00,0x20,
            0x00,0x00,0x00,0x01,0x30,0x00,0x00,0x00,0x4f,0xb3,0x63,0x3f,0x60,0x5f,0xf9,0x6c,0x3f,
            0x90,0xeb,0x4b,0x00,0xa2,0x6d,0x7f,0x47,0xb5,0xb8,0x16,0xf2,0x35,0xda,0xd0,0xf3,0xdb,
            0xb6,0xb9,0x53,0x79,0xbf,0x48,0x21,0xa9,0x9b,0x05,0x6d,0xa3,0xbb,0xda,0x07,0xe5,0xdb,
            0x72,0xf4,0xb4,0xa6,0x68,0x00,0x6d,0x00,0x00,0x00,0x01,0x02,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x60,0x00,0x00,0x00,0x68,0x17,0xd5,0xda,0xec,0xd2,0x9c,0xdd,0xce,0x89,0xd4,
            0x55,0xa0,0x21,0x45,0x9e,0x75,0xef,0xee,0x6f,0x89,0x5d,0x2c,0x6c,0x44,0x39,0x27,0x74,
            0x3b,0x48,0xb5,0x31,0xfd,0x3f,0xeb,0xe2,0xb6,0x38,0xd8,0x52,0xc7,0x99,0xbe,0x75,0x80,
            0x83,0x07,0x0b,0x52,0xaa,0x3a,0x3c,0xd9,0x4f,0xa5,0x41,0x0f,0xc3,0xe8,0xee,0x57,0x25,
            0x2e,0x0c,0x76,0x47,0xfb,0x13,0x57,0x6d,0x2c,0xbf,0x1d,0xec,0x27,0xe8,0xf6,0x87,0xcf,
            0x0d,0x28,0x83,0xe8,0x88,0x9d,0xce,0xe5,0x66,0xfa,0xd0,0x02,0xca,0x54,0x91,0xf4,0x08,
            0x00,0x00,0x00,0x00,0x57,0xbb,0xf7,0xa8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01
        ];
        let mut reply_cursor = Cursor::new(&auth_packet_reply[..]);
        //let reply_msg = super::CephMsgrMsg::read_from_wire(&mut reply_cursor).unwrap();
        //println!("{:?}", reply_msg);

    }

}

#[derive(Debug)]
pub enum SerialError {
	IoError(io::Error),
    ByteOrder(byteorder::Error),
	InvalidValue,
	InvalidType,
    FromUtf8Error(FromUtf8Error),
    UuidParseError(ParseError),
}

impl SerialError{
    pub fn new(err: String) -> SerialError {
        SerialError::IoError(
            io::Error::new(ErrorKind::Other, err)
        )
    }
}

impl From<FromUtf8Error> for SerialError {
    fn from(err: FromUtf8Error) -> SerialError {
        SerialError::FromUtf8Error(err)
    }
}

impl From<byteorder::Error> for SerialError {
    fn from(err: byteorder::Error) -> SerialError {
        SerialError::ByteOrder(err)
    }
}

impl From<io::Error> for SerialError {
    fn from(err: io::Error) -> SerialError {
        SerialError::IoError(err)
    }
}

impl From<ParseError> for SerialError {
    fn from(err: ParseError) -> SerialError {
        SerialError::UuidParseError(err)
    }
}

pub trait CephPrimitive<'a> {
	fn read_from_wire(input: &'a [u8]) -> nom::IResult<&[u8], Self> where Self: Sized; //Result<Self, SerialError> where Self: Sized;
	fn write_to_wire(&self) -> Result<Vec<u8>, SerialError>;
}

#[derive(Debug)]
pub struct CephMsgConnect{
    pub features: CephFeatures, //Composed of CephFeature bitflags
    pub host_type: CephEntity, //u32
    pub global_seq: u32,
    pub connect_seq: u32,
    pub protocol_version: Protocol,
    pub authorizer_protocol: CephAuthProtocol,
    pub authorizer_len: u32,
    pub flags: u8,
    pub authorizer: Vec<u8>,
}

impl<'a> CephPrimitive<'a> for CephMsgConnect{
	fn read_from_wire(input: &'a [u8]) -> nom::IResult<&[u8], Self>{
        chain!(input,
            feature_bits: le_u64 ~
            features: expr_opt!(CephFeatures::from_bits(feature_bits)) ~
            host_type_bits: le_u32 ~
            host_type: expr_opt!(CephEntity::from_u32(host_type_bits)) ~
            global_seq: le_u32 ~
            connect_seq: le_u32 ~
            protocol_bits: le_u32 ~
            protocol_version: expr_opt!(Protocol::from_u32(protocol_bits)) ~
            authorizer_bits: le_u32 ~
            authorizer: expr_opt!(CephAuthProtocol::from_u32(protocol_bits)) ~
            authorizer_len: le_u32 ~
            flags: le_u8,
            ||{
                CephMsgConnect{
                    features: features,
                    host_type: host_type,
                    global_seq: global_seq,
                    connect_seq: connect_seq,
                    protocol_version: protocol_version,
                    authorizer_protocol: authorizer,
                    authorizer_len: authorizer_len,
                    flags: flags,
                    authorizer: Vec::new()
                }
            }
        )
    }
	fn write_to_wire(&self) -> Result<Vec<u8>, SerialError>{
        let mut buffer: Vec<u8> = Vec::new();
        try!(buffer.write_u64::<LittleEndian>(self.features.bits));
        try!(buffer.write_u32::<LittleEndian>(self.host_type.clone() as u32));
        try!(buffer.write_u32::<LittleEndian>(self.global_seq));
        try!(buffer.write_u32::<LittleEndian>(self.connect_seq));
        try!(buffer.write_u32::<LittleEndian>(self.protocol_version.clone() as u32));
        try!(buffer.write_u32::<LittleEndian>(self.authorizer_protocol.clone() as u32));
        try!(buffer.write_u32::<LittleEndian>(self.authorizer_len));
        try!(buffer.write_u8(self.flags));

        return Ok(buffer);
    }
}

#[test]
fn test_ceph_connect_reply(){
    let bytes = vec![
        0x01,0xff,0xff,0xff,0xff,0xff,0x2f,0x00,0x00,0x08,0x00,0x00,0x00,0x01,0x00,0x00,
        0x00,0x0f,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01
    ];
    /*
    let expected_result = CephMsgConnectReply {
        tag: CephMsg::Ready,
        features: CephFeatures::CEPH_ALL,
        global_seq: 8,
        connect_seq: 1,
        protocol_version: Protocol::Unknown,
        authorizer_len: 0,
        flags: 0,
        authorizer: vec![],
    };
    */
    let result = CephMsgConnectReply::read_from_wire(&bytes);
    println!("CephMsgConnectReply parse result: {:?}", result);
}

#[derive(Debug)]
pub struct CephMsgConnectReply{
    pub tag: CephMsg,
    pub features: CephFeatures,
    pub global_seq: u32,
    pub connect_seq: u32,
    pub protocol_version: Protocol,
    pub authorizer_len: u32,
    pub flags: u8,
    pub authorizer: Vec<u8>,
}

impl<'a> CephPrimitive<'a> for CephMsgConnectReply{
	fn read_from_wire(input: &'a [u8]) -> nom::IResult<&[u8], Self>{
        chain!(input,
            tag_bits: le_u8 ~
            tag: expr_opt!(CephMsg::from_u8(tag_bits)) ~
            feature_bits: le_u64 ~
            features: expr_opt!(CephFeatures::from_bits(feature_bits)) ~
            global_seq: le_u32 ~
            connect_seq: le_u32 ~
            protocol_bits: le_u32 ~
            protocol_version: expr_opt!(Protocol::from_u32(protocol_bits)) ~
            authorizer_len: le_u32 ~
            flags: le_u8,
            ||{
                CephMsgConnectReply{
                    tag: tag,
                    features: features,
                    global_seq: global_seq,
                    connect_seq: connect_seq,
                    protocol_version: protocol_version,
                    authorizer_len: authorizer_len,
                    flags: flags,
                    authorizer: Vec::new(),
                }
            }
        )
    }

    fn write_to_wire(&self) -> Result<Vec<u8>, SerialError>{
        let mut buffer: Vec<u8> = Vec::new();
        try!(buffer.write_u8(self.tag.clone() as u8));
        try!(buffer.write_u64::<LittleEndian>(self.features.bits));
        try!(buffer.write_u32::<LittleEndian>(self.global_seq));
        try!(buffer.write_u32::<LittleEndian>(self.connect_seq));
        try!(buffer.write_u32::<LittleEndian>(self.protocol_version.clone() as u32));
        try!(buffer.write_u32::<LittleEndian>(self.authorizer_len));
        try!(buffer.write_u8(self.flags));
        for b in &self.authorizer{
            try!(buffer.write_u8(b.clone()));
        }
        return Ok(buffer);
    }
}

#[derive(Debug)]
pub struct CephMsgrMsg<'a>{
    pub tag: CephMsg,//    u8 tag = 0x07;
    pub header: CephMsgHeader,
    pub msg: Vec<Message<'a>>, //header + messages + footer
    pub footer: CephMsgFooter,
}

impl<'a> CephMsgrMsg<'a>{
    fn new(header: CephMsgHeader, msg: Vec<Message>, footer: CephMsgFooter)->CephMsgrMsg{
        return CephMsgrMsg{
            tag: CephMsg::Msg,
            header: header,
            msg: msg,
            footer: footer,
        }
    }
}

impl<'a> CephPrimitive<'a> for CephMsgrMsg<'a>{
    fn read_from_wire(input: &'a [u8]) -> nom::IResult<&[u8], Self>{
        chain!(input,
            tag_bits: le_u8 ~
            tag: expr_opt!(CephMsg::from_u8(tag_bits)) ~
            header: call!(CephMsgHeader::read_from_wire) ~
            //messages: call!(read_messages_from_wire(input, &header.msg_type)) ~
            footer: call!(CephMsgFooter::read_from_wire),
            ||{
                CephMsgrMsg{
                    tag: tag,
                    header: header,
                    msg: vec![],//messages,
                    footer: footer,
                }
            })
        /*
        //Skip the footer for now
        //If we had control of the TCP Socket than sure we could keep reading and get the footer
        //but for pcap packets we don't have the full packet so this becomes a problem.
        //let footer = try!(CephMsgFooter::read_from_wire(cursor));
        */
    }

    fn write_to_wire(&self) -> Result<Vec<u8>, SerialError>{
        let mut buffer: Vec<u8> = Vec::new();
        try!(buffer.write_u8(self.tag.clone() as u8));

        let header_bits = try!(self.header.write_to_wire());
        for b in header_bits{
            try!(buffer.write_u8(b.clone()));
        }
        //Encode Message
        for msg in self.msg.iter(){
            let bits = try!(write_message_to_wire(msg));
            buffer.extend(bits);
        }

        let footer_bits = try!(self.footer.write_to_wire());

        for b in footer_bits{
            try!(buffer.write_u8(b.clone()));
        }

        return Ok(buffer);
    }
}

enum_from_primitive!{
//#[repr(u32)]
#[repr(u8)]
#[derive(Debug, Clone,Eq,PartialEq)]
pub enum CephEntity{
    Mon=1,
    Mds=2,
    Osd=4,
    Client=8,
    Auth=20, //Used to setup a new CephX connection
    Any=255
}
}

enum_from_primitive!{
#[repr(u32)]
#[derive(Debug, Clone, Eq, PartialEq)]
enum Crypto {
    None = 0,
    Aes = 1,
}
}

enum_from_primitive!{
#[repr(u32)]
#[derive(Debug, Clone)]
pub enum Protocol{
    OsdProtocol = 24, /*server/client*/
    MdsProtocol = 32, /*server/client*/
    MonProtocol = 15, /*server/client*/
}
}

bitflags!{
    flags CephFeatures: u64 {
        const CEPH_FEATURE_UID  = 1u64 <<0,
        const CEPH_FEATURE_NOSRCADDR = 1u64 <<1,
        const CEPH_FEATURE_MONCLOCKCHECK = 1u64 <<2,
        const CEPH_FEATURE_FLOCK = 1u64 << 3,
        const CEPH_FEATURE_SUBSCRIBE2 = 1u64 <<4,
        const CEPH_FEATURE_MONNAME = 1u64 <<5,
        const CEPH_FEATURE_RECONNECT_SEQ = 1u64 <<6,
        const CEPH_FEATURE_DIRLAYOUTHASH = 1u64 << 7,
        const CEPH_FEATURE_OBJECTLOCATOR = 1u64 << 8,
        const CEPH_FEATURE_PGID64 = 1u64 << 9,
        const CEPH_FEATURE_INCSUBOSDMAP = 1u64 << 10,
        const CEPH_FEATURE_PGPOOL3 = 1u64 << 11,
        const CEPH_FEATURE_OSDREPLYMUX = 1u64 << 12,
        const CEPH_FEATURE_OSDENC = 1u64 << 13,
        const CEPH_FEATURE_OMAP = 1u64 << 14,
        const CEPH_FEATURE_QUERY_T = 1u64 << 15,
        const CEPH_FEATURE_MONENC = 1u64 << 16,
        const CEPH_FEATURE_INDEP_PG_MAP = 1u64 << 17,
        const CEPH_FEATURE_CRUSH_TUNABLES = 1u64 << 18,
        const CEPH_FEATURE_CHUNKY_SCRUB = 1u64 << 19,
        const CEPH_FEATURE_MON_NULLROUTE = 1u64 << 20,
        const CEPH_FEATURE_MON_GV = 1u64 << 21,
        const CEPH_FEATURE_BACKFILL_RESERVATION = 1u64 << 22,
        const CEPH_FEATURE_MSG_AUTH = 1u64 << 23,
        const CEPH_FEATURE_RECOVERY_RESERVATION = 1u64 << 24,
        const CEPH_FEATURE_CRUSH_TUNABLES1 = 1u64 << 25,
        const CEPH_FEATURE_CREATEPOOLID = 1u64 << 26,
        const CEPH_FEATURE_REPLY_CREATE_INODE = 1u64 << 27,
        const CEPH_FEATURE_OSD_HBMSGS = 1u64 << 28,
        const CEPH_FEATURE_MDSENC = 1u64 << 29,
        const CEPH_FEATURE_OSDHASHPSPOOL = 1u64 << 30,
        const CEPH_FEATURE_MON_SINGLE_PAXOS = 1u64 << 31,
        const CEPH_FEATURE_OSD_SNAPMAPPER = 1u64 << 32,
        const CEPH_FEATURE_MON_SCRUB = 1u64 << 33,
        const CEPH_FEATURE_OSD_PACKED_RECOVERY = 1u64 << 34,
        const CEPH_FEATURE_OSD_CACHEPOOL = 1u64 << 35,
        const CEPH_FEATURE_CRUSH_V2 = 1u64 << 36,
        const CEPH_FEATURE_EXPORT_PEER = 1u64 << 37,
        const CEPH_FEATURE_OSD_ERASURE_CODES = 1u64 << 38,
        const CEPH_FEATURE_OSDMAP_ENC = 1u64 << 39,
        const CEPH_FEATURE_MDS_INLINE_DATA = 1u64 << 40,
        const CEPH_FEATURE_CRUSH_TUNABLES3 = 1u64 << 41,
        const CEPH_FEATURE_OSD_PRIMARY_AFFINITY = 1u64 << 41, //overlap with tunables3
        const CEPH_FEATURE_MSGR_KEEPALIVE2 = 1u64 << 42,
        const CEPH_FEATURE_OSD_POOLRESEND = 1u64 << 43,
        const CEPH_FEATURE_ERASURE_CODE_PLUGINS_V2 = 1u64 << 44,
        const CEPH_FEATURE_OSD_SET_ALLOC_HINT = 1u64 << 45,
        const CEPH_FEATURE_OSD_FADVISE_FLAGS = 1u64 << 46,
        const CEPH_FEATURE_OSD_REPOP = 1u64 << 46, //overlap with fadvice
        const CEPH_FEATURE_OSD_OBJECT_DIGEST = 1u64 << 46, //overlap with fadvice
        const CEPH_FEATURE_OSD_TRANSACTION_MAY_LAYOUT = 1u64 << 46, //overlap with fadvice
        const CEPH_FEATURE_MDS_QUOTA = 1u64 << 47,
        const CEPH_FEATURE_CRUSH_V4 = 1u64 << 48,
        const CEPH_FEATURE_OSD_MIN_SIZE_RECOVERY = 1u64 << 49, //overlap
    	const CEPH_FEATURE_OSD_PROXY_FEATURES = 1u64 << 49,
        const CEPH_FEATURE_MON_METADATA = 1u64 << 50,
        const CEPH_FEATURE_OSD_BITWISE_HOBJ_SORT = 1u64 << 51,
        const CEPH_FEATURE_ERASURE_CODE_PLUGINS_V3 = 1u64 << 52,
        const CEPH_FEATURE_OSD_PROXY_WRITE_FEATURES = 1u64 << 53,
        const CEPH_FEATURE_OSD_HITSET_GMT = 1u64 << 54,
    	const CEPH_FEATURE_RESERVED2 = 1u64 << 61,
    	const CEPH_FEATURE_RESERVED = 1u64 << 62,
    	const CEPH_FEATURE_RESERVED_BROKEN = 1u64 << 63,
        const CEPH_CLIENT_DEFAULT =  CEPH_FEATURE_UID.bits
            | CEPH_FEATURE_NOSRCADDR.bits
            | CEPH_FEATURE_MONCLOCKCHECK.bits
            | CEPH_FEATURE_FLOCK.bits
            | CEPH_FEATURE_SUBSCRIBE2.bits
            | CEPH_FEATURE_MONNAME.bits
            | CEPH_FEATURE_RECONNECT_SEQ.bits
            | CEPH_FEATURE_DIRLAYOUTHASH.bits

            | CEPH_FEATURE_OBJECTLOCATOR.bits
            | CEPH_FEATURE_PGID64.bits
            | CEPH_FEATURE_INCSUBOSDMAP.bits
            | CEPH_FEATURE_PGPOOL3.bits
            | CEPH_FEATURE_OSDREPLYMUX.bits
            | CEPH_FEATURE_OSDENC.bits
            | CEPH_FEATURE_OMAP.bits
            | CEPH_FEATURE_QUERY_T.bits

            | CEPH_FEATURE_MONENC.bits
            | CEPH_FEATURE_INDEP_PG_MAP.bits
            | CEPH_FEATURE_CRUSH_TUNABLES.bits
            | CEPH_FEATURE_CHUNKY_SCRUB.bits
            | CEPH_FEATURE_MON_NULLROUTE.bits
            | CEPH_FEATURE_MON_GV.bits
            | CEPH_FEATURE_BACKFILL_RESERVATION.bits
            | CEPH_FEATURE_MSG_AUTH.bits

            | CEPH_FEATURE_RECOVERY_RESERVATION.bits
            | CEPH_FEATURE_CRUSH_TUNABLES1.bits
            | CEPH_FEATURE_CREATEPOOLID.bits
            | CEPH_FEATURE_REPLY_CREATE_INODE.bits
            | CEPH_FEATURE_OSD_HBMSGS.bits
            | CEPH_FEATURE_MDSENC.bits
            | CEPH_FEATURE_OSDHASHPSPOOL.bits
            | CEPH_FEATURE_MON_SINGLE_PAXOS.bits

            | CEPH_FEATURE_OSD_SNAPMAPPER.bits
            | CEPH_FEATURE_MON_SCRUB.bits
            | CEPH_FEATURE_OSD_PACKED_RECOVERY.bits
            | CEPH_FEATURE_OSD_CACHEPOOL.bits
            | CEPH_FEATURE_CRUSH_V2.bits
            | CEPH_FEATURE_EXPORT_PEER.bits
            | CEPH_FEATURE_OSD_ERASURE_CODES.bits
            | CEPH_FEATURE_OSDMAP_ENC.bits,

        const CEPH_ALL = CEPH_FEATURE_UID.bits
            | CEPH_FEATURE_NOSRCADDR.bits
            | CEPH_FEATURE_MONCLOCKCHECK.bits
            | CEPH_FEATURE_FLOCK.bits
            | CEPH_FEATURE_SUBSCRIBE2.bits
            | CEPH_FEATURE_MONNAME.bits
            | CEPH_FEATURE_RECONNECT_SEQ.bits
            | CEPH_FEATURE_DIRLAYOUTHASH.bits
            | CEPH_FEATURE_OBJECTLOCATOR.bits
            | CEPH_FEATURE_PGID64.bits
            | CEPH_FEATURE_INCSUBOSDMAP.bits
            | CEPH_FEATURE_PGPOOL3.bits
            | CEPH_FEATURE_OSDREPLYMUX.bits
            | CEPH_FEATURE_OSDENC.bits
            | CEPH_FEATURE_OMAP.bits
            | CEPH_FEATURE_QUERY_T.bits
            | CEPH_FEATURE_MONENC.bits
            | CEPH_FEATURE_INDEP_PG_MAP.bits
            | CEPH_FEATURE_CRUSH_TUNABLES.bits
            | CEPH_FEATURE_CHUNKY_SCRUB.bits
            | CEPH_FEATURE_MON_NULLROUTE.bits
            | CEPH_FEATURE_MON_GV.bits
            | CEPH_FEATURE_BACKFILL_RESERVATION.bits
            | CEPH_FEATURE_MSG_AUTH.bits
            | CEPH_FEATURE_RECOVERY_RESERVATION.bits
            | CEPH_FEATURE_CRUSH_TUNABLES1.bits
            | CEPH_FEATURE_CREATEPOOLID.bits
            | CEPH_FEATURE_REPLY_CREATE_INODE.bits
            | CEPH_FEATURE_OSD_HBMSGS.bits
            | CEPH_FEATURE_MDSENC.bits
            | CEPH_FEATURE_OSDHASHPSPOOL.bits
            | CEPH_FEATURE_MON_SINGLE_PAXOS.bits
            | CEPH_FEATURE_OSD_SNAPMAPPER.bits
            | CEPH_FEATURE_MON_SCRUB.bits
            | CEPH_FEATURE_OSD_PACKED_RECOVERY.bits
            | CEPH_FEATURE_OSD_CACHEPOOL.bits
            | CEPH_FEATURE_CRUSH_V2.bits
            | CEPH_FEATURE_EXPORT_PEER.bits
            | CEPH_FEATURE_OSD_ERASURE_CODES.bits
            | CEPH_FEATURE_OSDMAP_ENC.bits
            | CEPH_FEATURE_MDS_INLINE_DATA.bits
            | CEPH_FEATURE_CRUSH_TUNABLES3.bits
            | CEPH_FEATURE_OSD_PRIMARY_AFFINITY.bits
            | CEPH_FEATURE_MSGR_KEEPALIVE2.bits
            | CEPH_FEATURE_OSD_POOLRESEND.bits
            | CEPH_FEATURE_ERASURE_CODE_PLUGINS_V2.bits
            | CEPH_FEATURE_OSD_SET_ALLOC_HINT.bits
            | CEPH_FEATURE_OSD_FADVISE_FLAGS.bits
            | CEPH_FEATURE_OSD_REPOP.bits
            | CEPH_FEATURE_OSD_OBJECT_DIGEST.bits
            | CEPH_FEATURE_OSD_TRANSACTION_MAY_LAYOUT.bits
            | CEPH_FEATURE_MDS_QUOTA.bits
            | CEPH_FEATURE_CRUSH_V4.bits
            | CEPH_FEATURE_OSD_MIN_SIZE_RECOVERY.bits
            | CEPH_FEATURE_OSD_PROXY_FEATURES.bits
            | CEPH_FEATURE_MON_METADATA.bits
            | CEPH_FEATURE_OSD_BITWISE_HOBJ_SORT.bits
            | CEPH_FEATURE_ERASURE_CODE_PLUGINS_V3.bits
            | CEPH_FEATURE_OSD_PROXY_WRITE_FEATURES.bits
            | CEPH_FEATURE_OSD_HITSET_GMT.bits,
    }
}

enum_from_primitive!{
#[repr(u32)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum CephAuthProtocol{
    CephAuthUnknown = 0,
    CephAuthNone = 1,
    CephAuthCephx = 2,
}
}

enum_from_primitive!{
#[repr(u16)]
#[derive(Debug, Clone,Eq,PartialEq)]
pub enum CephPriority{
    Low = 64,
    Default = 127,
    High = 196,
    Highest = 255,
}
}

enum_from_primitive! {
#[derive(Debug, Clone,Eq,PartialEq)]
pub enum CephMsg{
    Ready = 1, /* server->client: ready for messages */
    Reset = 2, /* server->client: reset, try again */
    Wait = 3,  /* server->client: wait for racing incoming connection */
    RetrySession = 4, /* server->client + cseq: try again
	            			with higher cseq */
    RetryGlobal = 5,  /* server->client + gseq: try again
					       with higher gseq */
    Close = 6, /* closing pipe */
    Msg = 7,  /* message */
    Ack = 8,  /* message ack */
    KeepAlive = 9, /* just a keepalive byte! */
    BadProtocolVersion = 10, /* bad protocol version */
    BadAuthorizer = 11, /* bad authorizer */
    InsufficientFeatures = 12, /* insufficient features */
    Seq = 13, /* 64-bit int follows with seen seq number */
    KeepAlive2 = 14,
    KeepAlive2Ack = 15, /* keepalive reply */
    Unknown = 20,
}
}

#[derive(Debug,Eq,PartialEq)]
pub enum Message<'a>{
    Auth(AuthMessage<'a>),
    AuthReply(CephAuthOperationReply<'a>),
    Paxos(PaxosMessage),
    Command,
    CommandReply,
    WatchNotify,
    MsgForward,
    MsgRoute,
    MonCommand(MonCommand<'a>),
    MonCommandAck,
    Log,
    LogAck,
    Class,
    ClassAck,
    Getpoolstats,
    Getpoolstatsreply,
    GlobalId,
    MonScrub,
    MonElection,
    MonPaxos,
    MonProbe,
    MonJoin,
    MonSync,
    OsdAlive,
    OsdBoot,
    OsdFailure,
    OsdMarkMeDown,
    OsdMap,
    OsdOp(CephOsdOperation<'a>),
    OsdOpRepl(CephOsdOperationReply<'a>),
    OsdPing,
    OsdSubop(CephOsdOperation<'a>),
    OsdSubopReply(CephOsdOperationReply<'a>),
    OsdPgtemp,
    OsdPgNotify,
    OsdPgQuery,
    OsdPgSummary,
    OsdPgLog,
    OsdPgRemove,
    OsdPgInfo,
    OsdPgTrim,
    OsdScrub,
    OsdPgMissing,
    OsdRepScrub,
    OsdPgScan,
    OsdPgBackfill,
    Pgstats,
    Pgstatsack,
    OsdPgCreate,
    RemoveSnaps,
    OsdBackfillReserve,
    OsdRecoveryReserve,
    OsdPgPush,
    OsdPgPull,
    OsdPgPushReply,
    OsdEcWrite,
    OsdEcWriteReply,
    OsdEcRead,
    OsdEcReadReply,
    OsdRepop,
    OsdRepopreply,
    Timecheck,
    MonHealth,
    CrcData,
    CrcHeader,
    DataPing,
    Nop,
}

//Decode the msg from the wire and return the correct variant
fn read_messages_from_wire<'a>(cursor: &'a [u8], msg_type: &CephMsgType) -> nom::IResult<&'a [u8], Vec<Message<'a>>>{
    match msg_type{
        &CephMsgType::MsgAuth => {
            chain!(cursor,
                authop: call!(AuthMessage::read_from_wire),
                ||{
                    let mut v:Vec<Message> = Vec::new();
                    v.push(Message::Auth(authop));
                    v
                }
            )
        },
        &CephMsgType::MsgAuthReply => {
            chain!(cursor,
                auth_reply: call!(CephAuthOperationReply::read_from_wire),
                || {
                    let mut v:Vec<Message> = Vec::new();
                    v.push(Message::AuthReply(auth_reply));
                    v
                }
            )
        },
        &CephMsgType::MsgOsdOp => {
            chain!(cursor,
                osdop: call!(CephOsdOperation::read_from_wire),
                || {
                    let mut v:Vec<Message> = Vec::new();
                    v.push(Message::OsdOp(osdop));
                    v
                }
            )
        },
        &CephMsgType::MsgOsdOpReply => {
            chain!(cursor,
                op_reply: call!(CephOsdOperationReply::read_from_wire),
                || {
                    let mut v:Vec<Message> = Vec::new();
                    v.push(Message::OsdOpRepl(op_reply));
                    v
                }
            )
        },
        &CephMsgType::MsgOsdSubop => {
            chain!(cursor,
                osdop: call!(CephOsdOperation::read_from_wire),
                || {
                    let mut v:Vec<Message> = Vec::new();
                    v.push(Message::OsdSubop(osdop));
                    v
                }
            )
        },
        &CephMsgType::MsgOsdSubopReply => {
            chain!(cursor,
                osdop: call!(CephOsdOperationReply::read_from_wire),
                || {
                    let mut v:Vec<Message> = Vec::new();
                    v.push(Message::OsdSubopReply(osdop));
                    v
                }
            )
        },
        &CephMsgType::MsgMonCommand =>{
            chain!(cursor,
                mon_command: call!(MonCommand::read_from_wire),
                || {
                    let mut v:Vec<Message> = Vec::new();
                    v.push(Message::MonCommand(mon_command));
                    v
                }
            )
        },
        _ => {
            let mut v:Vec<Message> = Vec::new();
            v.push(Message::Nop);
            Done(&cursor[..], v)
        },
    }
}

fn write_message_to_wire(msg: &Message) -> Result<Vec<u8>, SerialError>{
    match msg{
        &Message::MonCommand(ref mon_cmd) =>{
            let bytes = try!(mon_cmd.write_to_wire());
            return Ok(bytes);
        },
        &Message::OsdOp(ref osd_op) => {
            let bytes = try!(osd_op.write_to_wire());
            return Ok(bytes);
        },
        &Message::OsdOpRepl(ref osd_op) => {
            let bytes = try!(osd_op.write_to_wire());
            return Ok(bytes);
        },
        _ => {
            return Ok(Vec::new());
        },
    }
}

enum_from_primitive! {
#[derive(Debug, Clone,Eq,PartialEq)]
pub enum CephMsgType{
    //MsgShutdown = 1 ,
    //MsgPing = 2,
    /* client <-> monitor */
    MsgMonMap = 4,
    MsgMonGetMap = 5,
    MsgMonGetOsdmap = 6,
    MsgMonMetadata = 7,
    MsgStatfs = 13,
    MsgStatfsReply = 14,
    MsgMonSubscribe = 15,
    MsgMonSubscribeAck = 16,
    MsgAuth = 17,
    MsgAuthReply = 18,
    MsgMonGetVersion =  19,
    MsgMonGetVersionReply = 20,

    MsgPaxos = 40,
    MsgOsdMap = 41,
    MsgOsdOp = 42,
    MsgOsdOpReply = 43,
    MsgWatchNotify = 44,
    MsgForward = 46,
    MsgRoute = 47,

    MsgMonCommand = 50,
    MsgMonCommandAck = 51,
    MsgLog = 52,
    MsgLogAck = 53,
    //MsgMonObserve = 54,
    //MsgMonObserveNotify = 55,
    MsgClass = 56,
    MsgClassAck = 57,
    MsgGetpoolstats  = 58,
    MsgGetpoolstatsreply = 59,
    MsgMonGlobalId = 60,

    // monitor internal
    MsgMonScrub = 64,
    MsgMonElection = 65,
    MsgMonPaxos = 66,
    MsgMonProbe= 67,
    MsgMonJoin = 68,
    MsgMonSync = 69,
    // OSD
    MsgOsdPing = 70,
    MsgOsdBoot = 71,
    MsgOsdFailure = 72,
    MsgOsdAlive = 73,
    MsgOsdMarkMeDown = 74,
    MsgOsdSubop = 76,
    MsgOsdSubopReply = 77,
    MsgOsdPgtemp = 78,
    MsgOsdPgNotify = 80,
    MsgOsdPgQuery = 81,
    MsgOsdPgSummary = 82,
    MsgOsdPgLog = 83,
    MsgOsdPgRemove = 84,
    MsgOsdPgInfo = 85,
    MsgOsdPgTrim = 86,
    MsgPgstats = 87,
    MsgPgstatsack = 88,
    MsgOsdPgCreate = 89,
    MsgRemoveSnaps = 90,
    MsgOsdScrub = 91,
    MsgOsdPgMissing = 92,
    MsgOsdRepScrub = 93,
    MsgOsdPgScan = 94,
    MsgOsdPgBackfill = 95,
    MsgCommand = 97,
    MsgCommandReply = 98,
    MsgOsdBackfillReserve=99,
    MsgOsdRecoveryReserve=150,
    MsgOsdPgPush = 105,
    MsgOsdPgPull = 106,
    MsgOsdPgPushReply= 107,
    MsgOsdEcWrite =  108,
    MsgOsdEcWriteReply=109,
    MsgOsdEcRead = 110,
    MsgOsdEcReadReply =111,
    MsgOsdRepop = 112,
    MsgOsdRepopreply = 113,
    // *** generic ***
    MsgTimecheck = 0x600,
    MsgMonHealth = 0x601,
    // *** Message::encode() crcflags bits ***
    MsgCrcData = (1 << 0),
    MsgCrcHeader = (1 << 1),
    //MsgCrcAll = (MsgCrcData | MsgCrcHeader),
    // Xio Testing
    MsgDataPing = 0x602,
    MsgNop = 0x607,
}
}

bitflags!{
    flags OsdOp: u32 {
        const CEPH_OSD_FLAG_ACK =            0x0001,  /* want (or is) "ack" ack */
        const CEPH_OSD_FLAG_ONNVRAM =        0x0002,  /* want (or is) "onnvram" ack */
        const CEPH_OSD_FLAG_ACK_ONDISK =     0x0004,  /* want (or is) "ondisk" ack */
        const CEPH_OSD_FLAG_RETRY =          0x0008,  /* resend attempt */
        const CEPH_OSD_FLAG_READ =           0x0010,  /* op may read */
        const CEPH_OSD_FLAG_WRITE =          0x0020,  /* op may write */
        const CEPH_OSD_FLAG_ORDERSNAP =      0x0040,  /* EOLDSNAP if snapc is out of order */
        const CEPH_OSD_FLAG_PEERSTAT_OLD =   0x0080,  /* DEPRECATED msg includes osd_peer_stat */
        const CEPH_OSD_FLAG_BALANCE_READS =  0x0100,
        const CEPH_OSD_FLAG_PARALLELEXEC =   0x0200,  /* execute op in parallel */
        const CEPH_OSD_FLAG_PGOP =           0x0400,  /* pg op, no object */
        const CEPH_OSD_FLAG_EXEC =           0x0800,  /* op may exec */
        const CEPH_OSD_FLAG_EXEC_PUBLIC =    0x1000,  /* DEPRECATED op may exec (public) */
        const CEPH_OSD_FLAG_LOCALIZE_READS = 0x2000,  /* read from nearby replica, if any */
        const CEPH_OSD_FLAG_RWORDERED =      0x4000,  /* order wrt concurrent reads */
        const CEPH_OSD_FLAG_IGNORE_CACHE =   0x8000,  /* ignore cache logic */
        const CEPH_OSD_FLAG_SKIPRWLOCKS =   0x10000,  /* skip rw locks */
        const CEPH_OSD_FLAG_IGNORE_OVERLAY =0x20000,  /* ignore pool overlay */
        const CEPH_OSD_FLAG_FLUSH =         0x40000,  /* this is part of flush */
        const CEPH_OSD_FLAG_MAP_SNAP_CLONE =0x80000,  /* map snap direct to clone id */
        const CEPH_OSD_FLAG_ENFORCE_SNAPC  =0x100000,  /* use snapc provided even if */
        const CEPH_OSD_FLAG_REDIRECTED   = 0x200000,  /* op has been redirected */
        const CEPH_OSD_FLAG_KNOWN_REDIR = 0x400000,  /* redirect bit is authoritative */
    }
}

#[derive(Debug,Eq,PartialEq)]
pub struct Subscription<'a>{
    name: &'a str,
    start_time: u64, //what is this?  Time since epoch?
    flags: u8,
}

impl<'a> CephPrimitive<'a> for Subscription<'a>{
    fn read_from_wire(input: &'a [u8]) -> nom::IResult<&[u8], Self>{
        chain!(input,
            str_len: le_u32 ~
            name: take_str!(str_len) ~
            start_time: le_u64 ~
            flags: le_u8, || {
                Subscription {
                    name: name,
                    start_time: start_time,
                    flags: flags
                }
            }
        )
    }

	fn write_to_wire(&self) -> Result<Vec<u8>, SerialError>{
        let mut buffer:Vec<u8> = Vec::new();
        buffer.extend(self.name.as_bytes());
        try!(buffer.write_u64::<LittleEndian>(self.start_time));
        try!(buffer.write_u8(self.flags));

        return Ok(buffer);
    }
}

#[derive(Debug,Eq,PartialEq)]
pub struct MonitorSubscribe<'a>{
    subscriptions: Vec<Subscription<'a>>,
}

impl<'a> CephPrimitive<'a> for MonitorSubscribe<'a>{
    fn read_from_wire(input: &'a [u8]) -> nom::IResult<&[u8], Self>{
        chain!(input,
            number_of_items: le_u32 ~
            subscriptions: count!(Subscription::read_from_wire, number_of_items as usize),
            ||{
                MonitorSubscribe{
                    subscriptions: subscriptions
                }
            }
        )
    }

	fn write_to_wire(&self) -> Result<Vec<u8>, SerialError>{
        let mut buffer:Vec<u8> = Vec::new();
        for subscription in self.subscriptions.iter(){
            let subscription_bytes = try!(subscription.write_to_wire());
            buffer.extend(subscription_bytes);
        }

        return Ok(buffer);
    }
}

#[derive(Debug,Eq,PartialEq)]
pub struct ObjectLocator<'a>{
    pub encoding_version: u8,
    pub min_compat_version: u8,
    pub size: u32,
    pub pool: u64,
    pub namespace_size: u32,
    pub namespace_data: &'a [u8],
}

impl<'a> CephPrimitive<'a> for ObjectLocator<'a> {
    fn read_from_wire(input: &'a [u8]) -> nom::IResult<&[u8], Self>{
        chain!(input,
            encoding_version: le_u8 ~
            min_compat_version: le_u8 ~
            size: le_u32 ~
            pool: le_u64 ~
            //TODO: Wireshark skips 8 bytes here.  What is this?
            skip: le_u64 ~
            namespace_size: le_u32 ~
            namespace_data: take!(namespace_size) ~
            //TODO: Wireshark skips 8 bytes here.  What is this?
            skip_2: le_u64,
            || {
            ObjectLocator{
                encoding_version: encoding_version,
                min_compat_version: min_compat_version,
                size: size,
                pool: pool,
                namespace_size: namespace_size,
                namespace_data: namespace_data,
            }
        })
    }

	fn write_to_wire(&self) -> Result<Vec<u8>, SerialError>{
        let mut buffer:Vec<u8> = Vec::new();
        try!(buffer.write_u8(self.encoding_version));
        try!(buffer.write_u8(self.min_compat_version));
        try!(buffer.write_u32::<LittleEndian>(self.size));
        try!(buffer.write_u64::<LittleEndian>(self.pool));
        try!(buffer.write_u32::<LittleEndian>(self.namespace_size));
        buffer.extend(self.namespace_data);

        return Ok(buffer);
    }
}

#[derive(Debug,Eq,PartialEq)]
pub struct PlacementGroup{
    pub group_version: u8,
    pub pool: u64,
    pub seed: u32,
    pub preferred: u32,
}

impl<'a> CephPrimitive<'a> for PlacementGroup {
    fn read_from_wire(input: &'a [u8]) -> nom::IResult<&[u8], Self>{
        chain!(input,
            group_version: le_u8 ~
            pool: le_u64 ~
            seed: le_u32 ~
            preferred: le_u32, || {
                PlacementGroup {
                    group_version: group_version,
                    pool: pool,
                    seed: seed,
                    preferred: preferred
                }
            }
        )
    }

	fn write_to_wire(&self) -> Result<Vec<u8>, SerialError>{
        let mut buffer:Vec<u8> = Vec::new();
        try!(buffer.write_u8(self.group_version));
        try!(buffer.write_u64::<LittleEndian>(self.pool));
        try!(buffer.write_u32::<LittleEndian>(self.seed));
        try!(buffer.write_u32::<LittleEndian>(self.preferred));

        return Ok(buffer);
    }

}
#[derive(Debug,Eq,PartialEq)]
pub struct Monitor<'a>{
    name: &'a str,
    entity_addr: EntityAddr,
    /*
    ipv4_addr: Option<Ipv4Addr>,
    ipv6_addr: Option<Ipv6Addr>,
    port: u16,
    */
}

impl<'a> CephPrimitive<'a> for Monitor<'a>{
    fn read_from_wire(input: &'a [u8]) -> nom::IResult<&[u8], Self>{
        println!("Monitor land");
        chain!(input,
            name: parse_str ~
            entity_addr: call!(EntityAddr::read_from_wire),
            ||{
                Monitor{
                    name: name,
                    entity_addr: entity_addr,
                }
            }
        )
    }

	fn write_to_wire(&self) -> Result<Vec<u8>, SerialError>{
        let buffer:Vec<u8> = Vec::new();

        return Ok(buffer);
    }
}

#[derive(Debug,Eq,PartialEq)]
pub struct ClientHitSetParams{
    encoding_version: u8,
    min_compat_version: u8,
    size: u32,
    hitset_type: u8, //decode me
}

impl<'a> CephPrimitive<'a> for ClientHitSetParams{
    fn read_from_wire(input: &'a [u8]) -> nom::IResult<&[u8], Self>{
        chain!(input,
            encoding_version: le_u8 ~
            min_compat_version: le_u8 ~
            size: le_u32 ~
            hitset_type: le_u8, ||{
                ClientHitSetParams {
                    encoding_version: encoding_version,
                    min_compat_version: min_compat_version,
                    size: size,
                    hitset_type: hitset_type
                }
            }
        )
    }

	fn write_to_wire(&self) -> Result<Vec<u8>, SerialError>{
        let mut buffer:Vec<u8> = Vec::new();

        try!(buffer.write_u8(self.encoding_version));
        try!(buffer.write_u8(self.min_compat_version));
        try!(buffer.write_u32::<LittleEndian>(self.size));
        try!(buffer.write_u8(self.hitset_type));

        return Ok(buffer);
    }
}
/*
#[derive(Debug,Eq,PartialEq)]
pub struct ClientPgInfo{
    encoding_version: u8,
    min_compat_version: u8,
    size: u32, //ceph.nanoseconds ?? what is this
    pool_type: u8, //Replicated/ Erasure //decode me
    pool_size: u8,
    crush_ruleset: u8,
    object_hash: u8,
    pg_count: u32,
    pgp_count: u32,
    last_changed: u32,
    snap_seq: u64,
    epoch: u32,
    user_id: u64,
    hash_flags: u32, //hash seed + pool together
    crash_replay_interval: u32,
    min_num_osds: u8,
    max_bytes: u64, //quotas
    max_objects: u64, //quotas
    tier_of: u64,
    cache_mode: u8,
    read_tier: u64,
    write_tier: u64,
    hitset_period: u32,
    hitset_count: u32,
    stripe_width: u32,
    target_max_bytes: u64, //quotas
    target_max_objects: u64, //quotas
    cache_target_dirty_full_ratio: u32,
    cache_target_full_ratio: u32,
    cache_min_flush_age: u32,
    cache_min_evict_age: u32,
    erasure_code_profile: String,
    last_force_resend: u32,
}

impl<'a> CephPrimitive<'a> for ClientHitSetParams<'a>{
    fn read_from_wire(input: &'a [u8]) -> nom::IResult<&[u8], Self> {
        chain!(input,
            encoding_version: le_u8 ~
            min_compat_version: le_u8 ~
            size: le_u32 ~
            pool_size: le_u8 ~
            crush_ruleset: le_u8 ~
            object_hash: le_u8 ~
            pg_count: le_u32 ~
            pgp_count: le_u32 ~
            last_changed: le_u32 ~
            snap_seq: le_u64 ~
            epoch: le_u32 ~
            user_id: le_u64 ~
            hash_flags: le_u32 ~
            crash_replay_interval: le_u32 ~
            min_num_osds: le_u8 ~
            max_bytes: le_u64 ~
            max_objects: le_u64 ~
            tier_of: le_u64 ~
            cache_mode: le_u8 ~
            read_tier: le_u64 ~
            write_tier: le_u64 ~
            hitset_period: le_u32 ~
            hitset_count: le_u32 ~
            stripe_width: le_u32 ~
            target_max_bytes: le_u64 ~
            target_max_objects: le_u64 ~
            cache_target_dirty_full_ratio: le_u32 ~
            cache_target_full_ratio: le_u32 ~
            cache_min_flush_age: le_u32 ~
            cache_min_evict_age: le_u32 ~
            str_len: le_u32 ~
            erasure_code_profile: call!(read_string(input)) ~
            last_force_resend: le_u32, || {
                ClientPgInfo {
                    encoding_version: encoding_version,
                    min_compat_version: min_compat_version,
                    size: size,
                    hitset_type: hitset_type
                }
            }
        );
    }

	fn write_to_wire(&self) -> Result<Vec<u8>, SerialError>{
        let mut buffer:Vec<u8> = Vec::new();

        try!(buffer.write_u8(self.encoding_version));
        try!(buffer.write_u8(self.min_compat_version));
        try!(buffer.write_u32::<LittleEndian>(self.size));
        try!(buffer.write_u8(self.hitset_type));

        return Ok(buffer);
    }
}
*/
#[derive(Debug,Eq,PartialEq)]
pub struct ClientOsdData<'a>{
    encoding_version: u8,
    min_compat_version: u8,
    size: u32,
    fsid: Uuid,
    epoch: u32,
    time_created: Utime,
    last_modified: Utime,
    //pools: Vec<ClientPoolInfo>,
    pool_ids: Vec<&'a str>,
    highest_pool_id: u32,
    flags: u32,
    highest_osd_num: u32,
    osd_states: Vec<u8>,
    osd_weights: Vec<u32>,

}

#[derive(Debug,Eq,PartialEq)]
pub struct OsdInfo{
    encoding_version: u8,
    //These are all epoch numbers I believe
    last_clean_being: u32,
    last_clean_end: u32,
    up_from: u32,
    up_through: u32,
    down_at: u32,
    lost_at: u32,
}

impl<'a> CephPrimitive<'a> for OsdInfo{
    fn read_from_wire(input: &'a [u8]) -> nom::IResult<&[u8], Self>{
        chain!(input,
            encoding_version: le_u8 ~
            last_clean_being: le_u32 ~
            last_clean_end: le_u32 ~
            up_from: le_u32 ~
            up_through: le_u32 ~
            down_at: le_u32 ~
            lost_at: le_u32, ||{
                OsdInfo{
                    encoding_version: encoding_version,
                    last_clean_being: last_clean_being,
                    last_clean_end: last_clean_end,
                    up_from: up_from,
                    up_through: up_through,
                    down_at: down_at,
                    lost_at: lost_at
                }
            }
        )
    }

	fn write_to_wire(&self) -> Result<Vec<u8>, SerialError>{
        let mut buffer:Vec<u8> = Vec::new();

        try!(buffer.write_u8(self.encoding_version));
        try!(buffer.write_u32::<LittleEndian>(self.last_clean_being));
        try!(buffer.write_u32::<LittleEndian>(self.last_clean_end));
        try!(buffer.write_u32::<LittleEndian>(self.up_from));
        try!(buffer.write_u32::<LittleEndian>(self.up_through));
        try!(buffer.write_u32::<LittleEndian>(self.down_at));
        try!(buffer.write_u32::<LittleEndian>(self.lost_at));

        return Ok(buffer);
    }
}

#[derive(Debug,Eq,PartialEq)]
pub struct CephOsdMap{
    epoch: u32,

    osd_info: Vec<OsdInfo>,
}

#[derive(Debug,Eq,PartialEq)]
pub struct OsdMap{
    fsid: Uuid,
    incremental_map_count: u32,
    map_count: u32,

    oldest_map: u32,
    newest_map:u32,
}

#[test]
fn test_monmap(){
    let bytes = vec![
        //unknown bytes
        /*0x11, 0x02, 0x00, 0x00, */0x03, 0x03, 0x0b, 0x02, 0x00, 0x00, 0xec, 0xbb, 0x89, 0x60, 0x0e, 0x21,
        0x11, 0xe2, 0xb4, 0x95, 0x83, 0xa8, 0x8f, 0x44, 0xdb, 0x01, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00,
        0x00, 0x00, 0x15, 0x00, 0x00, 0x00, 0x63, 0x68, 0x72, 0x69, 0x73, 0x2d, 0x6c, 0x6f, 0x63, 0x61,
        0x6c, 0x2d, 0x6d, 0x61, 0x63, 0x68, 0x69, 0x6e, 0x65, 0x2d, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x02, 0x1a, 0x85, 0x0a, 0x00, 0x03, 0xf4, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x00, 0x63, 0x68, 0x72, 0x69, 0x73, 0x2d, 0x6c, 0x6f, 0x63,
        0x61, 0x6c, 0x2d, 0x6d, 0x61, 0x63, 0x68, 0x69, 0x6e, 0x65, 0x2d, 0x35, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x1a, 0x85, 0x0a, 0x00, 0x03, 0x11, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x00, 0x63, 0x68, 0x72, 0x69, 0x73, 0x2d, 0x6c, 0x6f,
        0x63, 0x61, 0x6c, 0x2d, 0x6d, 0x61, 0x63, 0x68, 0x69, 0x6e, 0x65, 0x2d, 0x36, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x1a, 0x85, 0x0a, 0x00, 0x03, 0x55, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00
    ];
    let result = MonMap::read_from_wire(&bytes);
    println!("MonMap: {:?}", result);
}

#[derive(Debug,Eq,PartialEq)]
pub struct MonMap<'a>{
    encoding_version: u8,
    min_version: u8,
    fsid: Uuid,
    epoch: u32,
    monitors: Vec<Monitor<'a>>
}

impl<'a> CephPrimitive<'a> for MonMap<'a>{
    fn read_from_wire(input: &'a [u8]) -> nom::IResult<&[u8], Self>{
        chain!(input,
            encoding_version: le_u8 ~
            min_version: le_u8 ~
            num_of_monitors: le_u32 ~
            fsid: call!(parse_fsid) ~
            epoch: le_u32 ~
            num_of_monitors: le_u32 ~
            monitors: count!(Monitor::read_from_wire, (num_of_monitors/128) as usize), //128 == sockaddr_storage
            //monitors: count!(EntityAddr::read_from_wire, (num_of_monitors/128) as usize),
            ||{
                MonMap{
                    encoding_version: encoding_version,
                    min_version: min_version,
                    fsid: fsid,
                    epoch: epoch,
                    monitors: monitors,
                }
            }
        )
    }

	fn write_to_wire(&self) -> Result<Vec<u8>, SerialError>{
        let mut buffer:Vec<u8> = Vec::new();

        try!(buffer.write_u8(self.encoding_version));
        try!(buffer.write_u32::<LittleEndian>(self.epoch));

        return Ok(buffer);
    }
}

#[derive(Debug,Eq,PartialEq)]
pub struct ObjectId<'a>{
    pub size: u32,
    pub data:  &'a [u8]
}

impl<'a> CephPrimitive<'a> for ObjectId<'a> {
    fn read_from_wire(input: &'a [u8]) -> nom::IResult<&[u8], Self>{
        chain!(input,
            size: le_u32 ~
            data: take!(size),
            ||{
                ObjectId{
                    size: size,
                    data: data,
                }
            }
        )
    }

	fn write_to_wire(&self) -> Result<Vec<u8>, SerialError>{
        let mut buffer:Vec<u8> = Vec::new();
        try!(buffer.write_u32::<LittleEndian>(self.size));
        buffer.extend(self.data);

        return Ok(buffer);
    }

}

#[derive(Debug,Eq,PartialEq)]
pub struct Operation{
    pub operation: u16,
    pub flags: u32,
    pub offset: u64,
    pub size: u64,
    pub truncate_size: u64,
    pub truncate_seq: u32,
    pub payload_size: u32,
}

impl<'a> CephPrimitive<'a> for Operation {
    fn read_from_wire(input: &'a [u8]) -> nom::IResult<&[u8], Self>{
        chain!(input,
            operation: le_u16 ~
            flags: le_u32 ~
            offset: le_u64 ~
            size: le_u64 ~
            truncate_size: le_u64 ~
            truncate_seq: le_u32 ~
            payload_size: le_u32, ||{
                Operation{
                    operation: operation,
                    flags: flags,
                    offset: offset,
                    size: size,
                    truncate_size: truncate_size,
                    truncate_seq: truncate_seq,
                    payload_size: payload_size,
                }
            }
        )
    }

	fn write_to_wire(&self) -> Result<Vec<u8>, SerialError>{
        let mut buffer:Vec<u8> = Vec::new();
        try!(buffer.write_u16::<LittleEndian>(self.operation));
        try!(buffer.write_u32::<LittleEndian>(self.flags));
        try!(buffer.write_u64::<LittleEndian>(self.offset));
        try!(buffer.write_u64::<LittleEndian>(self.size));
        try!(buffer.write_u64::<LittleEndian>(self.truncate_size));
        try!(buffer.write_u32::<LittleEndian>(self.truncate_seq));
        try!(buffer.write_u32::<LittleEndian>(self.payload_size));

        return Ok(buffer);
    }
}

#[derive(Debug,Eq,PartialEq)]
pub struct ReplayVersion {
    version: u64,
    epoch: u32,
}

impl<'a> CephPrimitive<'a> for ReplayVersion {
    fn read_from_wire(input: &'a [u8]) -> nom::IResult<&[u8], Self>{
        chain!(input,
            version: le_u64 ~
            epoch: le_u32,
            || {
                ReplayVersion{
                    version: version,
                    epoch: epoch,
                }
            })
    }
	fn write_to_wire(&self) -> Result<Vec<u8>, SerialError>{
        let mut buffer:Vec<u8> = Vec::new();

        try!(buffer.write_u64::<LittleEndian>(self.version));
        try!(buffer.write_u32::<LittleEndian>(self.epoch));
        return Ok(buffer);
    }
}

#[derive(Debug,Eq,PartialEq)]
pub struct CephOsdOperationReply<'a>{
    pub object_id: ObjectId<'a>,
    pub placement_group: PlacementGroup,
    pub flags: OsdOp,
    pub result: u32,
    pub bad_replay_version: ReplayVersion,
    pub osd_map_epoch: u32,
    pub operation_count: u32,
    pub operation: Operation,
    pub retry_attempt: u32,
    pub operation_return_value: u32,
    pub replay_version: ReplayVersion,
    pub user_version: u64,
}

impl<'a> CephPrimitive<'a> for CephOsdOperationReply<'a>{
    fn read_from_wire(input: &'a [u8]) -> nom::IResult<&[u8], Self>{
        chain!(input,
            object_id: call!(ObjectId::read_from_wire) ~
            placement_group: call!(PlacementGroup::read_from_wire) ~
            flags_bits: le_u32 ~
            flags: expr_opt!(OsdOp::from_bits(flags_bits)) ~
            result: le_u32 ~
            bad_replay_version: call!(ReplayVersion::read_from_wire) ~
            osd_map_epoch: le_u32 ~
            operation_count: le_u32 ~
            operation: call!(Operation::read_from_wire) ~
            retry_attempt: le_u32 ~
            operation_return_value: le_u32 ~
            replay_version: call!(ReplayVersion::read_from_wire) ~
            user_version: le_u64,
        ||{
            CephOsdOperationReply{
                object_id: object_id,
                placement_group: placement_group,
                flags: flags,
                result: result,
                bad_replay_version: bad_replay_version,
                osd_map_epoch: osd_map_epoch,
                operation_count: operation_count,
                operation: operation,
                retry_attempt: retry_attempt,
                operation_return_value: operation_return_value,
                replay_version: replay_version,
                user_version: user_version,
            }
        })
    }

	fn write_to_wire(&self) -> Result<Vec<u8>, SerialError>{
        let mut buffer:Vec<u8> = Vec::new();

        buffer.extend(try!(self.object_id.write_to_wire()));
        buffer.extend(try!(self.placement_group.write_to_wire()));
        try!(buffer.write_u32::<LittleEndian>(self.flags.bits));
        buffer.extend(try!(self.bad_replay_version.write_to_wire()));
        try!(buffer.write_u32::<LittleEndian>(self.osd_map_epoch));
        try!(buffer.write_u32::<LittleEndian>(self.operation_count));
        buffer.extend(try!(self.operation.write_to_wire()));
        try!(buffer.write_u32::<LittleEndian>(self.retry_attempt));
        try!(buffer.write_u32::<LittleEndian>(self.operation_return_value));
        buffer.extend(try!(self.replay_version.write_to_wire()));
        try!(buffer.write_u64::<LittleEndian>(self.user_version));

        return Ok(buffer);
    }
}

#[derive(Debug,Eq,PartialEq)]
pub struct CephOsdOperation<'a>{
    pub client: u32,
    pub map_epoch: u32,
    pub flags: OsdOp,
    pub modification_time: Utime,
    pub reassert_version: u64,
    pub reassert_epoch: u32,
    pub locator: ObjectLocator<'a>,
    pub placement_group: PlacementGroup,
    pub object_id: ObjectId<'a>,
    pub operation_count: u16,
    pub operation: Operation, //TODO: Change to Vec<Operation>,
    pub snapshot_id: u64,
    pub snapshot_seq: u64,
    pub snapshot_count: u32,
    pub retry_attempt: u32,
    pub payload: Vec<u8>,
}

impl<'a> CephPrimitive<'a> for CephOsdOperation<'a>{
    fn read_from_wire(input: &'a [u8]) -> nom::IResult<&[u8], Self>{
        chain!(input,
            client: le_u32 ~
            map_epoch: le_u32 ~
            flags_bits: le_u32 ~
            flags: expr_opt!(OsdOp::from_bits(flags_bits)) ~
            modification_time: call!(Utime::read_from_wire) ~
            reassert_version: le_u64 ~
            reassert_epoch: le_u32 ~
            locator: call!(ObjectLocator::read_from_wire) ~
            placement_group: call!(PlacementGroup::read_from_wire) ~
            object_id: call!(ObjectId::read_from_wire) ~
            operation_count: le_u16 ~
            operation: call!(Operation::read_from_wire) ~
            snapshot_id: le_u64 ~
            snapshot_seq: le_u64 ~
            snapshot_count: le_u32 ~
            retry_attempt: le_u32,
            //payload: call!(vec![]),
            ||{
                CephOsdOperation{
                    client: client,
                    map_epoch: map_epoch,
                    flags: flags,
                    modification_time: modification_time,
                    reassert_version: reassert_version,
                    reassert_epoch: reassert_epoch,
                    locator: locator,
                    placement_group: placement_group,
                    object_id: object_id,
                    operation_count: operation_count,
                    operation: operation,
                    snapshot_id: snapshot_id,
                    snapshot_seq: snapshot_seq,
                    snapshot_count: snapshot_count,
                    retry_attempt: retry_attempt,
                    payload: vec![],
                }
            }
        )
    }

	fn write_to_wire(&self) -> Result<Vec<u8>, SerialError>{
        let mut buffer:Vec<u8> = Vec::new();

        try!(buffer.write_u32::<LittleEndian>(self.client));
        try!(buffer.write_u32::<LittleEndian>(self.map_epoch));
        try!(buffer.write_u32::<LittleEndian>(self.flags.bits));
        buffer.extend(try!(self.modification_time.write_to_wire()));
        try!(buffer.write_u64::<LittleEndian>(self.reassert_version));
        try!(buffer.write_u32::<LittleEndian>(self.reassert_epoch));
        buffer.extend(try!(self.locator.write_to_wire()));
        buffer.extend(try!(self.placement_group.write_to_wire()));
        buffer.extend(try!(self.object_id.write_to_wire()));
        try!(buffer.write_u16::<LittleEndian>(self.operation_count));
        buffer.extend(try!(self.operation.write_to_wire()));
        try!(buffer.write_u64::<LittleEndian>(self.snapshot_id));
        try!(buffer.write_u64::<LittleEndian>(self.snapshot_seq));
        try!(buffer.write_u32::<LittleEndian>(self.snapshot_count));
        try!(buffer.write_u32::<LittleEndian>(self.retry_attempt));

        for b in &self.payload{
            buffer.push(b.clone());
        }

        return Ok(buffer);
    }
}

//OSD <-> OSD operations
/*
#[derive(Debug)]
pub struct CephOsdSubOperation {
    pub map_epoch: u32,

    pub locator: ObjectLocator,
    pub acknowledgements_wanted: u8,

    pub operation: Operation, //TODO: Change to Vec<Operation>,
    pub modification_time: Utime,
    pub old_exists: bool,
    pub old_size: u64,
}
*/
pub struct AuthReplyMessage{
    protocol: CephAuthProtocol,
    result: i32,
    global_id: u64,
    //Wireshark gives some stupid message about decoding this section.
    //Need to do it manually
}

/*
Auth consists of a  PaxosMessage + AuthMessage
 */

#[derive(Debug,Eq,PartialEq)]
pub struct AuthMessage<'a>{
    paxos_msg: PaxosMessage,
    protocol: CephAuthProtocol,
    encoding_version: u8,
    supported_protocols: Vec<CephAuthProtocol>,
    entity_name: CephEntityName<'a>,
    global_id: u64,
    map_epoch: u32,
}

impl<'a> CephPrimitive<'a> for AuthMessage<'a>{
    fn read_from_wire(input: &'a [u8]) -> nom::IResult<&[u8], Self>{
        chain!(input,
            paxos_msg: call!(PaxosMessage::read_from_wire) ~
            authorizer_bits: le_u32 ~
            authorizer_protocol: expr_opt!(CephAuthProtocol::from_u32(authorizer_bits)) ~
            skip_1: le_u32 ~
            encoding_version: le_u8 ~
            protocol_fields: le_u32 ~
            supported_protocols: count!(parse_protocol, protocol_fields as usize) ~
            entity_name: call!(CephEntityName::read_from_wire) ~
            global_id: le_u64 ~
            map_epoch: le_u32,
            ||{
                AuthMessage{
                    paxos_msg: paxos_msg,
                    protocol: authorizer_protocol,
                    supported_protocols: supported_protocols,
                    entity_name: entity_name,
                    global_id: global_id,
                    encoding_version: encoding_version,
                    map_epoch: map_epoch,
                }
            }
        )
    }

	fn write_to_wire(&self) -> Result<Vec<u8>, SerialError>{
        let mut buffer: Vec<u8> = Vec::new();
        buffer.extend(try!(self.paxos_msg.write_to_wire()));

        try!(buffer.write_u32::<LittleEndian>(self.protocol.clone() as u32));

        //Unknown fields
        try!(buffer.write_u32::<LittleEndian>(0));
        //Unknown fields
        try!(buffer.write_u8(self.encoding_version));

        //Write out the supported protocols
        try!(buffer.write_u32::<LittleEndian>(self.supported_protocols.len() as u32));
        for protocol in &self.supported_protocols{
            try!(buffer.write_u32::<LittleEndian>(protocol.clone() as u32));
        }

        buffer.extend(try!(self.entity_name.write_to_wire()));
        try!(buffer.write_u64::<LittleEndian>(self.global_id));
        try!(buffer.write_u32::<LittleEndian>(self.map_epoch));

        return Ok(buffer);
    }
}

#[derive(Debug,Eq,PartialEq)]
pub struct PaxosMessage {
    pub version: u64,
    pub mon: i16,
    pub mon_tid: u64,
}

impl<'a> CephPrimitive<'a> for PaxosMessage{
    fn read_from_wire(input: &'a [u8]) -> nom::IResult<&[u8], Self>{
        chain!(input,
            version: le_u64 ~
            mon: le_i16 ~
            mon_tid: le_u64,
            ||{
                PaxosMessage{
                    version: version,
                    mon: mon,
                    mon_tid: mon_tid,
                }
            })
    }
	fn write_to_wire(&self) -> Result<Vec<u8>, SerialError>{
        let mut buffer: Vec<u8> = Vec::new();
        try!(buffer.write_u64::<LittleEndian>(self.version));
        try!(buffer.write_i16::<LittleEndian>(self.mon));
        try!(buffer.write_u64::<LittleEndian>(self.mon_tid));

        return Ok(buffer);
    }
}

#[derive(Debug,Eq,PartialEq)]
pub struct MonCommand<'a> {
    pub paxos: PaxosMessage,
    pub fsid: Uuid,
    pub arguments: Vec<&'a str> //Size: u32, utf8 data
}

impl<'a> CephPrimitive<'a> for MonCommand<'a>{
    fn read_from_wire(input: &'a [u8]) -> nom::IResult<&[u8], Self>{
        chain!(input,
            paxos: call!(PaxosMessage::read_from_wire) ~
            fsid: call!(parse_fsid) ~
            num_of_str: le_u32 ~
            arguments: count!(parse_str, num_of_str as usize),
            ||{
                MonCommand{
                    paxos: paxos,
                    fsid: fsid,
                    arguments: arguments,
                }
            }
        )
    }

	fn write_to_wire(&self) -> Result<Vec<u8>, SerialError>{
        let mut buffer: Vec<u8> = Vec::new();
        buffer.extend(try!(self.paxos.write_to_wire()));
        buffer.extend(self.fsid.as_bytes());

        try!(buffer.write_u32::<LittleEndian>(self.arguments.len() as u32));

        for arg in &self.arguments{
            //let arg_copy = arg.clone();
            //TODO: Can't use my write_string fn here.  buffer doesn't live long enough
            try!(buffer.write_u32::<LittleEndian>(arg.len() as u32));
            //buffer.extend(arg_copy.into_bytes());
            buffer.extend(arg.as_bytes());
        }

        return Ok(buffer);
    }
}

#[derive(Debug,Eq,PartialEq)]
pub struct CephSourceName{
    pub entity_type: CephEntity,
    pub num: u64,
}

impl<'a> CephPrimitive<'a> for CephSourceName{
    fn read_from_wire(input: &'a [u8]) -> nom::IResult<&[u8], Self>{
        chain!(input,
            entity_type_bits: le_u8 ~
            entity_type: expr_opt!(CephEntity::from_u8(entity_type_bits)) ~
            num: le_u64,
            || {
                CephSourceName{
                    entity_type: entity_type,
                    num: num,
                }
            }
        )
    }

	fn write_to_wire(&self) -> Result<Vec<u8>, SerialError>{
        let mut buffer: Vec<u8> = Vec::new();

        try!(buffer.write_u8(self.entity_type.clone() as u8));
        try!(buffer.write_u64::<LittleEndian>(self.num));

        return Ok(buffer);
    }
}

#[derive(Debug,Eq,PartialEq)]
pub struct CephEntityName<'a>{
    pub entity_type: CephEntity,
    pub id: &'a str,
}

impl<'a> CephPrimitive<'a> for CephEntityName<'a>{
    fn read_from_wire(input: &'a [u8]) -> nom::IResult<&[u8], Self>{
        chain!(input,
            entity_type_bits: le_u8 ~
            entity_type: expr_opt!(CephEntity::from_u8(entity_type_bits)) ~
            id: parse_str,
            ||{
                CephEntityName{
                    entity_type: entity_type,
                    id: id
                }
            }
        )
    }

	fn write_to_wire(&self) -> Result<Vec<u8>, SerialError>{
        let mut buffer: Vec<u8> = Vec::new();
        try!(buffer.write_u8(self.entity_type.clone() as u8));
        buffer.extend(self.id.as_bytes());
        return Ok(buffer);
    }
}

#[derive(Debug,Eq,PartialEq)]
pub struct Utime {
    pub tv_sec: u32,  // Seconds since epoch.
    pub tv_nsec: u32, // Nanoseconds since the last second.
}

impl Utime{
    pub fn new()->Self{
        let now: time::Timespec = time::now().to_timespec();
        return Utime {
            tv_sec: now.sec as u32,
            tv_nsec: now.nsec as u32,
        };
    }
}

impl<'a> CephPrimitive<'a> for Utime{
    fn read_from_wire(input: &'a [u8]) -> nom::IResult<&[u8], Self>{
        chain!(input,
            tv_sec: le_u32 ~
            tv_nsec: le_u32,
            ||{
                Utime {
                    tv_sec: tv_sec,
                    tv_nsec: tv_nsec,
                }
            })
    }

	fn write_to_wire(&self) -> Result<Vec<u8>, SerialError>{
        let mut buffer: Vec<u8> = Vec::new();

        try!(buffer.write_u32::<LittleEndian>(self.tv_sec));
        try!(buffer.write_u32::<LittleEndian>(self.tv_nsec));

        return Ok(buffer);
    }
}

// From src/include/msgr.h
#[derive(Debug,Eq,PartialEq)]
pub struct CephMsgHeader {
    pub sequence_num: u64,
    pub transaction_id: u64,
    pub msg_type: CephMsgType, //u16,  //CEPH_MSG_* or MSG_*
    pub priority: CephPriority,
    pub version: u16,   //version of message encoding
    pub front_len: u32, // The size of the front section
    pub middle_len: u32,// The size of the middle section
    pub data_len: u32,  // The size of the data section
    pub data_off: u16,  // The way data should be aligned by the reciever
    pub entity_name: CephSourceName, // Information about the sender
    pub compat_version: u16, // Oldest compatible encoding version
    pub reserved: u16, // Unused
    pub crc: u32,  // CRC of header
}

impl<'a> CephPrimitive<'a> for CephMsgHeader{
    fn read_from_wire(input: &'a [u8]) -> nom::IResult<&[u8], Self>{
        chain!(input,
            sequence_num: le_u64 ~
            transaction_id: le_u64 ~
            msg_type_bits: le_u16 ~
            msg_type: expr_opt!(CephMsgType::from_u16(msg_type_bits)) ~
            priority_bits: le_u16 ~
            priority: expr_opt!(CephPriority::from_u16(priority_bits)) ~
            version: le_u16 ~
            front_len: le_u32 ~
            middle_len: le_u32 ~
            data_len: le_u32 ~
            data_off: le_u16 ~
            entity_name: call!(CephSourceName::read_from_wire) ~
            compat_version: le_u16 ~
            reserved: le_u16 ~
            crc: le_u32,
            ||{
                CephMsgHeader{
                    sequence_num: sequence_num,
                    transaction_id: transaction_id,
                    msg_type: msg_type,
                    priority: priority,
                    version: version,
                    front_len: front_len,
                    middle_len: middle_len,
                    data_len: data_len,
                    data_off: data_off,
                    entity_name: entity_name,
                    compat_version: compat_version,
                    reserved: reserved,
                    crc: crc,
                }
            }
        )
    }

	fn write_to_wire(&self) -> Result<Vec<u8>, SerialError>{
        // let mut digest = crc32::Digest::new(crc32::CASTAGNOLI);

        let mut buffer:Vec<u8> = Vec::new();
        try!(buffer.write_u64::<LittleEndian>(self.sequence_num));
        try!(buffer.write_u64::<LittleEndian>(self.transaction_id));
        try!(buffer.write_u16::<LittleEndian>(self.msg_type.clone() as u16));
        try!(buffer.write_u16::<LittleEndian>(self.priority.clone() as u16));
        try!(buffer.write_u16::<LittleEndian>(self.version));
        try!(buffer.write_u32::<LittleEndian>(self.front_len));
        try!(buffer.write_u32::<LittleEndian>(self.middle_len));
        try!(buffer.write_u32::<LittleEndian>(self.data_len));
        try!(buffer.write_u16::<LittleEndian>(self.data_off));

        buffer.extend(try!(self.entity_name.write_to_wire()));

        try!(buffer.write_u16::<LittleEndian>(self.compat_version));
        try!(buffer.write_u16::<LittleEndian>(self.reserved));
        try!(buffer.write_u32::<LittleEndian>(self.crc));

        return Ok(buffer);
    }
}

#[derive(Debug,Eq,PartialEq)]
pub struct CephMsgFooter {
    pub front_crc: u32,
    pub middle_crc: u32,
    pub data_crc: u32,
    pub crypto_sig: u64,
    pub flags: u8
}

impl<'a> CephPrimitive<'a> for CephMsgFooter{
    fn read_from_wire(input: &'a [u8]) -> nom::IResult<&[u8], Self>{
        chain!(input,
            front_crc: le_u32 ~
            middle_crc: le_u32 ~
            data_crc: le_u32 ~
            crypto_sig: le_u64 ~
            flags: le_u8,
            ||{
                CephMsgFooter{
                    front_crc: front_crc,
                    middle_crc: middle_crc,
                    data_crc: data_crc,
                    crypto_sig: crypto_sig,
                    flags: flags
                }
            }
        )
    }
	fn write_to_wire(&self) -> Result<Vec<u8>, SerialError>{
        let mut buffer: Vec<u8> = Vec::new();

        try!(buffer.write_u32::<LittleEndian>(self.front_crc));
        try!(buffer.write_u32::<LittleEndian>(self.middle_crc));
        try!(buffer.write_u32::<LittleEndian>(self.data_crc));
        try!(buffer.write_u64::<LittleEndian>(self.crypto_sig));
        try!(buffer.write_u8(self.flags));

        return Ok(buffer);
    }
}

#[derive(Debug,Eq,PartialEq)]
pub struct CephAuthOperation<'a> {
    protocol: CephAuthProtocol,
    auth_data: &'a [u8],
    monmap_epoch: u32, // map epoch  (32bits -> 13 epochs/second for 10 years)
}

impl<'a> CephPrimitive<'a> for CephAuthOperation<'a>{
    fn read_from_wire(input: &'a [u8]) -> nom::IResult<&[u8], Self>{
        chain!(input,
            protocol_bits: le_u32 ~
            protocol: expr_opt!(CephAuthProtocol::from_u32(protocol_bits)) ~
            auth_data_len: le_u32 ~
            auth_data: take!(auth_data_len) ~
            monmap_epoch: le_u32,
            ||{
                CephAuthOperation{
                    protocol: protocol,
                    auth_data: auth_data,
                    monmap_epoch: monmap_epoch,
                }
            }
        )
    }
    fn write_to_wire(&self) -> Result<Vec<u8>, SerialError>{
        let buffer: Vec<u8> = Vec::new();

        return Ok(buffer);
    }
}

#[test]
fn test_auth_reply(){
    let bytes = vec![
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2e, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x09, 0x00, 0x00, 0x00,
        //TODO: This part fails
        0x01, 0xfb, 0x82, 0x78, 0xa0, 0x16, 0xcb, 0x40, 0x5e, 0x00, 0x00, 0x00,
        0x00
    ];
    let x: &[u8] = &[];
    /*let expected_result = CephAuthOperationReply {
        protocol: CephAuthProtocol::CephX,
        result: 0,
        global_id: 0x000000000000112e,
    };*/
    //TODO: Fails to parse string from Cephx
    //let result = CephAuthOperationReply::read_from_wire(&bytes);
    //println!("CephAuthOperationReply parse result: {:?}", result);
    //assert_eq!(Done(x, expected_result), result);
}

#[derive(Debug,Eq,PartialEq)]
pub struct CephAuthOperationReply<'a> {
    protocol: CephAuthProtocol,
    result: i32,
    global_id: u64,
    result_msg: &'a str,
    result_buffer: &'a [u8],
}

impl<'a> CephPrimitive<'a> for CephAuthOperationReply<'a>{
    fn read_from_wire(input: &'a [u8]) -> nom::IResult<&[u8], Self>{
        chain!(input,
            protocol_bits: le_u32 ~
            protocol: expr_opt!(CephAuthProtocol::from_u32(protocol_bits)) ~
            result: le_i32 ~
            global_id: le_u64 ~
            result_msg: parse_str ~
            result_buffer_len: le_u32 ~
            result_buffer: take!(result_buffer_len),
            ||{
                CephAuthOperationReply{
                    protocol: protocol,
                    result: result,
                    global_id: global_id,
                    result_msg: result_msg,
                    result_buffer: result_buffer,
                }
            }
        )
    }
    fn write_to_wire(&self) -> Result<Vec<u8>, SerialError>{
        let mut buffer: Vec<u8> = Vec::new();

        return Ok(buffer);
    }
}

#[test]
fn test_msg_ack(){
    let bytes = vec![
        0x08, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ];
    let x: &[u8] = &[];
    let expected_result = CephMsgTagAck {
        tag: CephMsg::Ack,
        seq: 1,
    };
    let result = CephMsgTagAck::read_from_wire(&bytes);
    println!("CephMsgTagAck parse result: {:?}", result);
    assert_eq!(Done(x, expected_result), result);
}

#[derive(Debug,Eq,PartialEq)]
struct CephMsgTagAck{
    tag: CephMsg, //0x08
    seq: u64 //Sequence number of msg being acknowledged
}

impl CephMsgTagAck{
    fn new(sequence_number: u64) -> CephMsgTagAck{
        return CephMsgTagAck{
            tag: CephMsg::Ack,
            seq: sequence_number,
        };
    }
}

impl<'a> CephPrimitive<'a> for CephMsgTagAck{
    fn read_from_wire(input: &'a [u8]) -> nom::IResult<&[u8], Self>{
        chain!(input,
            tag_bits: le_u8 ~
            msg: expr_opt!(CephMsg::from_u8(tag_bits)) ~
            seq: le_u64,
            ||{
                CephMsgTagAck{
                    tag: msg,
                    seq: seq,
                }
            }
        )
    }
	fn write_to_wire(&self) -> Result<Vec<u8>, SerialError>{
        let mut buffer: Vec<u8> = Vec::new();

        try!(buffer.write_u8(self.tag.clone() as u8));
        try!(buffer.write_u64::<LittleEndian>(self.seq));
        return Ok(buffer);
    }
}

#[derive(Debug)]
struct CephMsgKeepAlive{
    tag: CephMsg, //0x09
    data: u8, // No data
}

impl CephMsgKeepAlive{
    fn new() -> CephMsgKeepAlive{
        return CephMsgKeepAlive{
            tag: CephMsg::KeepAlive,
            data: 0,
        }
    }
}

impl<'a> CephPrimitive<'a> for CephMsgKeepAlive{
    fn read_from_wire(input: &'a [u8]) -> nom::IResult<&[u8], Self>{
        chain!(input,
            tag_bits: le_u8 ~
            msg: expr_opt!(CephMsg::from_u8(tag_bits)) ~
            data: le_u8,
            ||{
                CephMsgKeepAlive{
                    tag: msg,
                    data: data,
                }
            }
        )
    }
	fn write_to_wire(&self) -> Result<Vec<u8>, SerialError>{
        let mut buffer: Vec<u8> = Vec::new();

        try!(buffer.write_u8(self.tag.clone() as u8));
        try!(buffer.write_u8(self.data));
        return Ok(buffer);
    }
}

#[test]
fn test_keep_alive2(){
    let bytes = vec![
        0x0e, 0x3d, 0x0c, 0x39, 0x56, 0xc8, 0xc1, 0x6e, 0x02
    ];
    let x: &[u8] = &[];
    let expected_result = CephMsgKeepAlive2 {
        tag: CephMsg::KeepAlive2,
        timestamp: Utime {
            tv_sec: 1446579261,
            tv_nsec: 40813000
        }
    };
    let result = CephMsgKeepAlive2::read_from_wire(&bytes);
    println!("CephMsgKeepAlive2 parse result: {:?}", result);
    assert_eq!(Done(x, expected_result), result);
}

#[derive(Debug,Eq,PartialEq)]
struct CephMsgKeepAlive2{
    tag: CephMsg, //0x0E
    timestamp: Utime,
}

impl CephMsgKeepAlive2{
    fn new() -> CephMsgKeepAlive2{
        let now: time::Timespec = time::now().to_timespec();
        let timestamp = Utime{
            tv_sec: now.sec as u32,
            tv_nsec: now.nsec as u32,
        };
        return CephMsgKeepAlive2{
            tag: CephMsg::KeepAlive2,
            timestamp:timestamp,
        }
    }
}

impl<'a> CephPrimitive<'a> for CephMsgKeepAlive2{
    fn read_from_wire(input: &'a [u8]) -> nom::IResult<&[u8], Self>{
        chain!(input,
            tag_bits: le_u8 ~
            msg: expr_opt!(CephMsg::from_u8(tag_bits)) ~
            timestamp: call!(Utime::read_from_wire),
            ||{
                CephMsgKeepAlive2{
                    tag: msg,
                    timestamp: timestamp,
                }
            }
        )
    }
	fn write_to_wire(&self) -> Result<Vec<u8>, SerialError>{
        let mut buffer: Vec<u8> = Vec::new();

        try!(buffer.write_u8(self.tag.clone() as u8));
        try!(buffer.write_u32::<LittleEndian>(self.timestamp.tv_sec));
        try!(buffer.write_u32::<LittleEndian>(self.timestamp.tv_nsec));

        return Ok(buffer);
    }
}

#[test]
fn test_keep_alive2_ack(){
    let bytes = vec![
        0x0f, 0x3d, 0x0c, 0x39, 0x56, 0xc8, 0xc1, 0x6e, 0x02
    ];
    let x: &[u8] = &[];
    let expected_result = CephMsgKeepAlive2Ack {
        tag: CephMsg::KeepAlive2Ack,
        timestamp: Utime {
            tv_sec: 1446579261,
            tv_nsec: 40813000
        }
    };
    let result = CephMsgKeepAlive2Ack::read_from_wire(&bytes);
    println!("CephMsgKeepAlive2Ack parse result: {:?}", result);
    assert_eq!(Done(x, expected_result), result);
}

#[derive(Debug,Eq,PartialEq)]
struct CephMsgKeepAlive2Ack{
    tag: CephMsg, //0x0F
    timestamp: Utime,
}

impl CephMsgKeepAlive2Ack {
    fn new() -> CephMsgKeepAlive2Ack{
        let now: time::Timespec = time::now().to_timespec();
        let timestamp = Utime{
            tv_sec: now.sec as u32,
            tv_nsec: now.nsec as u32,
        };

        return CephMsgKeepAlive2Ack{
            tag: CephMsg::KeepAlive2Ack,
            timestamp: timestamp,
        };
    }
}

impl<'a> CephPrimitive<'a> for CephMsgKeepAlive2Ack{
    fn read_from_wire(input: &'a [u8]) -> nom::IResult<&[u8], Self>{
        chain!(input,
            tag_bits: le_u8 ~
            msg: expr_opt!(CephMsg::from_u8(tag_bits)) ~
            timestamp: call!(Utime::read_from_wire),
            ||{
                CephMsgKeepAlive2Ack{
                    tag: msg,
                    timestamp: timestamp,
                }
            }
        )
    }
	fn write_to_wire(&self) -> Result<Vec<u8>, SerialError>{
        let mut buffer: Vec<u8> = Vec::new();

        try!(buffer.write_u8(self.tag.clone() as u8));
        try!(buffer.write_u32::<LittleEndian>(self.timestamp.tv_sec));
        try!(buffer.write_u32::<LittleEndian>(self.timestamp.tv_nsec));

        return Ok(buffer);
    }
}

#[test]
fn test_entity_addr(){
    let bytes = vec![
        0x00, 0x00, 0x00, 0x00, 0x04, 0x81, 0x0f, 0x00, 0x00, 0x02, 0x00, 0x00, 0x0a, 0x00, 0x03, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ];
    let x: &[u8] = &[];
    let expected_result = EntityAddr{
        port: 0,
        nonce: 0x000f8104,
        addr: Some(Addr::v4addr(Ipv4Addr::new(10,0,3,1))),
    };
    let result = EntityAddr::read_from_wire(&bytes);
    println!("EntityAddr: {:?}", result);
    assert_eq!(Done(x, expected_result), result);
}

#[derive(Debug,Eq,PartialEq)]
pub enum Addr{
    v4addr(Ipv4Addr),
    v6addr(Ipv6Addr),
}

#[derive(Debug,Eq,PartialEq)]
pub struct EntityAddr{
    pub port: u16,
    pub nonce: u32,
    pub addr: Option<Addr>,
}

impl<'a> CephPrimitive<'a> for EntityAddr{
    fn read_from_wire(input: &'a [u8]) -> nom::IResult<&[u8], Self>{
        println!("EntityAddr");

        chain!(input,
            source_node_type: le_u32 ~
            nonce: le_u32 ~
            address_family: be_u16 ~
            port: be_u16 ~
            addr: alt!(
                call!(parse_ipv4) =>{|addr| return Some(Addr::v4addr(addr))} |
                call!(parse_ipv6) =>{|addr| return Some(Addr::v6addr(addr))}
            ),
            ||{
                EntityAddr{
                    port: port,
                    nonce: nonce,
                    addr: addr,
                }
            }
        )
    }
	fn write_to_wire(&self) -> Result<Vec<u8>, SerialError>{
        //socket_type
        let mut buffer:Vec<u8> = Vec::new();

        try!(buffer.write_u32::<LittleEndian>(0)); //Is this right?
        try!(buffer.write_u32::<LittleEndian>(self.nonce));
        if let Some(ref address) = self.addr{
            match address{
                &Addr::v4addr(ref v4address) => {
                    //Address Family
                    try!(buffer.write_u16::<BigEndian>(0x0002));
                    //Port
                    try!(buffer.write_u16::<BigEndian>(self.port));
                    for octet in v4address.octets().iter(){
                        try!(buffer.write_u8(*octet));
                    }
                    //Sockaddr_storage seems to be a 128 byte structure and
                    //the ceph client is sending 120 bytes of 0's or padding
                    for _ in 0..120{
                        try!(buffer.write_u8(0));
                    }
                },
                &Addr::v6addr(ref v6address) =>{
                    //Address Family
                    try!(buffer.write_u32::<LittleEndian>(0x000A));

                    //Port
                    try!(buffer.write_u16::<BigEndian>(self.port));

                    for octet in v6address.segments().iter(){
                        try!(buffer.write_u16::<BigEndian>(*octet));
                    }
                    //Sockaddr_storage seems to be a 128 byte structure and
                    //the ceph client is sending 108 bytes of 0's or padding
                    for _ in 0..108{
                        try!(buffer.write_u8(0));
                    }
                }
            }
        }
        return Ok(buffer);
    }
}

fn parse_strs<'a>(i: &'a [u8]) -> nom::IResult<&'a [u8], Vec<& str>>{
    chain!(i,
        num_of_str: le_u32 ~
        strs: count!(parse_str, num_of_str as usize),
        ||{
            strs
        }
    )
}

fn parse_protocol<'a>(i: &'a [u8]) -> nom::IResult<&'a [u8], CephAuthProtocol>{
    chain!(i,
        protocol_bits: le_u32 ~
        protocol: expr_opt!(CephAuthProtocol::from_u32(protocol_bits)),
        ||{
            protocol
        }
    )
}

#[test]
fn test_ipv4(){
    let bytes = vec![
        0x0a, 0x00, 0x03, 0x01
    ];
    let x: &[u8] = &[];
    let expected_result = Ipv4Addr::new(10,0,3,1);
    let result = parse_ipv4(&bytes);
    println!("Ipv4Addr parse result: {:?}", result);
    assert_eq!(Done(x, expected_result), result);
}

fn parse_ipv4<'a>(i: &'a [u8]) -> nom::IResult<&'a [u8], Ipv4Addr> {
    //tag!(0x0002) ~
    chain!(i,
        a: le_u8 ~
        b: le_u8 ~
        c: le_u8 ~
        d: le_u8 ~
        padding: take!(120),
        || {
            Ipv4Addr::new(a,b,c,d)
        }
    )
}

fn parse_ipv6<'a>(i: &'a [u8]) -> nom::IResult<&'a [u8], Ipv6Addr> {
    //tag!(0x000A) ~
    chain!(i,
        a: be_u16 ~
        b: be_u16 ~
        c: be_u16 ~
        d: be_u16 ~
        e: be_u16 ~
        f: be_u16 ~
        g: be_u16 ~
        h: be_u16 ~
        padding: take!(108),
        ||{
            Ipv6Addr::new(a,b,c,d,e,f,g,h)
        }
    )
}

fn parse_fsid<'a>(i: &'a [u8]) -> nom::IResult<&'a [u8], Uuid> {
    chain!(i,
        length: le_u32 ~
        s: take_str!(length) ~
        fsid: expr_res!(Uuid::parse_str(s)),
        ||{
            fsid
        }
    )
}

fn parse_str<'a>(i: &'a [u8]) -> nom::IResult<&'a [u8], &'a str> {
    chain!(i,
        length: le_u32 ~
        s: take_str!(length),
        ||{
            s
        }
    )
}

//Connect to Ceph Monitor and send a hello banner
fn send_banner(socket: &mut TcpStream)->Result<usize, SerialError>{
    let banner = String::from("ceph v027");
    let written_bytes = try!(socket.write(banner.as_bytes()));
    if written_bytes <= 0{
        return Err(SerialError::new("Unable to send banner".to_string()));
    }else{
        return Ok(written_bytes);
    }
}

fn send_msg(socket: &mut TcpStream, msg: Message)->Result<usize, SerialError>{
    let bytes_to_send = try!(write_message_to_wire(&msg));
    let written_bytes = try!(socket.write(&bytes_to_send[..]));
    if written_bytes <= 0{
        return Err(SerialError::new("Unable to send_msg".to_string()));
    }else{
        return Ok(written_bytes);
    }
}

//TODO: What should this do?
// fn recv_msg(socket: &mut TcpStream){

// }
