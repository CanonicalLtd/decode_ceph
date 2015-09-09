extern crate byteorder;
use crypto;

extern crate num;
use self::num::FromPrimitive;

use self::byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io;
use std::io::{ErrorKind};
use std::io::prelude::*;
use std::net::{Ipv4Addr,Ipv6Addr,TcpStream};
//There will be no padding between the elements and the elements will be sent in the order they appear
//const CEPH_BANNER: str = "ceph v027";
/*
CEPH_BANNER "ceph v027"
CEPH_BANNER_MAX_LEN 30

typedef u32le epoch_t;
typedef u32le ceph_seq_t;
typedef u64le ceph_tid_t;
typedef u64le version_t;
*/
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
        let banner = String::from("ceph v027");
        //Connect to monitor port
        let mut stream = TcpStream::connect("10.0.3.144:6789").unwrap();
        let mut buf: Vec<u8> = Vec::new();
        //recv banner
        (&mut stream).take(9).read_to_end(&mut buf).unwrap();
        println!("Banner received: {}", String::from_utf8(buf).unwrap()); //we're on a roll :D

        //send banner
        println!("Writing banner back to Ceph");
        let mut bytes_written = stream.write(&banner.into_bytes()).unwrap();
        println!("Wrote {} bytes back to Ceph", bytes_written);

        //Send sockaddr_storage
        let client_info = super::EntityAddr{
            port: 0,
            nonce: 0,
            v4addr: Some(Ipv4Addr::new(192,168,1,6)),
            v6addr: None,
        };

        //send sock_addr_storage
        let client_sock_addr_bytes = client_info.write_to_wire().unwrap();
        let mut bytes_written = stream.write(&client_sock_addr_bytes).unwrap();
        println!("Wrote {} sock_addr bytes back to Ceph", bytes_written);

        //Get server sockaddr_storage
        buf = Vec::new();
        (&mut stream).take(136).read_to_end(&mut buf).unwrap();
        let mut server_sockaddr_cursor = Cursor::new(&mut buf[..]);
        //println!("Decoding Ceph server sockaddr_storage bytes {:?}", server_sockaddr_cursor);
        let server_entity_addr = super::EntityAddr::read_from_wire(&mut server_sockaddr_cursor).unwrap();
        println!("Server entity_addr: {:?}", server_entity_addr);

        /*
         987     ceph_msg_connect connect;
         988     connect.features = policy.features_supported;
         989     connect.host_type = msgr->get_myinst().name.type();
         990     connect.global_seq = gseq;
         991     connect.connect_seq = cseq;
         992     connect.protocol_version = msgr->get_proto_version(peer_type, true);
         993     connect.authorizer_protocol = authorizer ? authorizer->protocol : 0;
         994     connect.authorizer_len = authorizer ? authorizer->bl.length() : 0;
         */
        let connect = super::CephMsgConnect{
            features: super::CEPH_ALL, //Wireshark is showing not all bits are set
            host_type: super::CephEntity::Client,
            global_seq: 1,
            connect_seq: 0,
            protocol_version: super::Protocol::MonProtocol,
            authorizer_protocol: super::CephAuthProtocol::CephAuthUnknown,
            authorizer_len: 0,
            flags: 0,
            authorizer: Vec::new(),
        };
        let connect_bytes = connect.write_to_wire().unwrap();
        println!("Writing CephMsgConnect to Ceph {:?}", &connect_bytes);
        bytes_written = stream.write(&connect_bytes).unwrap();
        println!("Wrote {} CephMsgConnect bytes", bytes_written);

        //Get the connection reply
        let mut reply_buffer = Vec::new();
        //(&mut stream).take(136).read_to_end(&mut reply_buffer).unwrap();
        (&mut stream).take(26).read_to_end(&mut reply_buffer).unwrap();
        println!("Reponse bytes: {:?}", &reply_buffer);

        //Decode it
        let mut ceph_msg_reply_cursor = Cursor::new(&mut reply_buffer[..]);
        let ceph_msg_reply = super::CephMsgConnectReply::read_from_wire(&mut ceph_msg_reply_cursor);
        println!("CephMsgConnectReply: {:?}", ceph_msg_reply);

        //I think I need to setup the authorizer stuff now and negotiate a cephx connection
        //let auth_client_ticket = crypto::AuthTicket::new(600.0);
        //let auth_ticket_bytes = auth_client_ticket.write_to_wire().unwrap();

        //bytes_written = stream.write(&auth_ticket_bytes).unwrap();
        //println!("Wrote {} auth ticket bytes", bytes_written);

        //recv this:
        //Decode header
        //Decode footer
        //front_crc
        //middle_crc
        //data_crc
        //flags
        /*
        let mut ceph_response_bytes = vec![
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x1a,0x85,0x0a,0x00,0x03,0xd8,0x00, //17
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, //34
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, //51
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, //68
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, //85
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, //102
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x88,0x50,0x0a,0x00,0x03,0x90,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
        ];
        let mut cursor = Cursor::new(&mut ceph_response_bytes[..]);
        super::decode_entity_addr(&mut cursor);
        let connect_msg = super::CephMsgConnect::read_from_wire(&mut cursor);
        println!("Connect msg: {:?}", connect_msg);
        println!("Cursor position: {}", cursor.position());
        let msg_header = super::CephMsgHeader::read_from_wire(&mut cursor);
        println!("Msg header: {:?}", msg_header);
        println!("Cursor position: {}", cursor.position());
        */
    }
    #[test]
    fn test_connect_reply(){

    }

}

#[derive(Debug)]
pub enum SerialError {
	IoError(io::Error),
    ByteOrder(byteorder::Error),
	InvalidValue,
	InvalidType,
}

impl SerialError{
    fn new(err: String) -> SerialError {
        SerialError::IoError(
            io::Error::new(ErrorKind::Other, err)
        )
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

pub trait CephPrimitive {
	fn read_from_wire<R: Read>(cursor: &mut R) -> Result<Self, SerialError>;
	fn write_to_wire(&self) -> Result<Vec<u8>, SerialError>;
}

#[derive(Debug)]
struct CephMsgConnect{
    features: CephFeatures, //Composed of CephFeature bitflags
    host_type: CephEntity, //u32
    global_seq: u32,
    connect_seq: u32,
    protocol_version: Protocol,
    authorizer_protocol: CephAuthProtocol,
    authorizer_len: u32,
    flags: u8,
    authorizer: Vec<u8>,
}

impl CephPrimitive for CephMsgConnect{
	fn read_from_wire<R: Read>(cursor: &mut R) -> Result<Self, SerialError>{
        let feature_bits = try!(cursor.read_u64::<LittleEndian>());
        println!("Feature_bits: {:x}", feature_bits);
        let host_type = try!(cursor.read_u32::<LittleEndian>());
        let global_seq = try!(cursor.read_u32::<LittleEndian>());
        let connect_seq = try!(cursor.read_u32::<LittleEndian>());
        let protocol_version = try!(cursor.read_u32::<LittleEndian>());
        let authorizer_protocol = try!(cursor.read_u32::<LittleEndian>());
        let authorizer_len = try!(cursor.read_u32::<LittleEndian>());
        let flags = try!(cursor.read_u8());

        return Ok(CephMsgConnect{
            features: CephFeatures::from_bits(feature_bits).unwrap(),
            host_type: CephEntity::from_u32(host_type).unwrap(),
            global_seq: global_seq,
            connect_seq: connect_seq,
            protocol_version: Protocol::from_u32(protocol_version).unwrap(),
            authorizer_protocol: CephAuthProtocol::from_u32(authorizer_protocol).unwrap(),
            authorizer_len: authorizer_len,
            flags: flags,
            authorizer: Vec::new()
        })
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

#[derive(Debug)]
struct CephMsgConnectReply{
    tag: CephMsg,
    features: CephFeatures,
    global_seq: u32,
    connect_seq: u32,
    protocol_version: Protocol,
    authorizer_len: u32,
    flags: u8,
    authorizer: Vec<u8>,
}

impl CephPrimitive for CephMsgConnectReply{
	fn read_from_wire<R: Read>(cursor: &mut R) -> Result<Self, SerialError>{
        let tag = try!(cursor.read_u8());
        println!("CephConnectMsgReply tag: {}", tag);

        let feature_bits = try!(cursor.read_u64::<LittleEndian>());
        println!("Feature_bits: {:x}", feature_bits);

        let global_seq = try!(cursor.read_u32::<LittleEndian>());
        let connect_seq = try!(cursor.read_u32::<LittleEndian>());
        let protocol_version = try!(cursor.read_u32::<LittleEndian>());
        println!("Protocol version: {:x}", protocol_version);

        let authorizer_len = try!(cursor.read_u32::<LittleEndian>());
        let flags = try!(cursor.read_u8());
        let authorizer = Vec::new();

        return Ok(CephMsgConnectReply{
            tag: CephMsg::from_u8(tag).unwrap(),
            features: CephFeatures::from_bits(feature_bits).unwrap(),
            global_seq: global_seq,
            connect_seq: connect_seq,
            protocol_version: Protocol::from_u32(protocol_version).unwrap(),
            authorizer_len: authorizer_len,
            flags: flags,
            authorizer: authorizer
        });

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
struct CephMsgrMsg {
    tag: CephMsg,//    u8 tag = 0x07;
    header: CephMsgHeader,
    footer: CephMsgFooter,
}

enum_from_primitive!{
#[repr(u32)]
#[derive(Debug, Clone)]
pub enum CephEntity{
    Mon=1,
    Mds=2,
    Osd=4,
    Client=8,
    Auth=20, //Used to setup a new CephX connection
    Any=255
}
}

#[derive(Debug, Clone)]
enum Crypto {
    None = 0,
    Aes = 1,
}

enum_from_primitive!{
#[repr(u32)]
#[derive(Debug, Clone)]
enum Protocol{
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
            | CEPH_FEATURE_OSDMAP_ENC.bits

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
#[derive(Debug, Clone)]
enum CephAuthProtocol{
    CephAuthUnknown = 0,
    CephAuthNone = 1,
    CephAuthCephx = 2,
}
}


enum_from_primitive!{
#[derive(Debug, Clone)]
enum CephPriority{
    Low = 64,
    Default = 127,
    High = 196,
    Highest = 255,
}
}

enum_from_primitive! {
#[derive(Debug, Clone)]
enum CephMsg{
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
}
}

enum_from_primitive! {
enum CephMsgType{
    // monitor internal
    MsgMonScrub = 64,
    MsgMonElection = 65,
    MsgMonPaxos = 66,
    MsgMonProbe= 67,
    MsgMonJoin = 68,
    MsgMonSync = 69,
    /* monitor <-> mon admin tool */
    MsgMonCommand = 50,
    MsgMonCommandAck = 51,
    MsgLog = 52,
    MsgLogack = 53,
    //MsgMonObserve = 54,
    //MsgMonObserveNotify = 55,
    MsgClass = 56,
    MsgClassAck = 57,
    MsgGetpoolstats  = 58,
    MsgGetpoolstatsreply = 59,
    MsgMonGlobalId = 60,
    MsgRoute = 47,
    MsgForward = 46,
    MsgPaxos = 40,
    MsgOsdPing = 70,
    MsgOsdBoot = 71,
    MsgOsdFailure = 72,
    MsgOsdAlive = 73,
    MsgOsdMarkMeDown = 74,
    MsgOsdSubop = 76,
    MsgOsdSubopreply = 77,
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

#[derive(Debug)]
pub struct CephEntityName{
    pub entity_type: CephEntity,
    pub num: u64,
}

pub struct Utime {
    pub tv_sec: u32,  // Seconds since epoch.
    pub tv_nsec: u32, // Nanoseconds since the last second.
}

// From src/include/msgr.h
#[derive(Debug)]
struct CephMsgHeader {
    sequence_num: u64,
    transaction_id: u64,
    msg_type: u16,  //CEPH_MSG_* or MSG_*
    priority: CephPriority,
    version: u16,   //version of message encoding
    front_len: u32, // The size of the front section
    middle_len: u32,// The size of the middle section
    data_len: u32,  // The size of the data section
    data_off: u16,  // The way data should be aligned by the reciever
    entity_name: CephEntityName, // Information about the sender
    compat_version: u16, // Oldest compatible encoding version
    reserved: u16, // Unused
    crc: u32,  // CRC of header
}

impl CephPrimitive for CephMsgHeader{
    fn read_from_wire<R: Read>(cursor: &mut R) -> Result<Self, SerialError>{

        let sequenece_num = try!(cursor.read_u64::<LittleEndian>());
        let transcation_id = try!(cursor.read_u64::<LittleEndian>());
        let msg_type = try!(cursor.read_u16::<LittleEndian>());
        println!("Msg type for CephMsgHeader: {}", msg_type);
        let priority = try!(cursor.read_u16::<LittleEndian>());
        println!("Priority: {}", priority);
        let version = try!(cursor.read_u16::<LittleEndian>());
        let front_len = try!(cursor.read_u32::<LittleEndian>());
        let middle_len = try!(cursor.read_u32::<LittleEndian>());
        let data_len = try!(cursor.read_u32::<LittleEndian>());
        let data_off = try!(cursor.read_u16::<LittleEndian>());

        let entity_type = try!(cursor.read_u8());
        println!("Entity_type: {}", entity_type);
        let entity_id = try!(cursor.read_u64::<LittleEndian>());

        let compat_version = try!(cursor.read_u16::<LittleEndian>());
        let reserved = try!(cursor.read_u16::<LittleEndian>());
        let crc = try!(cursor.read_u32::<LittleEndian>());

        return Ok(
            CephMsgHeader{
            sequence_num: sequenece_num,
            transaction_id: transcation_id,
            msg_type: msg_type,
            priority: CephPriority::from_u16(64).unwrap(),//TODO eliminate this
            version: version,
            front_len: front_len,
            middle_len: middle_len,
            data_len: data_len,
            data_off: data_off,
            entity_name: CephEntityName{
                entity_type: CephEntity::from_u8(1).unwrap(),//TODO eliminate this
                num: entity_id,
            },
            compat_version: compat_version,
            reserved: reserved,
            crc: crc,
            }
        );
    }

	fn write_to_wire(&self) -> Result<Vec<u8>, SerialError>{
        let mut buffer:Vec<u8> = Vec::new();
        try!(buffer.write_u64::<LittleEndian>(self.sequence_num));
        try!(buffer.write_u64::<LittleEndian>(self.transaction_id));
        try!(buffer.write_u16::<LittleEndian>(self.msg_type));
        try!(buffer.write_u16::<LittleEndian>(self.priority.clone() as u16));
        try!(buffer.write_u16::<LittleEndian>(self.version));
        try!(buffer.write_u32::<LittleEndian>(self.front_len));
        try!(buffer.write_u32::<LittleEndian>(self.middle_len));
        try!(buffer.write_u32::<LittleEndian>(self.data_len));
        try!(buffer.write_u16::<LittleEndian>(self.data_off));

        try!(buffer.write_u8(self.entity_name.entity_type.clone() as u8));
        try!(buffer.write_u64::<LittleEndian>(self.entity_name.num));

        try!(buffer.write_u16::<LittleEndian>(self.compat_version));
        try!(buffer.write_u16::<LittleEndian>(self.reserved));
        try!(buffer.write_u32::<LittleEndian>(self.crc));

        return Ok(buffer);
    }
}

#[derive(Debug)]
struct CephMsgFooter {
    front_crc: u32,
    middle_crc: u32,
    data_crc: u32,
    crypto_sig: u64,
    flags: u8
}

impl CephPrimitive for CephMsgFooter{
    fn read_from_wire<R: Read>(cursor: &mut R) -> Result<Self, SerialError>{
        let front_crc = try!(cursor.read_u32::<LittleEndian>());
        let middle_crc = try!(cursor.read_u32::<LittleEndian>());
        let data_crc = try!(cursor.read_u32::<LittleEndian>());

        let crypto_sig = try!(cursor.read_u64::<LittleEndian>());
        let flags = try!(cursor.read_u8());

        return Ok(
            CephMsgFooter{
                front_crc: front_crc,
                middle_crc: middle_crc,
                data_crc: data_crc,
                crypto_sig: crypto_sig,
                flags: flags
            }
        );
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

struct CephMsgTagAck{
    tag: CephMsg, //0x08
    seq: u64 //Sequence number of msg being acknowledged
}

impl CephPrimitive for CephMsgTagAck{
    fn read_from_wire<R: Read>(cursor: &mut R) -> Result<Self, SerialError>{
        let tag = try!(cursor.read_u8());
        let seq = try!(cursor.read_u64::<LittleEndian>());

        return Ok(CephMsgTagAck{
            tag: CephMsg::from_u8(tag).unwrap(),
            seq: seq,
        });
    }
	fn write_to_wire(&self) -> Result<Vec<u8>, SerialError>{
        let mut buffer: Vec<u8> = Vec::new();

        try!(buffer.write_u8(self.tag.clone() as u8));
        try!(buffer.write_u64::<LittleEndian>(self.seq));
        return Ok(buffer);
    }
}

struct CephMsgKeepAlive{
    tag: CephMsg, //0x09
    data: u8, // No data
}

impl CephPrimitive for CephMsgKeepAlive{
    fn read_from_wire<R: Read>(cursor: &mut R) -> Result<Self, SerialError>{
        let tag = try!(cursor.read_u8());
        let data = try!(cursor.read_u8());

        return Ok(CephMsgKeepAlive{
            tag: CephMsg::from_u8(tag).unwrap(),
            data: data,
        });
    }
	fn write_to_wire(&self) -> Result<Vec<u8>, SerialError>{
        let mut buffer: Vec<u8> = Vec::new();

        try!(buffer.write_u8(self.tag.clone() as u8));
        try!(buffer.write_u8(self.data));
        return Ok(buffer);
    }
}

struct CephMsgKeepAlive2{
    tag: CephMsg, //0x0E
    timestamp: Utime,
}

impl CephPrimitive for CephMsgKeepAlive2{
    fn read_from_wire<R: Read>(cursor: &mut R) -> Result<Self, SerialError>{
        let tag = try!(cursor.read_u8());
        let msg = CephMsg::from_u8(tag).unwrap();//TODO eliminate this
        let tv_sec = try!(cursor.read_u32::<LittleEndian>());
        let tv_nsec = try!(cursor.read_u32::<LittleEndian>());
        let time = Utime {
            tv_sec: tv_sec,
            tv_nsec: tv_nsec,
        };
        return Ok(CephMsgKeepAlive2{
            tag: msg,
            timestamp: time,
        });
    }
	fn write_to_wire(&self) -> Result<Vec<u8>, SerialError>{
        let mut buffer: Vec<u8> = Vec::new();

        try!(buffer.write_u8(self.tag.clone() as u8));
        try!(buffer.write_u32::<LittleEndian>(self.timestamp.tv_sec));
        try!(buffer.write_u32::<LittleEndian>(self.timestamp.tv_nsec));

        return Ok(buffer);
    }
}

struct CephMsgKeepAlive2Ack{
    tag: CephMsg, //0x0F
    timestamp: Utime,
}

impl CephPrimitive for CephMsgKeepAlive2Ack{
    fn read_from_wire<R: Read>(cursor: &mut R) -> Result<Self, SerialError>{
        let tag = try!(cursor.read_u8());
        let msg = CephMsg::from_u8(tag).unwrap();//TODO eliminate this

        let tv_sec = try!(cursor.read_u32::<LittleEndian>());
        let tv_nsec = try!(cursor.read_u32::<LittleEndian>());
        let time = Utime {
            tv_sec: tv_sec,
            tv_nsec: tv_nsec,
        };
        return Ok(CephMsgKeepAlive2Ack{
            tag: msg,
            timestamp: time,
        });
    }
	fn write_to_wire(&self) -> Result<Vec<u8>, SerialError>{
        let mut buffer: Vec<u8> = Vec::new();

        try!(buffer.write_u8(self.tag.clone() as u8));
        try!(buffer.write_u32::<LittleEndian>(self.timestamp.tv_sec));
        try!(buffer.write_u32::<LittleEndian>(self.timestamp.tv_nsec));

        return Ok(buffer);
    }
}

#[derive(Debug)]
struct EntityAddr{
    port: u16,
    nonce: u32,
    v4addr: Option<Ipv4Addr>,
    v6addr: Option<Ipv6Addr>,
}

impl CephPrimitive for EntityAddr{
    fn read_from_wire<R: Read>(cursor: &mut R) -> Result<Self, SerialError>{
        //type
        let addr_type = try!(cursor.read_u32::<LittleEndian>());
        let nonce = try!(cursor.read_u32::<LittleEndian>());
        //type-str
        let address_family = try!(cursor.read_u16::<BigEndian>());
        match address_family{
            0x0002 => {
                let port = try!(cursor.read_u16::<BigEndian>());
                let a = try!(cursor.read_u8());
                let b = try!(cursor.read_u8());
                let c = try!(cursor.read_u8());
                let d = try!(cursor.read_u8());
                let ip = Ipv4Addr::new(a,b,c,d);
                return Ok(
                    EntityAddr{
                        port: port,
                        nonce: nonce,
                        v4addr: Some(ip),
                        v6addr:None,
                    }
                );
            },
            0x000A =>{
                //TODO: Test this
                println!("IPv6 Addr");
                let port = try!(cursor.read_u16::<BigEndian>());
                println!("Port {}", port);
                let a = try!(cursor.read_u16::<BigEndian>());
                let b = try!(cursor.read_u16::<BigEndian>());
                let c = try!(cursor.read_u16::<BigEndian>());
                let d = try!(cursor.read_u16::<BigEndian>());
                let e = try!(cursor.read_u16::<BigEndian>());
                let f = try!(cursor.read_u16::<BigEndian>());
                let g = try!(cursor.read_u16::<BigEndian>());
                let h = try!(cursor.read_u16::<BigEndian>());
                let ip = Ipv6Addr::new(a,b,c,d,e,f,g,h);
                println!("IPv6 Addr_string: {}", ip);
                return Ok(
                    EntityAddr{
                        port: port,
                        nonce: nonce,
                        v4addr: None,
                        v6addr: Some(ip),
                    }
                );
            },
            _ => {
                println!("Unknown addr type");
                return Err(
                    SerialError::new(format!("unknown ip address family: {}", address_family))
                );
            }
        }
    }
	fn write_to_wire(&self) -> Result<Vec<u8>, SerialError>{
        //socket_type
        let mut buffer:Vec<u8> = Vec::new();

        try!(buffer.write_u32::<LittleEndian>(0)); //Is this right?
        try!(buffer.write_u32::<LittleEndian>(self.nonce));

        if self.v4addr.is_some(){
            //Address Family
            try!(buffer.write_u16::<BigEndian>(0x0002));
            //Port
            try!(buffer.write_u16::<BigEndian>(self.port));
            let tmp = self.v4addr.unwrap();//TODO eliminate this
            for octet in tmp.octets().iter(){
                try!(buffer.write_u8(*octet));
            }
            //Sockaddr_storage seems to be a 128 byte structure and
            //the ceph client is sending 120 bytes of 0's or padding
            for _ in 0..120{
                try!(buffer.write_u8(0));
            }
        }else if self.v6addr.is_some(){
            //Address Family
            try!(buffer.write_u32::<LittleEndian>(0x000A));

            //Port
            try!(buffer.write_u16::<BigEndian>(self.port));

            let tmp = self.v6addr.unwrap();//TODO eliminate this
            for octet in tmp.segments().iter(){
                try!(buffer.write_u16::<BigEndian>(*octet));
            }
        }else{
            //Unknown
            return Err(
                SerialError::new("EntityAddr needs a v4addr or v6addr.  Missing both".to_string())
            );
        }
        return Ok(buffer);
    }
}
/*
struct ceph_list<T> {
        u32le length;
        T     elements[length];
}
impl <T>CephPrimitive for Vec<T>{
	fn read_from_wire<R: Read>(cursor: &mut R) -> Result<Self, SerialError>{
        return Ok(Vec::new())
    }
	fn write_to_wire(&self) -> Result<Vec<u8>, SerialError>{
        return Ok(Vec::new());
    }
}
*/

//Connect to Ceph Monitor and send a hello banner
fn send_banner(socket: &mut TcpStream)->Result<(), SerialError>{
    let banner = String::from("ceph v027");
    let written_bytes = try!(socket.write(banner.as_bytes()));
    if written_bytes != 0{
        return Err(SerialError::new("blah".to_string()));
    }else{
        return Ok(());
    }
}

fn send_msg(socket: &mut TcpStream){

}

fn recv_msg(socket: &mut TcpStream){

}
