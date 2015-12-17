#![recursion_limit="100"]
#![allow(dead_code)]
#[macro_use] extern crate enum_primitive;
#[macro_use] extern crate bitflags;
#[macro_use] extern crate nom;
#[macro_use] extern crate log;
extern crate byteorder;
extern crate num;
extern crate output_args;
extern crate pcap;
extern crate users;
extern crate simple_logger;
extern crate time;
extern crate influent;

mod serial;
mod crypto;
mod mon_decode;
mod common_decode;
mod osd_decode;

use pcap::{Capture, Device};

use std::io::prelude::*;
use std::net::TcpStream;
use std::str::FromStr;

use influent::create_client;
use influent::client::Client;
use influent::client::Credentials;
use influent::measurement::{Measurement, Value};
use output_args::*;

#[cfg(test)]
mod tests{
    extern crate output_args;
    extern crate pcap;

    use std::io::Cursor;
    use std::net::Ipv4Addr;
    use std::path::Path;
    use pcap::{Capture, Device};
    use log;
    use nom;
    use output_args::*;
    use super::serial;

    #[test]
    fn test_pcap_parsing(){
        let args = output_args::Args {
            carbon: None,
            elasticsearch: None,
            stdout: Some("stdout".to_string()),
            influx: None,
            outputs: vec!["elasticsearch".to_string(), "carbon".to_string(), "stdout".to_string()],
            config_path: "".to_string(),
            log_level: log::LogLevel::Info
        };
        //Set the cursor so the parsing doesn't fail
        let mut cap = Capture::from_file(Path::new("ceph.pcap")).unwrap();
        /*
        while let Ok(packet) = cap.next() {
            match serial::parse_ceph_packet(&packet.data) {
                nom::IResult::Done(_, result) => {
                    println!("logging {:?}", result);
                    // let _ = super::process_packet(&result.header, &result.ceph_message, &args);
                },
                nom::IResult::Incomplete(i) => println!("Incomplete: {:?}: {:?}", i, packet),
                nom::IResult::Error(e) => println!("Error parsing; {:?}", e),
                // _ => trace!("Error while parsing packet")
            }
        }
        */
    }
}

//TODO expose even more data
#[derive(Debug)]
struct Document<'a>{
    header: &'a serial::PacketHeader,
    flags: serial::OsdOp,
    operation_count: u16,
    //placement_group: serial::PlacementGroup,
    size: u32,
    timestamp: u64, //Milliseconds since epoch
}

// JSON value representation
impl<'a> Document<'a>{
    fn to_carbon_string(&self, root_key: &str)->Result<String, String>{
        let src_addr: String = match self.header.src_v4addr{
            Some(addr) => addr.to_string(),
            None => {
                match self.header.src_v6addr{
                    Some(addr) => addr.to_string(),
                    None => "".to_string(),
                }
            },
        };

        let dst_addr: String = match self.header.dst_v4addr{
            Some(addr) => addr.to_string(),
            None => {
                match self.header.dst_v6addr{
                    Some(addr) => addr.to_string(),
                    None => "".to_string(),
                }
            },
        };
        //NOTE: carbon uses epoch time aka seconds since epoch not milliseconds
        let carbon_string = format!( r#"
{root_key}.src_ip {} {timestamp}
{root_key}.dst_ip {} {timestamp}
{root_key}.flags {:?} {timestamp}
{root_key}.operation_count {} {timestamp}
{root_key}.size {} {timestamp}
  "#, src_addr, dst_addr, self.flags, self.operation_count, self.size, root_key = root_key,
  timestamp = (self.timestamp/1000));

        return Ok(carbon_string);
    }
}

fn get_arguments() -> output_args::Args {
    output_args::get_args()
}

fn check_user()->Result<(), ()>{
    let current_user = users::get_current_uid();
    if current_user != 0 {
        error!("This program must be run by root to access the network devices");
        return Err(());
    }
    return Ok(());
}

fn get_time()->u64{
    let now = time::now();
    let milliseconds_since_epoch = now.to_timespec().sec * 1000;
    return milliseconds_since_epoch as u64;
}

fn log_to_stdout(){

}

fn log_packet_to_carbon(carbon_url: &str, data: String)->Result<(), String>{
    //Carbon is plaintext
    //echo "local.random.diceroll 4 `date +%s`" | nc -q0 ${SERVER} ${PORT}

    let mut stream = try!(TcpStream::connect(carbon_url).map_err(|e| e.to_string()));
    let bytes_written = try!(stream.write(&data.into_bytes()[..]).map_err(|e| e.to_string()));
    info!("Wrote: {} bytes to graphite", &bytes_written);

    return Ok(());
}

fn parse_carbon_url(url: &String)->Result<(String, u16), String>{
    let parts: Vec<&str> = url.split(":").collect();
    if parts.len() == 2{
        let carbon_host = parts[0].to_string();
        let carbon_port = try!(u16::from_str(parts[1]).map_err(|e| e.to_string()));
        return Ok((carbon_host, carbon_port));
    }else{
        return Err("Invalid carbon host specification.  See CLI example".to_string());
    }
}

fn log_msg_to_carbon(header: &serial::PacketHeader, msg: &serial::Message, output_args: &Args)->Result<(),String>{
    if output_args.carbon.is_some(){
        let op = match *msg{
            serial::Message::OsdOp(ref osd_op) => osd_op,
            //TODO: What should we do here?
            //serial::Message::OsdSubop(ref sub_op) => sub_op,
            _ => return Err("Bad type".to_string())
        };

        let carbon = output_args.clone().carbon.unwrap();

        let carbon_host = carbon.host.clone();
        let carbon_port = carbon.port.clone();
        let carbon_url = format!("{}:{}", carbon_host, carbon_port);
        let carbon_root_key = carbon.root_key.clone();

        let milliseconds_since_epoch = get_time();
        let doc = Document{
            header: header,
            flags: op.flags,
            operation_count: op.operation_count,
            size: op.operation.payload_size,
            timestamp: milliseconds_since_epoch,
        };
        let carbon_data = format!("{}.{}", carbon_root_key, try!(doc.to_carbon_string(&carbon.root_key)));
        try!(log_packet_to_carbon(&carbon_url, carbon_data));
    }
    Ok(())
}

fn log_msg_to_stdout(header: &serial::PacketHeader, msg: &serial::Message, output_args: &Args)->Result<(),String>{
    if output_args.stdout.is_some(){
        let op = match *msg{
            serial::Message::OsdOp(ref osd_op) => osd_op,
            //serial::Message::OsdSubop(ref sub_op) => sub_op,
            _ => return Err("Bad type".to_string())
        };
        let now = time::now();
        let time_spec = now.to_timespec();
        //TODO Expand this
        println!("{}", format!("ceph.{}.{:?}.{} {}",
            &header.src_v4addr.unwrap(),
            op.flags,
            op.operation.payload_size,
            time_spec.sec)
        );
    }
    Ok(())
}

fn log_msg_to_influx(header: &serial::PacketHeader, msg: &serial::Message, output_args: &Args)->Result<(),String>{
    if output_args.influx.is_some() && output_args.outputs.contains(&"influx".to_string()) {
        let op = match *msg{
            serial::Message::OsdOp(ref osd_op) => osd_op,
            //serial::Message::OsdSubop(ref sub_op) => sub_op,
            _ => return Err("Bad type".to_string())
        };

        let influx = &output_args.influx.clone().unwrap();
        let credentials = Credentials {
            username: influx.user.as_ref(),
            password: influx.password.as_ref(),
            database: "ceph"
        };
        let host = format!("http://{}:{}",influx.host, influx.port);
        let hosts = vec![host.as_ref()];
        let client = create_client(credentials, hosts);



        let src_addr: String = match header.src_v4addr{
            Some(addr) => addr.to_string(),
            None => {
                match header.src_v6addr{
                    Some(addr) => addr.to_string(),
                    None => "".to_string(),
                }
            },
        };

        let dst_addr: String = match header.dst_v4addr{
            Some(addr) => addr.to_string(),
            None => {
                match header.dst_v6addr{
                    Some(addr) => addr.to_string(),
                    None => "".to_string(),
                }
            },
        };
        let size = op.operation.payload_size as f64;
        let count = op.operation_count as i64;
        let flags: String = format!("{:?}", op.flags).clone();
        let mut measurement = Measurement::new("ceph");

        if op.flags.contains(serial::CEPH_OSD_FLAG_WRITE) {
            measurement.add_tag("type", "write");
        } else if op.flags.contains(serial::CEPH_OSD_FLAG_READ) {
            measurement.add_tag("type", "read");
        } else {
            trace!("{:?} doesn't contain {:?}", op.flags, vec![serial::CEPH_OSD_FLAG_WRITE, serial::CEPH_OSD_FLAG_READ]);
        }
        measurement.add_tag("src_address", src_addr.as_ref());
        measurement.add_tag("dst_address", dst_addr.as_ref());

        measurement.add_field("size", Value::Float(size));
        measurement.add_field("operation", Value::String(flags.as_ref()));
        measurement.add_field("count", Value::Integer(count));

        let res = client.write_one(measurement, None);
        debug!("{:?}", res);
    }
    Ok(())
}

fn process_packet(header: &serial::PacketHeader, msg: &serial::CephMsgrMsg, output_args: &Args)->Result<(),String>{
    //Process OSD operation packets
    for ceph_msg in msg.messages.iter(){
        let _ = log_msg_to_carbon(&header, &ceph_msg, output_args);
        let _ = log_msg_to_stdout(&header, &ceph_msg, output_args);
        let _ = log_msg_to_influx(&header, &ceph_msg, output_args);
    }
    Ok(())
}

fn main() {
    let args = get_arguments();
    //TODO make configurable via cli or config arg
    simple_logger::init_with_level(args.log_level).unwrap();

    match check_user(){
        Ok(_) => {},
        Err(_) =>{
            return;
        }
    };

    for output in &args.outputs {
        info!("Logging to {}", output);
    }

    let dev_list = match Device::list(){
        Ok(l) => l,
        Err(e) => {
            error!("Unable to list network devices.  Error: {}", e);
            return;
        }
    };

    info!("Searching for network devices");
    for dev_device in dev_list{
        if dev_device.name == "any"{
            let device_name = dev_device.name.clone();
            // let mut cooked_header = false;

            info!("Found Network device {}", &device_name);
            info!("Setting up capture({})", &device_name);
            let mut cap = Capture::from_device(dev_device).unwrap() //open the device
                          .promisc(true)
                          //.snaplen(500) //Might need this still if we're losing packets
                          .timeout(100)
                          .open() //activate the handle
                          .unwrap(); //assume activation worked

            info!("Setting up filter({})", &device_name);
            //Grab both monitor and OSD traffic
            match cap.filter("tcp portrange 6789-7300"){
                Ok(_) => {
                    info!("Filter successful({})", &device_name);
                },
                Err(e) => {
                    error!("Invalid capture filter({}). Error: {:?}", &device_name, e);
                    return;
                }
            }
            info!("Waiting for packets({})", &device_name);
            //Grab some packets :)

            //Infinite loop
            loop {
                match cap.next(){
                    //We received a packet
                    Ok(packet) =>{
                        match serial::parse_ceph_packet(&packet.data) {
                            nom::IResult::Done(_, result) => {
                                trace!("logging {:?}", result);
                                let _ = process_packet(&result.header, &result.ceph_message, &args);
                            },
                            _ => {}
                        };
                        // break
                    },
                    //We missed a packet, ignore
                    Err(_) => {},
                }
            }
        }
    }
}
