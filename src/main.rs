use futures::{SinkExt, StreamExt};
use packet::{builder::Builder, icmp, ip, Packet};
use pnet_packet::{
    icmp::IcmpTypes, ip::IpNextHeaderProtocols, FromPacket, MutablePacket, Packet as OtherPacket,
};
use tokio_util::codec::Framed;
use tun2::{AsyncDevice, TunPacket, TunPacketCodec};

fn canonical_pkt(pkt: TunPacket) -> Vec<u8> {
    let pkt = ip::v4::Packet::new(pkt.get_bytes()).unwrap();
    let icmp = icmp::Packet::new(pkt.payload()).unwrap();
    let icmp = icmp.echo().unwrap();
    let reply = ip::v4::Builder::default()
        .id(0x42)
        .unwrap()
        .ttl(64)
        .unwrap()
        .source(pkt.destination())
        .unwrap()
        .destination(pkt.source())
        .unwrap()
        .icmp()
        .unwrap()
        .echo()
        .unwrap()
        .reply()
        .unwrap()
        .identifier(icmp.identifier())
        .unwrap()
        .sequence(icmp.sequence())
        .unwrap()
        .payload(icmp.payload())
        .unwrap()
        .build()
        .unwrap();
    reply
}

async fn handle_pkt(pkt: TunPacket, framed: &mut Framed<AsyncDevice, TunPacketCodec>) {
    let canoni = canonical_pkt(TunPacket::new(pkt.get_bytes().to_vec()));
    println!("{:?}", canoni);
    match pnet_packet::ipv4::Ipv4Packet::new(pkt.get_bytes()) {
        Some(ip_pkt) => {
            match ip_pkt.get_next_level_protocol() {
                IpNextHeaderProtocols::Icmp => {
                    let icmp_pkt = pnet_packet::icmp::IcmpPacket::new(ip_pkt.payload()).unwrap();
                    match icmp_pkt.get_icmp_type() {
                        IcmpTypes::EchoRequest => {
                            let mut v = ip_pkt.payload().to_owned();
                            let mut pkkt =
                                pnet_packet::icmp::MutableIcmpPacket::new(&mut v[..]).unwrap();
                            pkkt.set_icmp_type(IcmpTypes::EchoReply);
                            pkkt.set_checksum(pnet_packet::icmp::checksum(&pkkt.to_immutable()));
                            //println!("{:?}",v);
                            let len = ip_pkt.packet().len();
                            let mut buf = vec![0u8; len];
                            let mut res =
                                pnet_packet::ipv4::MutableIpv4Packet::new(&mut buf).unwrap();
                            res.set_total_length(ip_pkt.get_total_length());
                            res.set_header_length(ip_pkt.get_header_length());
                            res.set_destination(ip_pkt.get_source());
                            res.set_source(ip_pkt.get_destination());
                            res.set_identification(0x42);
                            res.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
                            res.set_payload(&v);
                            res.set_ttl(64);
                            res.set_version(ip_pkt.get_version());
                            res.set_checksum(pnet_packet::ipv4::checksum(&res.to_immutable()));
                            println!("{:?}", buf);
                            let _ = framed.send(TunPacket::new(buf.to_vec())).await;
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }
        None => {}
    }
}

#[tokio::main]
async fn main() {
    let mut config = tun2::Configuration::default();
    config
        .address((10, 0, 0, 1))
        .netmask((255, 255, 255, 0))
        .up();
    let dev = tun2::create_as_async(&config).unwrap();
    let mut framed = dev.into_framed();
    let _ = std::process::Command::new("sh")
        .arg("-c")
        .arg("sudo route -n add -net 10.0.0.0/24 10.0.0.1")
        .output()
        .unwrap();
    while let Some(pkt) = framed.next().await {
        match pkt {
            Ok(pkt) => {
                handle_pkt(pkt, &mut framed).await;
            }
            Err(_) => (),
        }
    }
}
