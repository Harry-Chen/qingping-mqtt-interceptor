use envconfig::Envconfig;
use anyhow::Result;
use etherparse::TransportSlice::Tcp;
use log::{debug, info, warn, trace};
use qingping_mqtt_interceptor::fix_packet;

mod payload;

#[derive(Envconfig)]
struct Config {
    #[envconfig(from = "PCAP_INTERFACE", default = "br-lan")]
    pub pcap_interface: String,

    #[envconfig(from = "PCAP_FILTER", default = "")]
    pub pcap_filter: String,

    #[envconfig(from = "MEASUREMENT", default = "qingping")]
    pub measurement: String,
}

fn main() -> Result<()> {

    env_logger::init();
    let config = Config::init_from_env()?;

    let mut devices = pcap::Device::list()
        .expect("cannot list device");
    devices.retain(|d| d.name == config.pcap_interface);
    if devices.len() == 0 {
        panic!("no device available");
    }
    let device = devices.remove(0);
    info!("Using device {}", device.name);

    let mut cap = pcap::Capture::from_device(device)
        .expect("cannot setup capture")
        .timeout(0)
        .immediate_mode(true)
        .open()
        .expect("cannot open capture");

    cap.filter(config.pcap_filter.as_str(), true).expect("set filter failed");

    while let Ok(p) = cap.next_packet() {
        let packet = fix_packet(p);

        let Ok(parsed_packet) = etherparse::SlicedPacket::from_ethernet(&packet.data) else {
            trace!("Packet cannot be parsed as ethernet packet");
            continue
        };

        let Some(Tcp(_)) = parsed_packet.transport else {
            trace!("Packet is not TCP");
            continue
        };

        let payload = parsed_packet.payload;

        if payload.len() == 0 {
            trace!("Packet has no payload");
            continue
        }

        debug!("Got packet with payload length {:?}", payload.len());

        match mqttrs::decode_slice(payload) {
            Ok(packet) => {
                match packet {
                    Some(mqttrs::Packet::Publish(p)) => {
                        debug!("Got MQTT Publish Packet with topic {}", p.topic_name);
                        
                        match payload::process_payload(&config.measurement, p.payload) {
                            Ok(s) => {
                                println!("{}", s);
                            }
                            Err(e) => {
                                warn!("Cannot process MQTT Publish Packet: {:?}", e);
                            }
                        }
                    }
                    Some(p) => {
                        debug!("Ignore MQTT Packet: {:?}", p);
                    }
                    None => {
                        trace!("Incomplete MQTT Packet.");
                    }
                }
            }
            Err(e) => {
                trace!("Cannot parse as MQTT packet: {:?}", e);
            }
        }
    }

    Ok(())
}
