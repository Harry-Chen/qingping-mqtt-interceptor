use envconfig::Envconfig;
use anyhow::Result;
use log::{debug, info, warn};
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
        let plen = packet.header.caplen as usize;
        if plen <= 66 {
            continue
        }
        let payload = &packet.data[66..plen];
        debug!("Got packet with length {:?}", packet.header.caplen);
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
                        debug!("Incomplete MQTT Packet.");
                    }
                }
            }
            Err(e) => {
                debug!("Cannot parse MQTT packet: {:?}", e);
            }
        }
    }

    Ok(())
}
