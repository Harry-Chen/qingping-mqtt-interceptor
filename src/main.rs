use std::collections::HashMap;

use envconfig::Envconfig;
use serde::Deserialize;
use anyhow::Result;
use log::{debug, info, warn};

use qingping_mqtt_interceptor::FixHeaderCodec;

#[derive(Envconfig)]
struct Config {
    #[envconfig(from = "PCAP_INTERFACE", default = "br-lan")]
    pub pcap_interface: String,

    #[envconfig(from = "PCAP_FILTER", default = "")]
    pub pcap_filter: String,

    #[envconfig(from = "MEASUREMENT", default = "qingping")]
    pub measurement: String,
}

#[derive(Deserialize, Debug)]
struct SensorValue {
    pub status: Option<u32>,
    pub value: Option<f64>
}


#[derive(Deserialize, Debug)]
struct MqttPayload {
    pub mac: Option<String>,
    #[serde(rename = "sensorData")]
    pub sensor_data: Option<Vec<HashMap<String, SensorValue>>>,
    pub timestamp: Option<u64>
}


fn process_payload(measurement: &str, payload: &[u8]) -> Result<String> {
    let d: MqttPayload = serde_json::from_slice(payload)?;
    debug!("Got JSON payload: {:?}", d);
    if d.sensor_data.is_none() {
        return Err(anyhow::anyhow!("No sensor data"));
    }
    let values = d.sensor_data.unwrap().remove(0);
    let mac = match d.mac {
        Some(m) => m,
        None => String::from("UNKNOWN")
    };
    let timestamp = match d.timestamp {
        Some(t) => t * 1000000000, // convert to nanoseconds
        None => std::time::Instant::now().elapsed().as_nanos() as u64
    };
    info!("Valid MQTT update with timestamp {:?} device MAC {}", d.timestamp, mac);
    
    let mut result = format!("{},mac={} ", measurement, mac);
    let mut fields = Vec::new();
    for (k, sv) in values {
        if sv.value.is_none() {
            continue
        }
        match sv.status {
            Some(0) | Some(1) => {
                fields.push(format!("{}={}", k, sv.value.unwrap()));
            }
            Some(2) => {
                // tvoc sensor initializing...
            }
            Some(s) => {
                // what are these?
                warn!("Unknown status value {}", s);
            }
            None => {}
        }

    }
    result += &fields.join(",");
    result += " ";
    result += &timestamp.to_string();

    info!("Result: {}", result);
    Ok(result)
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

    for p in cap.iter(FixHeaderCodec) {
        let packet = p.expect("cannot get packet");
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
                        match process_payload(&config.measurement, p.payload) {
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
