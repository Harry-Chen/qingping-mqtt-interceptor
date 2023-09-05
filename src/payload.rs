use std::collections::HashMap;

use serde::Deserialize;
use anyhow::Result;
use log::{debug, info, warn};


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


pub(crate) fn process_payload(measurement: &str, payload: &[u8]) -> Result<String> {
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
