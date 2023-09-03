# Qingping MQTT Interceptor

Tool to parse data from MQTT traffic of [Qingping Air Monitor](https://www.qingping.co/air-monitor/overview), and print in InfluxDB line protocol.

There are several ways to get data from the monitor:

1. The monitor publishes data via (clear text) MQTT. However the interval (normally 15 minutes) cannot be controlled by user.
2. Poll HTTP API (used by Qingping+ App) to fetch the latest data. However it requires HTTPS MITM.
3. Connect the monitor to MIJIA and use miIO protocol to access the device.

If you can control the network, intercepting MQTT traffic should be the easiest way.

## Usage

First install `libpcap`, then run:

```bash
cargo install --git https://github.com/Harry-Chen/qingping-mqtt-interceptor.git
sudo env PCAP_INTERFACE="br-lan" PCAP_FILTER="port 11883" MEASUREMENT="qingping" qingping-mqtt-interceptor
```

Note: during the initilization of tVOC sensor, no data will be provided.
