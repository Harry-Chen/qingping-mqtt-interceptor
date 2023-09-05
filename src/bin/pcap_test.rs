use pcap::Capture;
use qingping_mqtt_interceptor::FixHeaderCodec;
use std::error;


fn main() -> Result<(), Box<dyn error::Error>> {
    // let device = Device::lookup()?.ok_or("no device available")?;

    // get the default Device
    // println!("Using device {}", device.name);

    let cap = Capture::from_device("br-lan")?.immediate_mode(true).open()?;

    for packet in cap.iter(FixHeaderCodec).take(100) {
        let packet = packet?;
        println!("{:?}", packet.header);
    }

    // while let Ok(packet) = cap.next_packet() {
    //     let packet = fix_packet(packet);
    //     println!("{:?} {:?}", packet.header.caplen, &packet.data.len());
    //     // break;
    // }

    Ok(())
}
