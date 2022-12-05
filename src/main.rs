use ipv4::IPv4;

use crate::{icmp::Icmp, protocol::Protocol, tun::Tun};

mod icmp;
mod ipv4;
mod ipv4test;
mod protocol;
mod tun;

fn main() {
    let tun = Tun::new().unwrap();
    let icmp = Box::new(Icmp::new());
    let ipv4 = IPv4::new(vec![icmp]);

    loop {
        let mut buf = [0u8; 65535];
        let n = tun.read(&mut buf).unwrap();
        let buf = &mut buf[0..n];

        // Debug
        println!("{:x?}", buf);

        if let Ok(mut buf) = ipv4.reply(buf) {
            tun.write(&mut buf).unwrap();
        }
    }
}
