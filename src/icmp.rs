use crate::{
    ipv4::IPv4Protocol,
    protocol::{get_checksum, Protocol, ProtocolError},
};

// RFC 792
pub struct Icmp {}

impl Icmp {
    pub fn new() -> Icmp {
        Icmp {}
    }
}

impl Protocol for Icmp {
    fn reply(&self, buf: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        let mut buf = buf.to_vec();

        // Type
        // Echo Reply
        buf[0] = 0;

        // Set the checksum field to zero before computing a checksum
        buf[2] = 0;
        buf[3] = 0;

        let checksum = get_checksum(&buf);

        // Checksum
        buf[2] = (checksum >> 8) as u8;
        buf[3] = (checksum & 0xff) as u8;
        Ok(buf)
    }
}

impl IPv4Protocol for Icmp {
    fn number(&self) -> u8 {
        1
    }
}
