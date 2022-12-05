use std::fmt;

use crate::{
    ipv4::IPv4Protocol,
    protocol::{get_checksum, Protocol, ProtocolError},
};

enum IcmpType {
    EchoReply = 0,
    Echo = 8,
}

#[derive(Debug, Eq, PartialEq)]
pub struct IcmpError(pub String);

impl fmt::Display for IcmpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "icmp: {}", self.0)
    }
}

// RFC 792
pub struct Icmp {}

impl Icmp {
    pub fn new() -> Icmp {
        Icmp {}
    }

    fn _verify_length(&self, buf: &[u8]) -> Result<(), ProtocolError> {
        // Type: 1 octet
        // Code: 1 octet
        // Checksum: 2 octets
        // Identifier: 2 octets
        // Sequence Number: 2 octets
        //
        // 1 + 1 + 2 + 2 + 2 = 8
        if buf.len() < 8 {
            return Err(IcmpError("too short".to_string()).into());
        }
        Ok(())
    }

    fn _verify_checksum(&self, buf: &Vec<u8>) -> Result<(), ProtocolError> {
        let checksum = get_checksum(buf);
        if checksum != 0 {
            return Err(IcmpError(format!("checksum error: checksum={:#x?}", checksum)).into());
        }
        Ok(())
    }
}

impl Protocol for Icmp {
    fn reply(&self, buf: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        self._verify_length(buf)?;

        let mut buf = buf.to_vec();
        self._verify_checksum(&buf)?;

        if buf[0] != IcmpType::Echo as u8 {
            return Err(ProtocolError::General);
        }

        // Type
        buf[0] = IcmpType::EchoReply as u8;

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
