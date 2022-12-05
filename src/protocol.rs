use crate::{icmp::IcmpError, ipv4::IPv4Error};

pub trait Protocol {
    fn reply(&self, buf: &[u8]) -> Result<Vec<u8>, ProtocolError>;
}

#[derive(Debug, Eq, PartialEq)]
pub enum ProtocolError {
    IPv4(IPv4Error),
    Icmp(IcmpError),
    General,
}

impl From<IPv4Error> for ProtocolError {
    fn from(e: IPv4Error) -> Self {
        Self::IPv4(e)
    }
}

impl From<IcmpError> for ProtocolError {
    fn from(e: IcmpError) -> Self {
        Self::Icmp(e)
    }
}

pub fn get_checksum(buf: &Vec<u8>) -> u16 {
    let mut checksum: u32 = 0;
    for i in (0..buf.len()).step_by(2) {
        checksum += ((buf[i] as u32) << 8) + buf[i + 1] as u32;
    }
    while (checksum >> 16) != 0 {
        checksum = (checksum & 0xffff) + (checksum >> 16);
    }
    // one's complement
    checksum = !checksum & 0xffff;
    checksum as u16
}
