use std::fmt;

use crate::protocol::{get_checksum, Protocol, ProtocolError};

#[derive(Debug, Eq, PartialEq)]
pub struct IPv4Error(pub String);

impl fmt::Display for IPv4Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ipv4: {}", self.0)
    }
}

// RFC 791
pub struct IPv4 {
    protocols: Vec<Box<dyn Protocol>>,
}

impl IPv4 {
    pub fn new(protocols: Vec<Box<dyn Protocol>>) -> IPv4 {
        IPv4 { protocols }
    }
}

impl IPv4 {
    const MIN_HEADER_SIZE: usize = 20;

    fn _verify_length(&self, buf: &[u8]) -> Result<(), ProtocolError> {
        if buf.len() < IPv4::MIN_HEADER_SIZE {
            return Err(IPv4Error("too short".to_string()).into());
        }
        Ok(())
    }

    fn _verify_version(&self, buf: &[u8]) -> Result<(), ProtocolError> {
        let version = buf[0] >> 4;
        if version != 4 {
            return Err(IPv4Error(format!("ip version error: version={}", version)).into());
        }
        Ok(())
    }

    fn _verify_ihl(&self, buf: &[u8], ihl: usize) -> Result<(), ProtocolError> {
        if buf.len() < ihl {
            return Err(IPv4Error(format!(
                "header length error: ihl={}, len={}",
                ihl,
                buf.len()
            ))
            .into());
        }
        Ok(())
    }

    fn _verify_total_length(&self, buf: &[u8]) -> Result<(), ProtocolError> {
        let total_length = ((buf[2] as usize) << 8) | buf[3] as usize;
        if buf.len() != total_length {
            return Err(IPv4Error(format!(
                "total length error: total length={}, len={}",
                total_length,
                buf.len()
            ))
            .into());
        }
        Ok(())
    }

    fn _verify_no_fragment(&self, buf: &[u8]) -> Result<(), ProtocolError> {
        // Flags (More Fragments)
        // Fragment Offset
        if buf[6] & 0x20 != 0 || buf[6] & 0x1f != 0 || buf[7] != 0 {
            return Err(IPv4Error("fragments unsupported".to_string()).into());
        }
        Ok(())
    }

    fn _verify_header_checksum(&self, header: &Vec<u8>) -> Result<(), ProtocolError> {
        let checksum = get_checksum(header);
        if checksum != 0 {
            return Err(IPv4Error(format!(
                "header checksum error: header checksum={:#x?}",
                checksum
            ))
            .into());
        }
        Ok(())
    }
}

impl Protocol for IPv4 {
    fn reply(&self, buf: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        self._verify_length(buf)?;
        self._verify_version(buf)?;

        // Internet Header Length (IHL)
        let ihl = 4 * (buf[0] & 0xf) as usize;
        self._verify_ihl(buf, ihl)?;

        self._verify_total_length(buf)?;
        self._verify_no_fragment(buf)?;

        let header = &mut buf[..ihl].to_vec();
        self._verify_header_checksum(header)?;

        // Swap the source IP address for the destination IP address
        for i in 12..16 {
            header.swap(i, i + 4);
        }

        let data = &buf[ihl..];
        for p in &self.protocols {
            if let Ok(mut data) = p.reply(data) {
                let mut buf = header.to_vec();
                buf.append(&mut data);
                return Ok(buf);
            }
        }
        Err(ProtocolError::General)
    }
}
