use crate::protocol::Protocol;

pub struct Icmp {}

impl Icmp {
    pub fn new() -> Icmp {
        Icmp {}
    }
}

impl Protocol for Icmp {
    fn reply(&self, buf: &[u8]) -> Option<Vec<u8>> {
        let mut buf = buf.to_vec();

        // Type
        // Echo Reply
        buf[0] = 0;

        // Set the checksum field to zero before computing a checksum
        buf[2] = 0;
        buf[3] = 0;

        let mut checksum: u32 = 0;
        for i in (0..buf.len()).step_by(2) {
            checksum += ((buf[i] as u32) << 8) + buf[i + 1] as u32;
        }
        while (checksum >> 16) != 0 {
            checksum = (checksum & 0xffff) + (checksum >> 16);
        }
        // one's complement
        checksum = !checksum;

        // Checksum
        buf[2] = (checksum >> 8) as u8;
        buf[3] = (checksum & 0xff) as u8;
        Some(buf)
    }
}
