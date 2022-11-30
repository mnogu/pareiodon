use crate::protocol::Protocol;

pub struct IPv4 {
    protocols: Vec<Box<dyn Protocol>>,
}

impl IPv4 {
    pub fn new(protocols: Vec<Box<dyn Protocol>>) -> IPv4 {
        IPv4 { protocols }
    }
}

impl Protocol for IPv4 {
    fn reply(&self, buf: &[u8]) -> Option<Vec<u8>> {
        let version = buf[0] >> 4;
        if version != 4 {
            return None;
        }

        // Internet Header Length (IHL)
        let ihl = 4 * (buf[0] & 0xf) as usize;
        let header = &mut buf[..ihl].to_vec();

        // Swap the source IP address for the destination IP address
        for i in 12..16 {
            header.swap(i, i + 4);
        }

        let data = &buf[ihl..];
        for p in &self.protocols {
            if let Some(mut data) = p.reply(data) {
                let mut buf = header.to_vec();
                buf.append(&mut data);
                return Some(buf);
            }
        }
        None
    }
}
