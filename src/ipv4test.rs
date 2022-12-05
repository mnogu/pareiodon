#[cfg(test)]
mod tests {
    use crate::{
        ipv4::{IPv4, IPv4Error},
        protocol::{Protocol, ProtocolError},
    };

    struct TestProtocol {}

    impl Protocol for TestProtocol {
        fn reply(&self, buf: &[u8]) -> Result<Vec<u8>, ProtocolError> {
            Ok(buf.to_vec())
        }
    }

    #[test]
    fn ipv4() {
        let buf = [
            0x45, // Version, IHL
            0x00, // Type of Service
            0x00, 0x54, // Total Length
            0x6d, 0x6f, // Identification
            0x40, 0x00, // Flags, Fragment Offset
            0x40, // Time to Live
            0x01, // Protocol
            0x49, 0x36, // Header Checksum
            0xc0, 0x00, 0x02, 0x01, // Source Address
            0xc0, 0x00, 0x02, 0x02, // Destination Address
            0x08, 0x00, 0x7f, 0x57, 0x00, 0x2d, 0x00, 0x02, 0xf3, 0x89, 0x8d, 0x63, 0x00, 0x00,
            0x00, 0x00, 0x35, 0xb9, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13,
            0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21,
            0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, // Data
        ];
        let ipv4 = IPv4::new(vec![Box::new(TestProtocol {})]);
        let reply = ipv4.reply(&buf);
        assert_eq!(
            reply,
            Ok(vec![
                0x45, // Version, IHL
                0x00, // Type of Service
                0x00, 0x54, // Total Length
                0x6d, 0x6f, // Identification
                0x40, 0x00, // Flags, Fragment Offset
                0x40, // Time to Live
                0x01, // Protocol
                0x49, 0x36, // Header Checksum
                0xc0, 0x00, 0x02, 0x02, // Source Address
                0xc0, 0x00, 0x02, 0x01, // Destination Address
                0x08, 0x00, 0x7f, 0x57, 0x00, 0x2d, 0x00, 0x02, 0xf3, 0x89, 0x8d, 0x63, 0x00, 0x00,
                0x00, 0x00, 0x35, 0xb9, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13,
                0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21,
                0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
                0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, // Data
            ])
        );
    }

    #[test]
    fn too_short() {
        let buf = [
            0x45, // Version, IHL
            0x00, // Type of Service
            0x00, 0x13, // Total Length
            0x6d, 0x6f, // Identification
            0x40, 0x00, // Flags, Fragment Offset
            0x40, // Time to Live
            0x01, // Protocol
            0x49, 0x36, // Header Checksum
            0xc0, 0x00, 0x02, 0x01, // Source Address
            0xc0, 0x00, 0x02, // Destination Address (missing 1 byte)
        ];
        let ipv4 = IPv4::new(vec![Box::new(TestProtocol {})]);
        let reply = ipv4.reply(&buf);
        assert_eq!(reply, Err(IPv4Error("too short".to_string()).into()));
    }

    #[test]
    fn wrong_version() {
        let buf = [
            0x55, // Version (wrong version), IHL
            0x00, // Type of Service
            0x00, 0x14, // Total Length
            0x6d, 0x6f, // Identification
            0x40, 0x00, // Flags, Fragment Offset
            0x40, // Time to Live
            0x01, // Protocol
            0x49, 0x36, // Header Checksum
            0xc0, 0x00, 0x02, 0x01, // Source Address
            0xc0, 0x00, 0x02, 0x01, // Destination Address
        ];
        let ipv4 = IPv4::new(vec![Box::new(TestProtocol {})]);
        let reply = ipv4.reply(&buf);
        assert_eq!(
            reply,
            Err(IPv4Error("ip version error: version=5".to_string()).into())
        );
    }

    #[test]
    fn wrong_ihl() {
        let buf = [
            0x46, // Version, IHL (wrong IHL)
            0x00, // Type of Service
            0x00, 0x14, // Total Length
            0x6d, 0x6f, // Identification
            0x40, 0x00, // Flags, Fragment Offset
            0x40, // Time to Live
            0x01, // Protocol
            0x49, 0x36, // Header Checksum
            0xc0, 0x00, 0x02, 0x01, // Source Address
            0xc0, 0x00, 0x02, 0x01, // Destination Address
        ];
        let ipv4 = IPv4::new(vec![Box::new(TestProtocol {})]);
        let reply = ipv4.reply(&buf);
        assert_eq!(
            reply,
            // 6 * 4 = 24
            Err(IPv4Error("header length error: ihl=24, len=20".to_string()).into())
        );
    }
    #[test]
    fn wrong_total_length() {
        let buf = [
            0x45, // Version, IHL
            0x00, // Type of Service
            0x00, 0x54, // Total Length
            0x6d, 0x6f, // Identification
            0x40, 0x00, // Flags, Fragment Offset
            0x40, // Time to Live
            0x01, // Protocol
            0x49, 0x36, // Header Checksum
            0xc0, 0x00, 0x02, 0x01, // Source Address
            0xc0, 0x00, 0x02, 0x02, // Destination Address
            0x08, 0x00, 0x7f, 0x57, 0x00, 0x2d, 0x00, 0x02, 0xf3, 0x89, 0x8d, 0x63, 0x00, 0x00,
            0x00, 0x00, 0x35, 0xb9, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13,
            0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21,
            0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x00, // Data (extra 1 byte)
        ];
        let ipv4 = IPv4::new(vec![Box::new(TestProtocol {})]);
        let reply = ipv4.reply(&buf);
        assert_eq!(
            reply,
            Err(IPv4Error("total length error: total length=84, len=85".to_string()).into())
        );
    }

    #[test]
    fn more_fragments() {
        let buf = [
            0x45, // Version, IHL
            0x00, // Type of Service
            0x00, 0x14, // Total Length
            0x6d, 0x6f, // Identification
            0x20, 0x00, // Flags (More Fragments), Fragment Offset
            0x40, // Time to Live
            0x01, // Protocol
            0x49, 0x36, // Header Checksum
            0xc0, 0x00, 0x02, 0x01, // Source Address
            0xc0, 0x00, 0x02, 0x01, // Destination Address
        ];
        let ipv4 = IPv4::new(vec![Box::new(TestProtocol {})]);
        let reply = ipv4.reply(&buf);
        assert_eq!(
            reply,
            Err(IPv4Error("fragments unsupported".to_string()).into())
        );
    }

    #[test]
    fn non_zero_fragment_offset() {
        let buf = [
            0x45, // Version, IHL
            0x00, // Type of Service
            0x00, 0x14, // Total Length
            0x6d, 0x6f, // Identification
            0x41, 0x00, // Flags, Fragment Offset (non zero)
            0x40, // Time to Live
            0x01, // Protocol
            0x49, 0x36, // Header Checksum
            0xc0, 0x00, 0x02, 0x01, // Source Address
            0xc0, 0x00, 0x02, 0x01, // Destination Address
        ];
        let ipv4 = IPv4::new(vec![Box::new(TestProtocol {})]);
        let reply = ipv4.reply(&buf);
        assert_eq!(
            reply,
            Err(IPv4Error("fragments unsupported".to_string()).into())
        );

        let buf = [
            0x45, // Version, IHL
            0x00, // Type of Service
            0x00, 0x14, // Total Length
            0x6d, 0x6f, // Identification
            0x40, 0x01, // Flags, Fragment Offset (non zero)
            0x40, // Time to Live
            0x01, // Protocol
            0x49, 0x36, // Header Checksum
            0xc0, 0x00, 0x02, 0x01, // Source Address
            0xc0, 0x00, 0x02, 0x01, // Destination Address
        ];
        let ipv4 = IPv4::new(vec![Box::new(TestProtocol {})]);
        let reply = ipv4.reply(&buf);
        assert_eq!(
            reply,
            Err(IPv4Error("fragments unsupported".to_string()).into())
        );
    }

    #[test]
    fn wrong_header_checksum() {
        let buf = [
            0x45, // Version, IHL
            0x00, // Type of Service
            0x00, 0x14, // Total Length
            0x6d, 0x6f, // Identification
            0x40, 0x00, // Flags, Fragment Offset
            0x40, // Time to Live
            0x01, // Protocol
            0x49, 0x75, // Header Checksum (wrong header checksum)
            0xc0, 0x00, 0x02, 0x01, // Source Address
            0xc0, 0x00, 0x02, 0x02, // Destination Address
        ];
        let ipv4 = IPv4::new(vec![Box::new(TestProtocol {})]);
        let reply = ipv4.reply(&buf);
        assert_eq!(
            reply,
            Err(IPv4Error("header checksum error: header checksum=0x1".to_string()).into()),
        );
    }
}
