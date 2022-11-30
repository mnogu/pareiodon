pub trait Protocol {
    fn reply(&self, buf: &[u8]) -> Option<Vec<u8>>;
}
