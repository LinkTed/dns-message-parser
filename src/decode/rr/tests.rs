use super::Header;
use crate::{DecodeError, DomainName};

#[test]
fn header_get_class_error() {
    let header = Header {
        domain_name: DomainName::default(),
        class: u16::MAX,
        ttl: 1000,
    };
    assert_eq!(header.get_class(), Err(DecodeError::Class(u16::MAX)));
}
