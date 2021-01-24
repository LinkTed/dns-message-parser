use bytes::Bytes;
use dns_message_parser::{DecodeError, Dns, DomainName, DomainNameError};

fn decode_msg(msg: &[u8]) -> Dns {
    // Decode BytesMut to message
    let bytes = Bytes::copy_from_slice(&msg[..]);
    // Decode the DNS message
    Dns::decode(bytes).unwrap()
}

#[test]
fn domain_name() {
    let data = b"\x03\x61\x2e\x74\x00";
    let bytes = Bytes::copy_from_slice(&data[..]);
    let error = Err(DecodeError::DomainNameError(DomainNameError::LabelDot));
    assert_eq!(DomainName::decode(bytes), error)
}

#[test]
fn request() {
    let msg = b"\xdb\x1c\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x01\x00\x01";
    let dns = decode_msg(&msg[..]);
    assert_eq!(dns.is_response(), false);
}

#[test]
fn response() {
    let msg = b"\xdb\x1c\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
    \x03\x6f\x72\x67\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x04\x0a\x00\
    \x00\x0a";
    let dns = decode_msg(&msg[..]);
    assert_eq!(dns.is_response(), true);
}
