use dns_message_parser::{DomainName, DomainNameError};
use std::convert::TryFrom;

#[test]
fn label_length_error() {
    let string = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let result = DomainName::try_from(string);
    assert_eq!(result, Err(DomainNameError::LabelLength(string.len())));
}

#[test]
fn domain_name_length_error() {
    let label = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let mut domain_name = DomainName::default();
    for _ in 0..4 {
        domain_name.append_label(label).unwrap();
    }
    let result = domain_name.append_label(label);
    assert_eq!(
        result,
        Err(DomainNameError::DomainNameLength(label.len() * 5 + 4))
    );
}
