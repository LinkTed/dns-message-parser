use dns_message_parser::{DomainName, DomainNameError, Label, LabelError};

#[test]
fn label_length_error() {
    let string = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let result: Result<DomainName, DomainNameError> = string.parse();
    assert_eq!(
        result,
        Err(DomainNameError::LabelError(LabelError::Length(
            string.len()
        )))
    );
}

#[test]
fn label_empty_error() {
    let string = "";
    let result: Result<DomainName, DomainNameError> = string.parse();
    assert_eq!(result, Err(DomainNameError::LabelError(LabelError::Empty)));
}

#[test]
fn domain_name_length_error() {
    let label: Label = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        .parse()
        .unwrap();
    let mut domain_name = DomainName::default();
    for _ in 0..3 {
        domain_name.append_label(label.clone()).unwrap();
    }
    let result = domain_name.append_label(label.clone());
    assert_eq!(
        result,
        Err(DomainNameError::DomainNameLength(label.len() * 4 + 4))
    );
}
