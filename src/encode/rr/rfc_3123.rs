use crate::encode::Encoder;
use crate::rr::{APItem, Class, Type, APL, APL_NEGATION_MASK};
use crate::{EncodeError, EncodeResult};
use std::convert::TryInto;
use std::mem::size_of;

impl Encoder {
    fn set_u8(&mut self, n: u8, index: usize) -> EncodeResult<()> {
        let bytes_len = self.bytes.len();
        if index + size_of::<u8>() - 1 < bytes_len {
            self.bytes[index] = n;
            Ok(())
        } else {
            Err(EncodeError::NotEnoughBytes(bytes_len, index))
        }
    }

    #[inline]
    pub(super) fn set_address_length_index(
        &mut self,
        negation: bool,
        address_length_index: usize,
    ) -> EncodeResult<()> {
        let length = self.bytes.len() - (address_length_index + size_of::<u8>());
        if let Ok(mut length) = length.try_into() {
            if length < APL_NEGATION_MASK {
                if negation {
                    length |= APL_NEGATION_MASK;
                }
                self.set_u8(length, address_length_index)
            } else {
                Err(EncodeError::APLAddressLength(length))
            }
        } else {
            Err(EncodeError::Length(length))
        }
    }

    pub(super) fn rr_apl_apitem(&mut self, apitem: &APItem) -> EncodeResult<()> {
        let address = apitem.get_address();
        let prefix = apitem.get_prefix();
        self.rr_address_family_number(&address.get_address_family_number());
        self.u8(prefix);
        let address_length_index = self.bytes.len();
        self.u8(0);
        self.rr_address_with_prefix(address, prefix);
        self.set_address_length_index(apitem.negation, address_length_index)
    }

    pub(super) fn rr_apl(&mut self, apl: &APL) -> EncodeResult<()> {
        self.domain_name(&apl.domain_name)?;
        self.rr_type(&Type::APL);
        self.rr_class(&Class::IN);
        self.u32(apl.ttl);
        let length_index = self.create_length_index();
        for apitem in &apl.apitems {
            self.rr_apl_apitem(apitem)?;
        }
        self.set_length_index(length_index)
    }
}

#[test]
fn set_address_length_index_error_1() {
    use bytes::BytesMut;
    use std::collections::HashMap;
    let bytes = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
    \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
    \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
    \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
    \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
    \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
    \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
    \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
    \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
    \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
    \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
    \x00\x00\x00\x00\x00\x00\x00";
    let bytes = BytesMut::from(&bytes[..]);
    let mut encoder = Encoder {
        bytes,
        domain_name_index: HashMap::new(),
    };
    assert_eq!(
        encoder.set_address_length_index(false, 0),
        Err(EncodeError::Length(256))
    );
}

#[test]
fn set_address_length_index_error_2() {
    use bytes::BytesMut;
    use std::collections::HashMap;
    let bytes = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
    \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
    \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
    \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
    \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
    \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    let bytes = BytesMut::from(&bytes[..]);
    let mut encoder = Encoder {
        bytes,
        domain_name_index: HashMap::new(),
    };
    assert_eq!(
        encoder.set_address_length_index(false, 0),
        Err(EncodeError::APLAddressLength(128))
    );
}

#[test]
fn set_u8() {
    use bytes::BytesMut;
    use std::collections::HashMap;
    let bytes = b"";
    let bytes = BytesMut::from(&bytes[..]);
    let mut encoder = Encoder {
        bytes,
        domain_name_index: HashMap::new(),
    };
    assert_eq!(
        encoder.set_u8(10, 0),
        Err(EncodeError::NotEnoughBytes(0, 0))
    );
}
