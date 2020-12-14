use crate::{EncodeError, EncodeResult};
use bytes::BytesMut;
use std::collections::HashMap;
use std::convert::TryInto;

pub(crate) struct Encoder {
    pub bytes: BytesMut,
    pub domain_name_index: HashMap<String, (u16, usize)>,
}

impl Encoder {
    #[inline]
    pub(super) fn get_offset(&self) -> EncodeResult<u16> {
        let bytes_len = self.bytes.len();
        if let Ok(offset) = bytes_len.try_into() {
            Ok(offset)
        } else {
            Err(EncodeError::Length(bytes_len))
        }
    }
}

impl Default for Encoder {
    fn default() -> Self {
        Encoder {
            bytes: BytesMut::new(),
            domain_name_index: HashMap::new(),
        }
    }
}
