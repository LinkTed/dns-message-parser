mod encode;
use encode::EncodeData;

mod r_data;

use bytes::BytesMut;

use crate::RR;

use std::collections::HashMap;

use super::{encode_ipv4_addr, encode_ipv6_addr, encode_string, encode_u16, encode_u32, encode_u8};
use super::{EncodeError, EncodeResult};

impl RR {
    pub fn encode(
        &self,
        bytes: &mut BytesMut,
        compression: &mut HashMap<String, usize>,
    ) -> EncodeResult {
        let offset = 0;
        self.domain_name.encode(bytes, &offset, compression)?;
        self.rdata
            .encode(bytes, &self.class, self.ttl, compression)?;

        Ok(())
    }
}
