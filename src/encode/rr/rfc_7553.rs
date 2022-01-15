use crate::{
    encode::Encoder,
    rr::{Type, URI},
    EncodeResult,
};

impl Encoder {
    pub(super) fn rr_uri(&mut self, uri: &URI) -> EncodeResult<()> {
        self.domain_name(&uri.domain_name)?;
        self.rr_type(&Type::URI);
        self.rr_class(&uri.class);
        self.u32(uri.ttl);
        let length_index = self.create_length_index_u16();
        self.u16(uri.priority);
        self.u16(uri.weight);
        self.vec(uri.uri.as_bytes());
        self.set_length_index_u16(length_index)
    }
}

impl_encode_rr!(URI, rr_uri);
