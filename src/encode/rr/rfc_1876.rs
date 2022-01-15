use crate::{
    encode::Encoder,
    rr::{Type, LOC},
    EncodeResult,
};

impl Encoder {
    pub(super) fn rr_loc(&mut self, loc: &LOC) -> EncodeResult<()> {
        self.domain_name(&loc.domain_name)?;
        self.rr_type(&Type::LOC);
        self.rr_class(&loc.class);
        self.u32(loc.ttl);
        let length_index = self.create_length_index_u16();
        self.u8(loc.version);
        self.u8(loc.size);
        self.u8(loc.horiz_pre);
        self.u8(loc.vert_pre);
        self.u32(loc.latitube);
        self.u32(loc.longitube);
        self.u32(loc.altitube);
        self.set_length_index_u16(length_index)
    }
}

impl_encode_rr!(LOC, rr_loc);
