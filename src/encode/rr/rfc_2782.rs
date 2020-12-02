use crate::encode::Encoder;
use crate::rr::{Type, SRV};
use crate::EncodeResult;

impl Encoder {
    pub(super) fn rr_srv(&mut self, srv: &SRV) -> EncodeResult<()> {
        self.domain_name(&srv.domain_name)?;
        self.rr_type(&Type::SRV)?;
        self.rr_class(&srv.class)?;
        self.u32(srv.ttl);
        let length_index = self.create_length_index();
        self.u16(srv.priority);
        self.u16(srv.weight);
        self.u16(srv.port);
        self.domain_name(&srv.target)?;
        self.set_length_index(length_index)
    }
}

impl_encode_rr!(SRV, rr_srv);
