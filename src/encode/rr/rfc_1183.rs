use crate::encode::Encoder;
use crate::rr::{AFSDBSubtype, ISDNAddress, PSDNAddress, Type, AFSDB, ISDN, SA, X25};
use crate::{EncodeError, EncodeResult};
use num_traits::ToPrimitive;

impl Encoder {
    impl_encode_rr_domain_name_domain_name!(RP, mbox_dname, txt_dname, rr_rp);

    fn rr_afsdb_subtype(&mut self, afsdb_subtype: &AFSDBSubtype) -> EncodeResult<()> {
        if let Some(buffer) = afsdb_subtype.to_u16() {
            self.u16(buffer);
            Ok(())
        } else {
            Err(EncodeError::AFSDBSubtype(afsdb_subtype.clone()))
        }
    }

    pub(super) fn rr_afsdb(&mut self, afsdb: &AFSDB) -> EncodeResult<()> {
        self.domain_name(&afsdb.domain_name)?;
        self.rr_type(&Type::AFSDB)?;
        self.rr_class(&afsdb.class)?;
        self.u32(afsdb.ttl);
        let length_index = self.create_length_index();
        self.rr_afsdb_subtype(&afsdb.subtype)?;
        self.domain_name(&afsdb.hostname)?;
        self.set_length_index(length_index)
    }

    fn rr_x25_psdn_address(&mut self, psdn_address: &PSDNAddress) -> EncodeResult<()> {
        self.string(&psdn_address)
    }

    pub(super) fn rr_x25(&mut self, x25: &X25) -> EncodeResult<()> {
        self.domain_name(&x25.domain_name)?;
        self.rr_type(&Type::X25)?;
        self.rr_class(&x25.class)?;
        self.u32(x25.ttl);
        let length_index = self.create_length_index();
        self.rr_x25_psdn_address(&x25.psdn_address)?;
        self.set_length_index(length_index)
    }

    #[inline]
    fn rr_isdn_address(&mut self, isdn_address: &ISDNAddress) -> EncodeResult<()> {
        self.string(&isdn_address)
    }

    #[inline]
    fn rr_isdn_sa(&mut self, sa: &SA) -> EncodeResult<()> {
        self.string(&sa)
    }

    pub(super) fn rr_isdn(&mut self, isdn: &ISDN) -> EncodeResult<()> {
        self.domain_name(&isdn.domain_name)?;
        self.rr_type(&Type::ISDN)?;
        self.rr_class(&isdn.class)?;
        self.u32(isdn.ttl);
        let length_index = self.create_length_index();
        self.rr_isdn_address(&isdn.isdn_address)?;
        if let Some(sa) = &isdn.sa {
            self.rr_isdn_sa(&sa)?;
        }
        self.set_length_index(length_index)
    }

    impl_encode_rr_u16_domain_name!(RT, preference, intermediate_host, rr_rt);
}

impl_encode_rr!(RP, rr_rp);

impl_encode_rr!(AFSDB, rr_afsdb);

impl_encode_rr!(X25, rr_x25);

impl_encode_rr!(ISDN, rr_isdn);

impl_encode_rr!(RT, rr_rt);
