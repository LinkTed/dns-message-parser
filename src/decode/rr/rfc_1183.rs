use super::Header;
use crate::decode::Decoder;
use crate::rr::{AFSDBSubtype, ISDNAddress, PSDNAddress, AFSDB, ISDN, SA, X25};
use crate::{DecodeError, DecodeResult};
use num_traits::FromPrimitive;
use std::convert::TryFrom;

impl<'a, 'b: 'a> Decoder<'a, 'b> {
    impl_decode_rr_domain_name_domain_name!(RP, mbox_dname, txt_dname, rr_rp);

    fn rr_afsdb_subtype(&mut self) -> DecodeResult<AFSDBSubtype> {
        let buffer = self.u16()?;
        if let Some(afs_db_subtype) = AFSDBSubtype::from_u16(buffer) {
            Ok(afs_db_subtype)
        } else {
            Err(DecodeError::AFSDBSubtypeError(buffer))
        }
    }

    pub(super) fn rr_afsdb(&mut self, header: Header) -> DecodeResult<AFSDB> {
        let class = header.get_class()?;
        let subtype = self.rr_afsdb_subtype()?;
        let hostname = self.domain_name()?;
        let afs_db = AFSDB {
            domain_name: header.domain_name,
            ttl: header.ttl,
            class,
            subtype,
            hostname,
        };
        Ok(afs_db)
    }

    pub(super) fn rr_x25(&mut self, header: Header) -> DecodeResult<X25> {
        let class = header.get_class()?;
        let psdn_address = self.string()?;
        let psdn_address = PSDNAddress::try_from(psdn_address)?;

        let x25 = X25 {
            domain_name: header.domain_name,
            ttl: header.ttl,
            class,
            psdn_address,
        };
        Ok(x25)
    }

    pub(super) fn rr_isdn(&mut self, header: Header) -> DecodeResult<ISDN> {
        let class = header.get_class()?;
        let isdn_address = self.string()?;
        let isdn_address = ISDNAddress::try_from(isdn_address)?;

        let sa = if self.is_finished()? {
            None
        } else {
            let sa = self.string()?;
            let sa = SA::try_from(sa)?;
            Some(sa)
        };

        let isdn = ISDN {
            domain_name: header.domain_name,
            ttl: header.ttl,
            class,
            isdn_address,
            sa,
        };
        Ok(isdn)
    }

    impl_decode_rr_u16_domain_name!(RT, preference, intermediate_host, rr_rt);
}
