use bytes::Bytes;

use crate::{Class, RData, Type};

use super::{DecodeData, DecodeError, DecodeResult};

impl RData {
    pub fn decode(
        bytes: &Bytes,
        offset: &mut usize,
        type_: &Type,
    ) -> DecodeResult<(Class, u32, RData)> {
        let mut decode_data = DecodeData::new(bytes, offset);
        match type_ {
            Type::A => decode_data.decode_a(),
            Type::NS => decode_data.decode_ns(),
            Type::MD => decode_data.decode_md(),
            Type::MF => decode_data.decode_mf(),
            Type::CNAME => decode_data.decode_cname(),
            Type::SOA => decode_data.decode_soa(),
            Type::MB => decode_data.decode_mb(),
            Type::MG => decode_data.decode_mg(),
            Type::MR => decode_data.decode_mr(),
            Type::NULL => decode_data.decode_null(),
            Type::WKS => decode_data.decode_wks(),
            Type::PTR => decode_data.decode_ptr(),
            Type::HINFO => decode_data.decode_hinfo(),
            Type::MINFO => decode_data.decode_minfo(),
            Type::MX => decode_data.decode_mx(),
            Type::TXT => decode_data.decode_txt(),
            Type::RP => decode_data.decode_rp(),
            Type::AFSDB => decode_data.decode_afsdb(),
            Type::X25 => decode_data.decode_x25(),
            Type::ISDN => decode_data.decode_isdn(),
            Type::RT => decode_data.decode_rt(),
            Type::NSAP => decode_data.decode_nsap(),
            Type::NSAP_PTR => Err(DecodeError::NotYetImplemented),
            Type::SIG => Err(DecodeError::NotYetImplemented),
            Type::KEY => Err(DecodeError::NotYetImplemented),
            Type::PX => decode_data.decode_px(),
            Type::GPOS => decode_data.decode_gpos(),
            Type::AAAA => decode_data.decode_aaaa(),
            Type::LOC => decode_data.decode_loc(),
            Type::NXT => Err(DecodeError::NotYetImplemented),
            Type::EID => decode_data.decode_eid(),
            Type::NIMLOC => decode_data.decode_nimloc(),
            Type::SRV => decode_data.decode_srv(),
            Type::ATMA => Err(DecodeError::NotYetImplemented),
            Type::NAPTR => Err(DecodeError::NotYetImplemented),
            Type::KX => decode_data.decode_kx(),
            Type::DNAME => decode_data.decode_dname(),
            Type::OPT => decode_data.decode_opt(),
            Type::SSHFP => decode_data.decode_sshfp(),
            // TODO Weitermachen
            _ => Err(DecodeError::NotYetImplemented),
        }
    }
}
