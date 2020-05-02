use crate::{AFSDBSubtype, Class, DomainName, RData, SSHFPAlgorithm, SSHFPType};

use num_traits::FromPrimitive;

use super::{
    decode_ipv4_addr, decode_ipv6_addr, decode_string, decode_u16, decode_u32, decode_u8,
    DecodeData, DecodeError, DecodeResult,
};

use std::mem::size_of;

impl<'a> DecodeData<'a> {
    pub(super) fn decode_a(&mut self) -> DecodeResult<(Class, u32, RData)> {
        let (class, ttl, rdlength) = self.decode_generic_rr_header()?;

        if rdlength == size_of::<u8>() * 4 {
            let ipv4_addr = decode_ipv4_addr(self.bytes, self.offset)?;
            Ok((class, ttl, RData::A(ipv4_addr)))
        } else {
            Err(DecodeError::AError)
        }
    }

    pub(super) fn decode_ns(&mut self) -> DecodeResult<(Class, u32, RData)> {
        let (class, ttl, ns_d_name) = self.decode_domain()?;
        Ok((class, ttl, RData::NS(ns_d_name)))
    }

    pub(super) fn decode_md(&mut self) -> DecodeResult<(Class, u32, RData)> {
        let (class, ttl, mad_name) = self.decode_domain()?;
        Ok((class, ttl, RData::MD(mad_name)))
    }

    pub(super) fn decode_mf(&mut self) -> DecodeResult<(Class, u32, RData)> {
        let (class, ttl, mad_name) = self.decode_domain()?;
        Ok((class, ttl, RData::MF(mad_name)))
    }

    pub(super) fn decode_cname(&mut self) -> DecodeResult<(Class, u32, RData)> {
        let (class, ttl, c_name) = self.decode_domain()?;
        Ok((class, ttl, RData::CNAME(c_name)))
    }

    pub(super) fn decode_soa(&mut self) -> DecodeResult<(Class, u32, RData)> {
        let (class, ttl, rdlength) = self.decode_generic_rr_header()?;
        let end = *self.offset + rdlength;

        if rdlength < (size_of::<u32>() * 5 + 2) {
            return Err(DecodeError::SOAError);
        }

        let m_name = DomainName::decode(self.bytes, self.offset)?;

        if end < (*self.offset + size_of::<u32>() * 5 + 1) {
            return Err(DecodeError::SOAError);
        }

        let r_name = DomainName::decode(self.bytes, self.offset)?;

        if end != (*self.offset + size_of::<u32>() * 5) {
            return Err(DecodeError::SOAError);
        }

        let serial = decode_u32(self.bytes, self.offset)?;
        let refresh = decode_u32(self.bytes, self.offset)?;
        let retry = decode_u32(self.bytes, self.offset)?;
        let expire = decode_u32(self.bytes, self.offset)?;
        let min_ttl = decode_u32(self.bytes, self.offset)?;

        Ok((
            class,
            ttl,
            RData::SOA(m_name, r_name, serial, refresh, retry, expire, min_ttl),
        ))
    }

    pub(super) fn decode_mb(&mut self) -> DecodeResult<(Class, u32, RData)> {
        let (class, ttl, mad_name) = self.decode_domain()?;
        Ok((class, ttl, RData::MB(mad_name)))
    }

    pub(super) fn decode_mg(&mut self) -> DecodeResult<(Class, u32, RData)> {
        let (class, ttl, mgm_name) = self.decode_domain()?;
        Ok((class, ttl, RData::MG(mgm_name)))
    }

    pub(super) fn decode_mr(&mut self) -> DecodeResult<(Class, u32, RData)> {
        let (class, ttl, new_name) = self.decode_domain()?;
        Ok((class, ttl, RData::MR(new_name)))
    }

    pub(super) fn decode_null(&mut self) -> DecodeResult<(Class, u32, RData)> {
        let (class, ttl, data) = self.decode_vec()?;
        Ok((class, ttl, RData::NULL(data)))
    }

    pub(super) fn decode_wks(&mut self) -> DecodeResult<(Class, u32, RData)> {
        let (class, ttl, rdlength) = self.decode_generic_rr_header()?;

        if size_of::<u8>() * 5 > rdlength {
            return Err(DecodeError::WKSError);
        }

        let ipv4_addr = decode_ipv4_addr(self.bytes, self.offset)?;

        let protocol = decode_u8(self.bytes, self.offset)?;

        let start = *self.offset;
        *self.offset += rdlength - size_of::<u8>() * 5;

        if let Some(buffer) = self.bytes.get(start..*self.offset) {
            let bit_map = Vec::from(buffer);
            Ok((class, ttl, RData::WKS(ipv4_addr, protocol, bit_map)))
        } else {
            Err(DecodeError::WKSError)
        }
    }

    pub(super) fn decode_ptr(&mut self) -> DecodeResult<(Class, u32, RData)> {
        let (class, ttl, ptr_d_name) = self.decode_domain()?;
        Ok((class, ttl, RData::PTR(ptr_d_name)))
    }

    pub(super) fn decode_hinfo(&mut self) -> DecodeResult<(Class, u32, RData)> {
        let (class, ttl, rdlength) = self.decode_generic_rr_header()?;
        let start = *self.offset;

        if rdlength <= 1 {
            return Err(DecodeError::HINFOError);
        }

        let end = start + rdlength;

        let cpu = decode_string(self.bytes, self.offset)?;

        if end <= *self.offset {
            return Err(DecodeError::HINFOError);
        }

        let os = decode_string(self.bytes, self.offset)?;

        if end == *self.offset {
            Ok((class, ttl, RData::HINFO(cpu, os)))
        } else {
            Err(DecodeError::HINFOError)
        }
    }

    pub(super) fn decode_minfo(&mut self) -> DecodeResult<(Class, u32, RData)> {
        let (class, ttl, (r_mail_bx, e_mail_bx)) = self.decode_domain_domain()?;
        Ok((class, ttl, RData::MINFO(r_mail_bx, e_mail_bx)))
    }

    pub(super) fn decode_mx(&mut self) -> DecodeResult<(Class, u32, RData)> {
        let (class, ttl, (preference, exchange)) = self.decode_u16_domain()?;
        Ok((class, ttl, RData::MX(preference, exchange)))
    }

    pub(super) fn decode_txt(&mut self) -> DecodeResult<(Class, u32, RData)> {
        let (class, ttl, string) = self.decode_string()?;
        Ok((class, ttl, RData::TXT(string)))
    }

    pub(super) fn decode_rp(&mut self) -> DecodeResult<(Class, u32, RData)> {
        let (class, ttl, (mbox_dname, txt_dname)) = self.decode_domain_domain()?;
        Ok((class, ttl, RData::RP(mbox_dname, txt_dname)))
    }

    pub(super) fn decode_afsdb(&mut self) -> DecodeResult<(Class, u32, RData)> {
        let (class, ttl, rdlength) = self.decode_generic_rr_header()?;
        let start = *self.offset;

        if size_of::<u16>() + 1 > rdlength {
            return Err(DecodeError::AFSDBError);
        }

        let subtype = decode_u16(self.bytes, self.offset)?;
        if let Some(subtype) = AFSDBSubtype::from_u16(subtype) {
            let hostname = DomainName::decode(self.bytes, self.offset)?;

            if *self.offset == (start + rdlength) {
                Ok((class, ttl, RData::AFSDB(subtype, hostname)))
            } else {
                Err(DecodeError::AFSDBError)
            }
        } else {
            Err(DecodeError::AFSDBError)
        }
    }

    pub(super) fn decode_x25(&mut self) -> DecodeResult<(Class, u32, RData)> {
        let (class, ttl, psdn_address) = self.decode_string()?;

        // TODO check hex
        if psdn_address.is_empty() {
            return Err(DecodeError::X25Error);
        }

        Ok((class, ttl, RData::X25(psdn_address)))
    }

    pub(super) fn decode_isdn(&mut self) -> DecodeResult<(Class, u32, RData)> {
        let (class, ttl, rdlength) = self.decode_generic_rr_header()?;
        let start = *self.offset;

        if 2 > rdlength {
            return Err(DecodeError::ISDNError);
        }
        // TODO check hex
        let isdn_address = decode_string(self.bytes, self.offset)?;

        let sa = if *self.offset < (start + rdlength) {
            // TODO check hex
            Some(decode_string(self.bytes, self.offset)?)
        } else {
            None
        };

        if *self.offset == (start + rdlength) {
            Ok((class, ttl, RData::ISDN(isdn_address, sa)))
        } else {
            Err(DecodeError::ISDNError)
        }
    }

    pub(super) fn decode_rt(&mut self) -> DecodeResult<(Class, u32, RData)> {
        let (class, ttl, (preference, intermediate_host)) = self.decode_u16_domain()?;
        Ok((class, ttl, RData::RT(preference, intermediate_host)))
    }

    pub(super) fn decode_nsap(&mut self) -> DecodeResult<(Class, u32, RData)> {
        let (class, ttl, data) = self.decode_vec()?;

        if class != Class::IN {
            return Err(DecodeError::NSAPError);
        }

        if data.is_empty() {
            return Err(DecodeError::NSAPError);
        }

        Ok((class, ttl, RData::NSAP(data)))
    }

    pub(super) fn decode_px(&mut self) -> DecodeResult<(Class, u32, RData)> {
        let (class, ttl, rdlength) = self.decode_generic_rr_header()?;
        let start = *self.offset;

        if size_of::<u16>() + 2 > rdlength {
            return Err(DecodeError::PXError);
        }

        let preference = decode_u16(self.bytes, self.offset)?;

        let map822 = DomainName::decode(self.bytes, self.offset)?;

        if *self.offset > (start + rdlength) {
            return Err(DecodeError::PXError);
        }

        let mapx400 = DomainName::decode(self.bytes, self.offset)?;

        if *self.offset == (start + rdlength) {
            Ok((class, ttl, RData::PX(preference, map822, mapx400)))
        } else {
            Err(DecodeError::PXError)
        }
    }

    pub(super) fn decode_gpos(&mut self) -> DecodeResult<(Class, u32, RData)> {
        let (class, ttl, rdlength) = self.decode_generic_rr_header()?;
        let start = *self.offset;

        if 6 > rdlength {
            return Err(DecodeError::GPOSError);
        }

        // TODO String value check

        let longitude = decode_string(self.bytes, self.offset)?;
        let longitude_len = longitude.len();
        if longitude_len > 256 || 1 > longitude_len {
            return Err(DecodeError::GPOSError);
        }

        if *self.offset > (start + rdlength) {
            return Err(DecodeError::GPOSError);
        }

        let latitude = decode_string(self.bytes, self.offset)?;
        let latitude_len = latitude.len();
        if latitude_len > 256 || 1 > latitude_len {
            return Err(DecodeError::GPOSError);
        }

        if *self.offset > (start + rdlength) {
            return Err(DecodeError::GPOSError);
        }

        let altitude = decode_string(self.bytes, self.offset)?;
        let altitude_len = altitude.len();
        if altitude_len > 256 || 1 > altitude_len {
            return Err(DecodeError::GPOSError);
        }

        if *self.offset == (start + rdlength) {
            Ok((class, ttl, RData::GPOS(longitude, latitude, altitude)))
        } else {
            Err(DecodeError::GPOSError)
        }
    }

    pub(super) fn decode_aaaa(&mut self) -> DecodeResult<(Class, u32, RData)> {
        let (class, ttl, rdlength) = self.decode_generic_rr_header()?;

        if rdlength == size_of::<u16>() * 8 {
            let ipv6_addr = decode_ipv6_addr(self.bytes, self.offset)?;
            Ok((class, ttl, RData::AAAA(ipv6_addr)))
        } else {
            Err(DecodeError::AAAAError)
        }
    }

    pub(super) fn decode_loc(&mut self) -> DecodeResult<(Class, u32, RData)> {
        let (class, ttl, rdlength) = self.decode_generic_rr_header()?;

        if size_of::<u8>() * 4 + size_of::<u32>() * 3 != rdlength {
            return Err(DecodeError::LOCError);
        }

        let version = decode_u8(self.bytes, self.offset)?;
        let size = decode_u8(self.bytes, self.offset)?;
        let horiz_pre = decode_u8(self.bytes, self.offset)?;
        let vert_pre = decode_u8(self.bytes, self.offset)?;

        let latitube = decode_u32(self.bytes, self.offset)?;
        let longitube = decode_u32(self.bytes, self.offset)?;
        let altitube = decode_u32(self.bytes, self.offset)?;

        Ok((
            class,
            ttl,
            RData::LOC(
                version, size, horiz_pre, vert_pre, latitube, longitube, altitube,
            ),
        ))
    }

    pub(super) fn decode_eid(&mut self) -> DecodeResult<(Class, u32, RData)> {
        let (class, ttl, data) = self.decode_vec()?;

        if data.is_empty() {
            return Err(DecodeError::EIDError);
        }

        Ok((class, ttl, RData::EID(data)))
    }

    pub(super) fn decode_nimloc(&mut self) -> DecodeResult<(Class, u32, RData)> {
        let (class, ttl, data) = self.decode_vec()?;

        if data.is_empty() {
            return Err(DecodeError::NIMLOCError);
        }

        Ok((class, ttl, RData::NIMLOC(data)))
    }

    pub(super) fn decode_srv(&mut self) -> DecodeResult<(Class, u32, RData)> {
        let (class, ttl, rdlength) = self.decode_generic_rr_header()?;
        let start = *self.offset;

        if size_of::<u16>() * 3 + 1 > rdlength {
            return Err(DecodeError::SRVError);
        }

        let priority = decode_u16(self.bytes, self.offset)?;
        let weight = decode_u16(self.bytes, self.offset)?;
        let port = decode_u16(self.bytes, self.offset)?;
        let target = DomainName::decode(self.bytes, self.offset)?;

        if *self.offset == (start + rdlength) {
            Ok((class, ttl, RData::SRV(priority, weight, port, target)))
        } else {
            Err(DecodeError::SRVError)
        }
    }

    pub(super) fn decode_kx(&mut self) -> DecodeResult<(Class, u32, RData)> {
        let (class, ttl, (preference, exchanger)) = self.decode_u16_domain()?;
        Ok((class, ttl, RData::KX(preference, exchanger)))
    }

    pub(super) fn decode_dname(&mut self) -> DecodeResult<(Class, u32, RData)> {
        let (class, ttl, target) = self.decode_domain()?;
        Ok((class, ttl, RData::DNAME(target)))
    }

    pub(super) fn decode_opt(&mut self) -> DecodeResult<(Class, u32, RData)> {
        let _payload_size = decode_u16(self.bytes, self.offset)?;
        let _flags = decode_u32(self.bytes, self.offset)?;
        let rdlength = decode_u16(self.bytes, self.offset)? as usize;
        *self.offset += rdlength;
        // TODO
        Ok((Class::NONE, 0, RData::OPT))
    }

    pub(super) fn decode_sshfp(&mut self) -> DecodeResult<(Class, u32, RData)> {
        let (class, ttl, rdlength) = self.decode_generic_rr_header()?;
        let start = *self.offset;

        if size_of::<u8>() * 2 + 1 > rdlength {
            return Err(DecodeError::SSHFPError);
        }

        let algorithm = decode_u8(self.bytes, self.offset)?;
        let algorithm = if let Some(algorithm) = SSHFPAlgorithm::from_u8(algorithm) {
            algorithm
        } else {
            return Err(DecodeError::SSHFPError);
        };

        let type_ = decode_u8(self.bytes, self.offset)?;
        let type_ = if let Some(type_) = SSHFPType::from_u8(type_) {
            type_
        } else {
            return Err(DecodeError::SSHFPError);
        };

        if let Some(buffer) = self.bytes.get(start..*self.offset) {
            Ok((
                class,
                ttl,
                RData::SSHFP(algorithm, type_, Vec::from(buffer)),
            ))
        } else {
            Err(DecodeError::SSHFPError)
        }
    }
}
