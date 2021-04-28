use crate::decode::Decoder;
use crate::rr::{Class, Type, RR};
use crate::{DecodeError, DecodeResult, DomainName};
use std::convert::TryFrom;

pub(super) struct Header {
    pub(super) domain_name: DomainName,
    pub(super) class: u16,
    pub(super) ttl: u32,
}

impl Header {
    pub(super) fn get_class(&self) -> DecodeResult<Class> {
        match Class::try_from(self.class) {
            Ok(class) => Ok(class),
            Err(buffer) => Err(DecodeError::Class(buffer)),
        }
    }
}

impl<'a, 'b: 'a> Decoder<'b, 'b> {
    fn rr_data(&'a mut self) -> DecodeResult<Decoder<'a, 'b>> {
        let rd_length = self.u16()?;
        let r_data = self.sub(rd_length)?;
        Ok(r_data)
    }

    pub fn rr(&'a mut self) -> DecodeResult<RR> {
        let (type_, header) = self.rr_header()?;
        let mut r_data = self.rr_data()?;
        let rr = match type_ {
            Type::A => RR::A(r_data.rr_a(header)?),
            Type::NS => RR::NS(r_data.rr_ns(header)?),
            Type::MD => RR::MD(r_data.rr_md(header)?),
            Type::MF => RR::MF(r_data.rr_mf(header)?),
            Type::CNAME => RR::CNAME(r_data.rr_cname(header)?),
            Type::SOA => RR::SOA(r_data.rr_soa(header)?),
            Type::MB => RR::MB(r_data.rr_mb(header)?),
            Type::MG => RR::MG(r_data.rr_mg(header)?),
            Type::MR => RR::MR(r_data.rr_mr(header)?),
            Type::NULL => RR::NULL(r_data.rr_null(header)?),
            Type::WKS => RR::WKS(r_data.rr_wks(header)?),
            Type::PTR => RR::PTR(r_data.rr_ptr(header)?),
            Type::HINFO => RR::HINFO(r_data.rr_hinfo(header)?),
            Type::MINFO => RR::MINFO(r_data.rr_minfo(header)?),
            Type::MX => RR::MX(r_data.rr_mx(header)?),
            Type::TXT => RR::TXT(r_data.rr_txt(header)?),
            Type::RP => RR::RP(r_data.rr_rp(header)?),
            Type::AFSDB => RR::AFSDB(r_data.rr_afsdb(header)?),
            Type::X25 => RR::X25(r_data.rr_x25(header)?),
            Type::ISDN => RR::ISDN(r_data.rr_isdn(header)?),
            Type::RT => RR::RT(r_data.rr_rt(header)?),
            Type::NSAP => RR::NSAP(r_data.rr_nsap(header)?),
            Type::GPOS => RR::GPOS(r_data.rr_gpos(header)?),
            Type::LOC => RR::LOC(r_data.rr_loc(header)?),
            Type::PX => RR::PX(r_data.rr_px(header)?),
            Type::KX => RR::KX(r_data.rr_kx(header)?),
            Type::SRV => RR::SRV(r_data.rr_srv(header)?),
            Type::AAAA => RR::AAAA(r_data.rr_aaaa(header)?),
            Type::SSHFP => RR::SSHFP(r_data.rr_sshfp(header)?),
            Type::DNAME => RR::DNAME(r_data.rr_dname(header)?),
            Type::OPT => RR::OPT(r_data.rr_opt(header)?),
            Type::APL => RR::APL(r_data.rr_apl(header)?),
            Type::NID => RR::NID(r_data.rr_nid(header)?),
            Type::L32 => RR::L32(r_data.rr_l32(header)?),
            Type::L64 => RR::L64(r_data.rr_l64(header)?),
            Type::LP => RR::LP(r_data.rr_lp(header)?),
            Type::EUI48 => RR::EUI48(r_data.rr_eui48(header)?),
            Type::EUI64 => RR::EUI64(r_data.rr_eui64(header)?),
            Type::URI => RR::URI(r_data.rr_uri(header)?),
            Type::EID => RR::EID(r_data.rr_eid(header)?),
            Type::NIMLOC => RR::NIMLOC(r_data.rr_nimloc(header)?),
            Type::DNSKEY => RR::DNSKEY(r_data.rr_dnskey(header)?),
            Type::DS => RR::DS(r_data.rr_ds(header)?),
            Type::CAA => RR::CAA(r_data.rr_caa(header)?),
            Type::SVCB => RR::SVCB(r_data.rr_service_binding(header, false)?),
            Type::HTTPS => RR::HTTPS(r_data.rr_service_binding(header, true)?),
            type_ => return Err(DecodeError::NotYetImplemented(type_)),
        };
        r_data.finished()?;
        Ok(rr)
    }
}

impl<'a, 'b: 'a> Decoder<'a, 'b> {
    fn rr_header(&mut self) -> DecodeResult<(Type, Header)> {
        let domain_name = self.domain_name()?;
        let type_ = self.rr_type()?;
        let class = self.u16()?;
        let ttl = self.u32()?;
        let header = Header {
            domain_name,
            class,
            ttl,
        };
        Ok((type_, header))
    }

    pub fn rr_class(&mut self) -> DecodeResult<Class> {
        let buffer = self.u16()?;
        match Class::try_from(buffer) {
            Ok(class) => Ok(class),
            Err(buffer) => Err(DecodeError::Class(buffer)),
        }
    }

    pub fn rr_type(&mut self) -> DecodeResult<Type> {
        let buffer = self.u16()?;
        match Type::try_from(buffer) {
            Ok(type_) => Ok(type_),
            Err(buffer) => Err(DecodeError::Type(buffer)),
        }
    }
}

impl_decode!(Class, rr_class);

impl_decode!(Type, rr_type);

impl_decode!(RR, rr);
