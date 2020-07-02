use crate::{AFSDBSubtype, DomainName, SSHFPAlgorithm, SSHFPType, Type};

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use super::{
    encode_ipv4_addr, encode_ipv6_addr, encode_string, encode_u16, encode_u32, encode_u8,
    EncodeData, EncodeResult,
};

impl<'a> EncodeData<'a> {
    pub(super) fn encode_a(&mut self, ipv4_addr: &Ipv4Addr) -> EncodeResult {
        self.encode_generic_rr_header(Type::A)?;
        encode_ipv4_addr(&mut self.bytes_rdata, ipv4_addr);
        Ok(())
    }

    pub(super) fn encode_ns(
        &mut self,
        ns_d_name: &DomainName,
        compression: &mut HashMap<String, usize>,
    ) -> EncodeResult {
        self.encode_domain(Type::NS, ns_d_name, compression)
    }

    pub(super) fn encode_md(
        &mut self,
        mad_name: &DomainName,
        compression: &mut HashMap<String, usize>,
    ) -> EncodeResult {
        self.encode_domain(Type::MD, mad_name, compression)
    }

    pub(super) fn encode_mf(
        &mut self,
        mad_name: &DomainName,
        compression: &mut HashMap<String, usize>,
    ) -> EncodeResult {
        self.encode_domain(Type::MF, mad_name, compression)
    }

    pub(super) fn encode_cname(
        &mut self,
        c_name: &DomainName,
        compression: &mut HashMap<String, usize>,
    ) -> EncodeResult {
        self.encode_domain(Type::CNAME, c_name, compression)
    }

    pub(super) fn encode_soa(
        &mut self,
        m_name: &DomainName,
        r_name: &DomainName,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        min_ttl: u32,
        compression: &mut HashMap<String, usize>,
    ) -> EncodeResult {
        self.encode_generic_rr_header(Type::SOA)?;
        let offset = self.get_offset();
        m_name.encode(&mut self.bytes_rdata, &offset, compression)?;
        r_name.encode(&mut self.bytes_rdata, &offset, compression)?;
        encode_u32(&mut self.bytes_rdata, serial);
        encode_u32(&mut self.bytes_rdata, refresh);
        encode_u32(&mut self.bytes_rdata, retry);
        encode_u32(&mut self.bytes_rdata, expire);
        encode_u32(&mut self.bytes_rdata, min_ttl);
        Ok(())
    }

    pub(super) fn encode_mb(
        &mut self,
        mad_name: &DomainName,
        compression: &mut HashMap<String, usize>,
    ) -> EncodeResult {
        self.encode_domain(Type::MB, mad_name, compression)
    }

    pub(super) fn encode_mg(
        &mut self,
        mgm_name: &DomainName,
        compression: &mut HashMap<String, usize>,
    ) -> EncodeResult {
        self.encode_domain(Type::MG, mgm_name, compression)
    }

    pub(super) fn encode_mr(
        &mut self,
        new_name: &DomainName,
        compression: &mut HashMap<String, usize>,
    ) -> EncodeResult {
        self.encode_domain(Type::MR, new_name, compression)
    }

    pub(super) fn encode_null(&mut self, vec: &[u8]) -> EncodeResult {
        self.encode_vec(Type::NULL, vec)
    }

    pub(super) fn encode_wks(
        &mut self,
        ipv4_addr: &Ipv4Addr,
        protocol: u8,
        bit_map: &[u8],
    ) -> EncodeResult {
        self.encode_generic_rr_header(Type::WKS)?;
        encode_ipv4_addr(&mut self.bytes_rdata, ipv4_addr);
        encode_u8(&mut self.bytes_rdata, protocol);
        self.bytes_rdata.extend(bit_map);
        Ok(())
    }

    pub(super) fn encode_ptr(
        &mut self,
        ptr_d_name: &DomainName,
        compression: &mut HashMap<String, usize>,
    ) -> EncodeResult {
        self.encode_domain(Type::PTR, ptr_d_name, compression)
    }

    pub(super) fn encode_hinfo(&mut self, cpu: &str, os: &str) -> EncodeResult {
        self.encode_generic_rr_header(Type::HINFO)?;
        encode_string(&mut self.bytes_rdata, cpu)?;
        encode_string(&mut self.bytes_rdata, os)
    }

    pub(super) fn encode_minfo(
        &mut self,
        r_mail_bx: &DomainName,
        e_mail_bx: &DomainName,
        compression: &mut HashMap<String, usize>,
    ) -> EncodeResult {
        self.encode_domain_domain(Type::MINFO, r_mail_bx, e_mail_bx, compression)
    }

    pub(super) fn encode_mx(
        &mut self,
        preference: u16,
        exchange: &DomainName,
        compression: &mut HashMap<String, usize>,
    ) -> EncodeResult {
        self.encode_u16_domain(Type::MX, preference, exchange, compression)
    }

    pub(super) fn encode_txt(&mut self, string: &str) -> EncodeResult {
        self.encode_string(Type::TXT, string)
    }

    pub(super) fn encode_rp(
        &mut self,
        mbox_dname: &DomainName,
        txt_dname: &DomainName,
        compression: &mut HashMap<String, usize>,
    ) -> EncodeResult {
        self.encode_domain_domain(Type::RP, mbox_dname, txt_dname, compression)
    }

    pub(super) fn encode_afsdb(
        &mut self,
        subtype: &AFSDBSubtype,
        hostname: &DomainName,
        compression: &mut HashMap<String, usize>,
    ) -> EncodeResult {
        self.encode_generic_rr_header(Type::AFSDB)?;
        subtype.encode(&mut self.bytes_rdata)?;
        let offset = self.get_offset();
        hostname.encode(&mut self.bytes_rdata, &offset, compression)
    }

    pub(super) fn encode_x25(&mut self, psdn_address: &str) -> EncodeResult {
        self.encode_string(Type::X25, psdn_address)
    }

    pub(super) fn encode_isdn(&mut self, isdn_address: &str, sa: &Option<String>) -> EncodeResult {
        self.encode_generic_rr_header(Type::ISDN)?;
        encode_string(&mut self.bytes_rdata, isdn_address)?;
        if let Some(sa) = sa {
            encode_string(&mut self.bytes_rdata, sa)
        } else {
            Ok(())
        }
    }

    pub(super) fn encode_rt(
        &mut self,
        preference: u16,
        intermediate_host: &DomainName,
        compression: &mut HashMap<String, usize>,
    ) -> EncodeResult {
        self.encode_u16_domain(Type::RT, preference, intermediate_host, compression)
    }

    pub(super) fn encode_nsap(&mut self, nsap: &[u8]) -> EncodeResult {
        self.encode_vec(Type::NSAP, nsap)
    }

    pub(super) fn encode_px(
        &mut self,
        preference: u16,
        map_822: &DomainName,
        map_x_400: &DomainName,
        compression: &mut HashMap<String, usize>,
    ) -> EncodeResult {
        self.encode_generic_rr_header(Type::PX)?;
        let offset = self.get_offset();
        encode_u16(&mut self.bytes_rdata, preference);
        map_822.encode(&mut self.bytes_rdata, &offset, compression)?;
        map_x_400.encode(&mut self.bytes_rdata, &offset, compression)
    }

    pub(super) fn encode_gpos(
        &mut self,
        longitude: &str,
        latitude: &str,
        altitude: &str,
    ) -> EncodeResult {
        self.encode_generic_rr_header(Type::GPOS)?;
        encode_string(&mut self.bytes_rdata, longitude)?;
        encode_string(&mut self.bytes_rdata, latitude)?;
        encode_string(&mut self.bytes_rdata, altitude)
    }

    pub(super) fn encode_aaaa(&mut self, ipv6_addr: &Ipv6Addr) -> EncodeResult {
        self.encode_generic_rr_header(Type::AAAA)?;
        encode_ipv6_addr(&mut self.bytes_rdata, ipv6_addr);
        Ok(())
    }

    pub(super) fn encode_loc(
        &mut self,
        version: u8,
        size: u8,
        horiz_pre: u8,
        vert_pre: u8,
        latitube: u32,
        longitube: u32,
        altitube: u32,
    ) -> EncodeResult {
        self.encode_generic_rr_header(Type::LOC)?;
        encode_u8(&mut self.bytes_rdata, version);
        encode_u8(&mut self.bytes_rdata, size);
        encode_u8(&mut self.bytes_rdata, horiz_pre);
        encode_u8(&mut self.bytes_rdata, vert_pre);
        encode_u32(&mut self.bytes_rdata, latitube);
        encode_u32(&mut self.bytes_rdata, longitube);
        encode_u32(&mut self.bytes_rdata, altitube);
        Ok(())
    }

    pub(super) fn encode_eid(&mut self, endpoint_identifier: &[u8]) -> EncodeResult {
        self.encode_vec(Type::EID, endpoint_identifier)
    }

    pub(super) fn encode_nimloc(&mut self, nimrod_locator: &[u8]) -> EncodeResult {
        self.encode_vec(Type::NIMLOC, nimrod_locator)
    }

    pub(super) fn encode_srv(
        &mut self,
        priority: u16,
        weight: u16,
        port: u16,
        target: &DomainName,
        compression: &mut HashMap<String, usize>,
    ) -> EncodeResult {
        self.encode_generic_rr_header(Type::SRV)?;
        let offset = self.get_offset();
        encode_u16(&mut self.bytes_rdata, priority);
        encode_u16(&mut self.bytes_rdata, weight);
        encode_u16(&mut self.bytes_rdata, port);
        target.encode(&mut self.bytes_rdata, &offset, compression)
    }

    pub(super) fn encode_kx(
        &mut self,
        preference: u16,
        exchanger: &DomainName,
        compression: &mut HashMap<String, usize>,
    ) -> EncodeResult {
        self.encode_u16_domain(Type::KX, preference, exchanger, compression)
    }

    pub(super) fn encode_dname(
        &mut self,
        target: &DomainName,
        compression: &mut HashMap<String, usize>,
    ) -> EncodeResult {
        self.encode_domain(Type::DNAME, target, compression)
    }

    pub(super) fn encode_opt(
        &mut self,
        requestor_payload_size: u16,
        version: u8,
        dnssec: bool,
        rdata: &[u8],
    ) -> EncodeResult {
        // TODO rfc6891
        Type::OPT.encode(self.bytes)?;
        encode_u16(self.bytes, requestor_payload_size);
        encode_u8(self.bytes, 0);
        encode_u8(self.bytes, version);
        encode_u8(self.bytes, dnssec as u8);
        encode_u8(self.bytes, 0);
        self.bytes_rdata.extend(rdata);
        Ok(())
    }

    pub(super) fn encode_sshfp(
        &mut self,
        algorihtm: &SSHFPAlgorithm,
        type_: &SSHFPType,
        fingerprint: &[u8],
    ) -> EncodeResult {
        self.encode_generic_rr_header(Type::SSHFP)?;
        algorihtm.encode(&mut self.bytes_rdata)?;
        type_.encode(&mut self.bytes_rdata)?;
        self.bytes_rdata.extend(fingerprint);
        Ok(())
    }
}
