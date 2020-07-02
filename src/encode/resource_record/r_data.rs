use bytes::BytesMut;

use crate::{Class, RData};

use super::{EncodeData, EncodeError, EncodeResult};

use std::collections::HashMap;

impl RData {
    pub fn encode(
        &self,
        bytes: &mut BytesMut,
        class: &Class,
        ttl: u32,
        compression: &mut HashMap<String, usize>,
    ) -> EncodeResult {
        let mut encode_data = EncodeData::new(bytes, class, ttl);
        match self {
            RData::A(ipv4_addr) => encode_data.encode_a(ipv4_addr)?,
            RData::NS(ns_d_name) => encode_data.encode_ns(ns_d_name, compression)?,
            RData::MD(mad_name) => encode_data.encode_md(mad_name, compression)?,
            RData::MF(mad_name) => encode_data.encode_mf(mad_name, compression)?,
            RData::CNAME(c_name) => encode_data.encode_cname(c_name, compression)?,
            RData::SOA(m_name, r_name, serial, refresh, retry, expire, min_ttl) => encode_data
                .encode_soa(
                    m_name,
                    r_name,
                    *serial,
                    *refresh,
                    *retry,
                    *expire,
                    *min_ttl,
                    compression,
                )?,
            RData::MB(mad_name) => encode_data.encode_mb(mad_name, compression)?,
            RData::MG(mgm_name) => encode_data.encode_mg(mgm_name, compression)?,
            RData::MR(new_name) => encode_data.encode_mr(new_name, compression)?,
            RData::NULL(vec) => encode_data.encode_null(vec)?,
            RData::WKS(ipv4_addr, protocol, bit_map) => {
                encode_data.encode_wks(ipv4_addr, *protocol, bit_map)?
            }
            RData::PTR(ptr_d_name) => encode_data.encode_ptr(ptr_d_name, compression)?,
            RData::HINFO(cpu, os) => encode_data.encode_hinfo(cpu, os)?,
            RData::MINFO(r_mail_bx, e_mail_bx) => {
                encode_data.encode_minfo(r_mail_bx, e_mail_bx, compression)?
            }
            RData::MX(preference, exchange) => {
                encode_data.encode_mx(*preference, exchange, compression)?
            }
            RData::TXT(string) => encode_data.encode_txt(string)?,
            RData::RP(mbox_dname, txt_dname) => {
                encode_data.encode_rp(mbox_dname, txt_dname, compression)?
            }
            RData::AFSDB(subtype, hostname) => {
                encode_data.encode_afsdb(subtype, hostname, compression)?
            }
            RData::X25(psdn_address) => encode_data.encode_x25(psdn_address)?,
            RData::ISDN(isdn_address, sa) => encode_data.encode_isdn(isdn_address, sa)?,
            RData::RT(preference, intermediate_host) => {
                encode_data.encode_rt(*preference, intermediate_host, compression)?
            }
            RData::NSAP(nsap) => encode_data.encode_nsap(nsap)?,
            // TODO NSAP-PTR
            // TODO SIG
            // TODO KEY
            RData::PX(preference, map_822, map_x_400) => {
                encode_data.encode_px(*preference, map_822, map_x_400, compression)?
            }
            RData::GPOS(longitude, latitude, altitude) => {
                encode_data.encode_gpos(longitude, latitude, altitude)?
            }
            RData::AAAA(ipv6_addr) => encode_data.encode_aaaa(ipv6_addr)?,
            RData::LOC(version, size, horiz_pre, vert_pre, latitube, longitube, altitube) => {
                encode_data.encode_loc(
                    *version, *size, *horiz_pre, *vert_pre, *latitube, *longitube, *altitube,
                )?
            }
            // TODO NXT
            RData::EID(endpoint_identifier) => encode_data.encode_eid(endpoint_identifier)?,
            RData::NIMLOC(nimrod_locator) => encode_data.encode_nimloc(nimrod_locator)?,
            RData::SRV(priority, weight, port, target) => {
                encode_data.encode_srv(*priority, *weight, *port, target, compression)?
            }
            // TODO ATMA
            // TODO NAPTR
            RData::KX(preference, exchanger) => {
                encode_data.encode_kx(*preference, exchanger, compression)?
            }
            // TODO CERT
            // TODO A6
            RData::DNAME(target) => encode_data.encode_dname(target, compression)?,
            // TODO SINK
            RData::OPT(requestor_payload_size, version, dnssec, rdata) => {
                encode_data.encode_opt(*requestor_payload_size, *version, *dnssec, rdata)?
            }
            // TODO APL
            // TODO DS
            RData::SSHFP(algorithm, type_, fingerprint) => {
                encode_data.encode_sshfp(algorithm, type_, fingerprint)?
            }
            // TODO IPSECKEY
            // TODO
            RData::URI(priority, weight, uri) => encode_data.encode_uri(*priority, *weight, uri)?,
            // TODO
            _ => return Err(EncodeError::NotYetImplemented),
        }

        encode_data.add_rdata()
    }
}
