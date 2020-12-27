use super::super::Header;
use crate::decode::Decoder;
use crate::rr::edns::{EDNSOption, EDNSOptionCode};
use crate::rr::OPT;
use crate::{DecodeError, DecodeResult};
use std::convert::TryFrom;

fn rr_opt_ttl(ttl: u32) -> DecodeResult<(u8, u8, bool)> {
    let extend_rcode = ((ttl >> 24) & 0xff) as u8;
    let version = ((ttl >> 16) & 0xff) as u8;
    let buffer = ((ttl >> 8) & 0xff) as u8;
    let dnssec = match buffer {
        0 => false,
        1 => true,
        buffer => return Err(DecodeError::OPTZero(buffer)),
    };
    let buffer = (ttl & 0xff) as u8;
    if buffer != 0 {
        return Err(DecodeError::OPTZero(buffer));
    }
    Ok((extend_rcode, version, dnssec))
}

impl<'a, 'b: 'a> Decoder<'b, 'b> {
    fn rr_edns_option(&'a mut self) -> DecodeResult<EDNSOption> {
        let edns_option_code = self.rr_edns_option_code()?;
        let edns_option_length = self.u16()?;
        let mut ends_option_data = self.sub(edns_option_length)?;
        let edns_option = match edns_option_code {
            EDNSOptionCode::ECS => EDNSOption::ECS(ends_option_data.rr_edns_ecs()?),
            EDNSOptionCode::Cookie => EDNSOption::Cookie(ends_option_data.rr_edns_cookie()?),
            EDNSOptionCode::Padding => EDNSOption::Padding(ends_option_data.rr_edns_padding()?),
        };
        ends_option_data.finished()?;
        Ok(edns_option)
    }

    pub(in super::super) fn rr_opt(&'a mut self, header: Header) -> DecodeResult<OPT> {
        if header.domain_name != "." {
            return Err(DecodeError::OPTDomainName(header.domain_name));
        }
        let requestor_payload_size = header.class;
        // TODO
        let (extend_rcode, version, dnssec) = rr_opt_ttl(header.ttl)?;
        let mut edns_options = Vec::new();
        while !self.is_finished()? {
            edns_options.push(self.rr_edns_option()?);
        }
        let opt = OPT {
            requestor_payload_size,
            extend_rcode,
            version,
            dnssec,
            edns_options,
        };
        Ok(opt)
    }
}

impl<'a, 'b: 'a> Decoder<'a, 'b> {
    fn rr_edns_option_code(&mut self) -> DecodeResult<EDNSOptionCode> {
        let buffer = self.u16()?;
        match EDNSOptionCode::try_from(buffer) {
            Ok(ends_option_code) => Ok(ends_option_code),
            Err(buffer) => Err(DecodeError::EDNSOptionCode(buffer)),
        }
    }
}
