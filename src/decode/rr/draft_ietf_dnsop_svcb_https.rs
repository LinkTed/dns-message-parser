use crate::decode::error::DecodeError::ECHLengthMismatch;
use crate::decode::Decoder;
use crate::rr::{ServiceBinding, ServiceParameter};
use crate::DecodeResult;

use super::Header;
use std::collections::BTreeSet;

impl<'a, 'b: 'a> Decoder<'b, 'b> {
    /// Decode a Service Binding (SVCB or HTTP) resource record
    ///
    /// Preconditions
    /// * The header and question sections should have already been decoded. Specifically, index of
    ///   any previously-identified domain names must already be captured.
    ///
    /// Parameters
    /// - `header` - the header that precedes the question section
    /// - `https` - true for `HTTPS` resource records, false for `SVCB`
    pub(super) fn rr_service_binding(
        &'a mut self,
        header: Header,
        https: bool,
    ) -> DecodeResult<ServiceBinding> {
        let priority = self.u16()?;
        let target_name = self.domain_name()?;
        let mut parameters = BTreeSet::new();
        if priority != 0 {
            while !self.is_finished()? {
                let service_parameter_key = self.u16()?;
                let value_length = self.u16()?;
                let mut parameter_decoder = self.sub(value_length)?;
                let service_parameter =
                    parameter_decoder.rr_service_parameter(service_parameter_key)?;
                parameter_decoder.finished()?;

                parameters.insert(service_parameter);
            }
        }
        Ok(ServiceBinding {
            name: header.domain_name,
            ttl: header.ttl,
            priority,
            target_name,
            parameters,
            https,
        })
    }
}

impl<'a, 'b: 'a> Decoder<'a, 'b> {
    /// Decode a single service parameter
    ///
    /// Parameters:
    /// - `service_parameter_key` - the IANA-controlled numeric identifier as defined in section 14.3 of the RFC
    ///
    /// Returns:
    /// - `Ok(ServiceParameter)` - if there were no issues decoding the value
    /// - `Err` - if there was any decoding error
    fn rr_service_parameter(
        &mut self,
        service_parameter_key: u16,
    ) -> DecodeResult<ServiceParameter> {
        let service_parameter = match service_parameter_key {
            0 => {
                let mut key_ids = vec![];
                while !self.is_finished()? {
                    key_ids.push(self.u16()?);
                }
                ServiceParameter::MANDATORY { key_ids }
            }
            1 => {
                let mut alpn_ids = vec![];
                while !self.is_finished()? {
                    alpn_ids.push(self.string_with_len()?);
                }
                ServiceParameter::ALPN { alpn_ids }
            }
            2 => ServiceParameter::NO_DEFAULT_ALPN,
            3 => ServiceParameter::PORT { port: self.u16()? },
            4 => {
                let mut hints = vec![];
                while !self.is_finished()? {
                    hints.push(self.ipv4_addr()?);
                }
                ServiceParameter::IPV4_HINT { hints }
            }
            5 => {
                // Note the RFC does not explicitly state that the length is two octets
                // "In wire format, the value of the parameter is an ECHConfigList [ECH],
                // including the redundant length prefix." - RFC Section 9
                let length = self.u16()? as usize;
                let config_list = self.vec()?;
                if config_list.len() != length {
                    return Err(ECHLengthMismatch(length, config_list.len()));
                }
                ServiceParameter::ECH { config_list }
            }
            6 => {
                let mut hints = vec![];
                while !self.is_finished()? {
                    hints.push(self.ipv6_addr()?);
                }
                ServiceParameter::IPV6_HINT { hints }
            }
            65535 => ServiceParameter::KEY_65535,
            number => ServiceParameter::PRIVATE {
                number,
                wire_data: self.vec()?,
            },
        };
        Ok(service_parameter)
    }
}
