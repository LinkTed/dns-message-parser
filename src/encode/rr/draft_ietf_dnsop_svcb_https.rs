use crate::encode::Encoder;
use crate::rr::{Class, ServiceBinding, ServiceBindingMode, ServiceParameter, Type};
use crate::{EncodeError, EncodeResult};

impl Encoder {
    /// Encode a service binding (SVCB or HTTPS) resource record
    pub(super) fn rr_service_binding(
        &mut self,
        service_binding: &ServiceBinding,
    ) -> EncodeResult<()> {
        let rr_type = if service_binding.https {
            &Type::HTTPS
        } else {
            &Type::SVCB
        };
        self.domain_name(&service_binding.name)?;
        self.rr_type(rr_type);
        self.rr_class(&Class::IN);
        self.u32(service_binding.ttl);

        // RDATA wire format: RFC section 2.2
        let length_index = self.create_length_index();
        self.u16(service_binding.priority);
        self.domain_name(&service_binding.target_name)?;
        if service_binding.mode() == ServiceBindingMode::Service {
            for parameter in &service_binding.parameters {
                self.rr_service_parameter(parameter)?;
            }
        }
        self.set_length_index(length_index)
    }

    /// Encode a single service parameter
    fn rr_service_parameter(&mut self, parameter: &ServiceParameter) -> EncodeResult<()> {
        self.u16(parameter.get_registered_number());
        let length_index = self.create_length_index();
        match parameter {
            ServiceParameter::MANDATORY { key_ids } => {
                let mut key_ids = key_ids.clone();
                key_ids.sort_unstable();
                for key_id in key_ids {
                    self.u16(key_id);
                }
            }
            ServiceParameter::ALPN { alpn_ids } => {
                for alpn_id in alpn_ids {
                    self.string_with_len(alpn_id)?;
                }
            }
            ServiceParameter::NO_DEFAULT_ALPN => {}
            ServiceParameter::PORT { port } => {
                self.u16(*port);
            }
            ServiceParameter::IPV4_HINT { hints } => {
                for hint in hints {
                    self.ipv4_addr(hint);
                }
            }
            ServiceParameter::ECH { config_list } => {
                if config_list.len() > u16::MAX as usize {
                    return Err(EncodeError::Length(config_list.len()));
                }
                // Note the RFC does not explicitly state that the length is two octets
                // "In wire format, the value of the parameter is an ECHConfigList [ECH],
                // including the redundant length prefix." - RFC Section 9
                self.u16(config_list.len() as u16);
                self.vec(config_list);
            }
            ServiceParameter::IPV6_HINT { hints } => {
                for hint in hints {
                    self.ipv6_addr(hint);
                }
            }
            ServiceParameter::PRIVATE {
                number: _,
                wire_data,
            } => {
                self.vec(wire_data);
            }
            ServiceParameter::KEY_65535 => {}
        }
        self.set_length_index(length_index)
    }
}
