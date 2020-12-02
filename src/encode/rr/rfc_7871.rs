use crate::encode::Encoder;
use crate::rr::{Address, AddressNumber, EDNSOptionCode, ECS};
use crate::{EncodeError, EncodeResult};
use num_traits::ToPrimitive;
use std::net::{Ipv4Addr, Ipv6Addr};

impl Encoder {
    fn rr_edns_ecs_address_number(&mut self, address_number: &AddressNumber) -> EncodeResult<()> {
        if let Some(buffer) = address_number.to_u16() {
            self.u16(buffer);
            Ok(())
        } else {
            Err(EncodeError::ECSAddressNumberError(address_number.clone()))
        }
    }

    fn rr_edns_ecs_address_ipv4(
        &mut self,
        ipv4_addr: &Ipv4Addr,
        mut source_prefix_length: u8,
    ) -> EncodeResult<()> {
        let ipv4_addr = ipv4_addr.octets();
        for b in &ipv4_addr {
            self.u8(*b);
            if source_prefix_length < 8 {
                break;
            } else {
                source_prefix_length -= 8;
            }
        }
        Ok(())
    }

    fn rr_edns_ecs_address_ipv6(
        &mut self,
        ipv6_addr: &Ipv6Addr,
        mut source_prefix_length: u8,
    ) -> EncodeResult<()> {
        let ipv6_addr = ipv6_addr.octets();
        for b in &ipv6_addr {
            self.u8(*b);
            if source_prefix_length < 8 {
                break;
            } else {
                source_prefix_length -= 8;
            }
        }
        Ok(())
    }

    fn rr_edns_ecs_address(
        &mut self,
        address: &Address,
        source_prefix_length: u8,
    ) -> EncodeResult<()> {
        match address {
            Address::Ipv4(ipv4_addr) => {
                self.rr_edns_ecs_address_ipv4(ipv4_addr, source_prefix_length)
            }
            Address::Ipv6(ipv6_addr) => {
                self.rr_edns_ecs_address_ipv6(ipv6_addr, source_prefix_length)
            }
        }
    }

    pub(super) fn rr_edns_ecs(&mut self, ecs: &ECS) -> EncodeResult<()> {
        self.rr_edns_option_code(&EDNSOptionCode::ECS)?;
        let length_index = self.create_length_index();
        self.rr_edns_ecs_address_number(&ecs.address.get_address_number())?;
        self.u8(ecs.source_prefix_length);
        self.u8(ecs.scope_prefix_length);
        self.rr_edns_ecs_address(&ecs.address, ecs.source_prefix_length)?;
        self.set_length_index(length_index)
    }
}
