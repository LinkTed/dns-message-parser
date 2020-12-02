use crate::decode::Decoder;
use crate::rr::{Address, AddressNumber, ECS};
use crate::{DecodeError, DecodeResult};
use num_traits::FromPrimitive;
use std::mem::size_of;
use std::net::{Ipv4Addr, Ipv6Addr};

impl<'a, 'b: 'a> Decoder<'a, 'b> {
    fn rr_ends_ecs_address_number(&mut self) -> DecodeResult<AddressNumber> {
        let buffer = self.u16()?;
        if let Some(address_number) = AddressNumber::from_u16(buffer) {
            Ok(address_number)
        } else {
            Err(DecodeError::EcsAddressNumberError(buffer))
        }
    }

    fn rr_edns_ecs_address_ipv4(&mut self) -> DecodeResult<Address> {
        let buffer = self.vec()?;
        let buffer_len = buffer.len();
        if size_of::<[u8; 4]>() < buffer_len {
            return Err(DecodeError::EcsTooBigIpv4Address(buffer_len));
        }

        let mut octects: [u8; 4] = [0; 4];
        octects[0..buffer_len].copy_from_slice(&buffer[..]);

        let ipv4_addr = Ipv4Addr::from(octects);
        Ok(Address::Ipv4(ipv4_addr))
    }

    fn rr_edns_ecs_address_ipv6(&mut self) -> DecodeResult<Address> {
        let buffer = self.vec()?;
        let buffer_len = buffer.len();
        if size_of::<[u8; 16]>() < buffer_len {
            return Err(DecodeError::EcsTooBigIpv6Address(buffer_len));
        }

        let mut octects: [u8; 16] = [0; 16];
        octects[0..buffer_len].copy_from_slice(&buffer[..]);

        let ipv6_addr = Ipv6Addr::from(octects);
        Ok(Address::Ipv6(ipv6_addr))
    }

    fn rr_ends_ecs_address(&mut self, address_number: AddressNumber) -> DecodeResult<Address> {
        match address_number {
            AddressNumber::Ipv4 => self.rr_edns_ecs_address_ipv4(),
            AddressNumber::Ipv6 => self.rr_edns_ecs_address_ipv6(),
        }
    }

    pub(super) fn rr_edns_ecs(&mut self) -> DecodeResult<ECS> {
        let address_number = self.rr_ends_ecs_address_number()?;
        let source_prefix_length = self.u8()?;
        let scope_prefix_length = self.u8()?;
        let address = self.rr_ends_ecs_address(address_number)?;
        let ecs = ECS::new(source_prefix_length, scope_prefix_length, address)?;
        Ok(ecs)
    }
}
