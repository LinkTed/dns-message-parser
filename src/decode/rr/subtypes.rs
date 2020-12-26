use crate::decode::Decoder;
use crate::rr::{Address, AddressFamilyNumber};
use crate::{DecodeError, DecodeResult};
use std::convert::TryFrom;
use std::mem::size_of;
use std::net::{Ipv4Addr, Ipv6Addr};

impl<'a, 'b: 'a> Decoder<'a, 'b> {
    pub(super) fn rr_address_family_number(&mut self) -> DecodeResult<AddressFamilyNumber> {
        let buffer = self.u16()?;
        match AddressFamilyNumber::try_from(buffer) {
            Ok(address_number) => Ok(address_number),
            Err(buffer) => Err(DecodeError::EcsAddressNumber(buffer)),
        }
    }

    fn rr_address_ipv4(&mut self) -> DecodeResult<Address> {
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

    fn rr_address_ipv6(&mut self) -> DecodeResult<Address> {
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

    pub(super) fn rr_address(
        &mut self,
        address_number: AddressFamilyNumber,
    ) -> DecodeResult<Address> {
        match address_number {
            AddressFamilyNumber::Ipv4 => self.rr_address_ipv4(),
            AddressFamilyNumber::Ipv6 => self.rr_address_ipv6(),
        }
    }
}
