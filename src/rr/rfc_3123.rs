use crate::rr::{Address, AddressError};
use crate::DomainName;
use std::fmt::{Display, Formatter, Result as FmtResult};

pub const APL_NEGATION_MASK: u8 = 0b1000_0000;

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct APItem {
    prefix: u8,
    pub negation: bool,
    address: Address,
}

impl APItem {
    pub fn new(prefix: u8, negation: bool, address: Address) -> Result<APItem, AddressError> {
        address.check_prefix(prefix)?;

        let apitem = APItem {
            prefix,
            negation,
            address,
        };

        Ok(apitem)
    }

    #[inline]
    pub const fn get_prefix(&self) -> u8 {
        self.prefix
    }

    pub fn set_prefix(&mut self, prefix: u8) -> Result<(), AddressError> {
        self.address.check_prefix(prefix)?;
        self.prefix = prefix;
        Ok(())
    }

    #[inline]
    pub const fn get_address(&self) -> &Address {
        &self.address
    }

    pub fn set_address(&mut self, address: Address) -> Result<(), AddressError> {
        address.check_prefix(self.prefix)?;
        self.address = address;
        Ok(())
    }
}

#[test]
fn set_prefix() {
    let address = Address::Ipv6("1122:3344::".parse().unwrap());
    let mut apitem = APItem::new(64, true, address).unwrap();
    apitem.set_prefix(96).unwrap();
}

#[test]
fn set_address() {
    let address = Address::Ipv6("1122:3344::".parse().unwrap());
    let mut apitem = APItem::new(64, true, address).unwrap();
    let address = Address::Ipv6("1122:3344:55::".parse().unwrap());
    apitem.set_address(address).unwrap();
}

impl Display for APItem {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        if self.negation {
            write!(f, "!")?;
        }
        write!(
            f,
            "{}:{}/{}",
            self.address.get_address_family_number() as u8,
            self.address,
            self.prefix
        )
    }
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct APL {
    pub domain_name: DomainName,
    pub ttl: u32,
    pub apitems: Vec<APItem>,
}

impl_to_type!(APL);

impl Display for APL {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{} {} IN APL", self.domain_name, self.ttl,)?;
        for apitem in &self.apitems {
            write!(f, " {}", apitem)?;
        }
        Ok(())
    }
}
