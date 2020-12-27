use crate::rr::{Address, AddressError};
use std::cmp::max;
use std::fmt::{Display, Formatter, Result as FmtResult};

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct ECS {
    source_prefix_length: u8,
    scope_prefix_length: u8,
    address: Address,
}

macro_rules! setter {
    ($(#[$doc_comment:meta])* $method:ident, $member:ident, $type:ident) => {
        $(#[$doc_comment])*
        pub fn $method(&mut self, new_value: $type) -> Result<(), AddressError> {
            let previous = self.$member.clone();
            self.$member = new_value;
            match self.check_addr() {
                Ok(()) => Ok(()),
                Err(address_error) => {
                    self.$member = previous;
                    Err(address_error)
                }
            }
        }
    };
}

impl ECS {
    fn check_addr(&self) -> Result<(), AddressError> {
        let prefix_length = self.get_prefix_length();
        self.address.check_prefix(prefix_length)
    }

    pub fn new(
        source_prefix_length: u8,
        scope_prefix_length: u8,
        address: Address,
    ) -> Result<ECS, AddressError> {
        let ecs = ECS {
            source_prefix_length,
            scope_prefix_length,
            address,
        };

        ecs.check_addr()?;

        Ok(ecs)
    }

    /// Returns the current source prefix length.
    #[inline]
    pub const fn get_source_prefix_length(&self) -> u8 {
        self.source_prefix_length
    }

    setter!(
        /// Try to set the source prefix length.
        ///
        /// Returns `Ok()` if the length fit in the current address as network mask, otherwise
        /// returns [`AddressError`] and the value is not changed.
        ///
        /// [`AddressError`]: crate::rr::AddressError
        set_source_prefix_length,
        source_prefix_length,
        u8
    );

    /// Returns the current scope prefix length.
    #[inline]
    pub const fn get_scope_prefix_length(&self) -> u8 {
        self.scope_prefix_length
    }

    setter!(
        /// Try to set the scope prefix length.
        ///
        /// Returns `Ok()` if the length fit in the current address as network mask, otherwise
        /// returns [`AddressError`] and the value is not changed.
        ///
        /// [`AddressError`]: crate::rr::AddressError
        set_scope_prefix_length,
        scope_prefix_length,
        u8
    );

    /// Returns the current address.
    #[inline]
    pub const fn get_address(&self) -> &Address {
        &self.address
    }

    setter!(
        /// Try to set the scope prefix length.
        ///
        /// Returns `Ok()` if the current and scope prefix length fits in the new address as
        /// network mask , otherwise returns [`AddressError`] and the value is not changed.
        ///
        /// [`AddressError`]: crate::rr::AddressError
        set_address,
        address,
        Address
    );

    /// Returns the prefix length of the address.
    ///
    /// It the max value of the `source_prefix_length` and `scope_prefix_length`.
    #[inline]
    pub fn get_prefix_length(&self) -> u8 {
        max(self.source_prefix_length, self.scope_prefix_length)
    }
}

impl Display for ECS {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "{} {} {}",
            self.source_prefix_length, self.scope_prefix_length, self.address
        )
    }
}
