use std::fmt::{Display, Formatter, Result as FmtResult};

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct Cookie {
    pub client_cookie: [u8; 8],
    pub server_cookie: Vec<u8>,
}

impl Display for Cookie {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{:x?} {:x?}", self.client_cookie, self.server_cookie)
    }
}
