use hex::encode;
use std::fmt::{Display, Formatter, Result as FmtResult};
use thiserror::Error;

pub const CLIENT_COOKIE_LENGTH: usize = 8;
pub const MINIMUM_SERVER_COOKIE_LENGTH: usize = 8;
pub const MAXIMUM_SERVER_COOKIE_LENGTH: usize = 32;

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct Cookie {
    pub client_cookie: [u8; 8],
    server_cookie: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Error)]
pub enum CookieError {
    #[error("Server cookie length is not between {MINIMUM_SERVER_COOKIE_LENGTH} and {MAXIMUM_SERVER_COOKIE_LENGTH}: {0}]")]
    ServerCookieLength(usize),
}

impl Cookie {
    pub fn new(
        client_cookie: [u8; 8],
        server_cookie: Option<Vec<u8>>,
    ) -> Result<Cookie, CookieError> {
        let mut cookie = Cookie {
            client_cookie,
            server_cookie: None,
        };
        cookie.set_server_cookie(server_cookie)?;
        Ok(cookie)
    }

    pub fn set_server_cookie(&mut self, server_cookie: Option<Vec<u8>>) -> Result<(), CookieError> {
        match server_cookie {
            Some(server_cookie) => {
                let server_cookie_len = server_cookie.len();
                if (MINIMUM_SERVER_COOKIE_LENGTH..MAXIMUM_SERVER_COOKIE_LENGTH)
                    .contains(&server_cookie_len)
                {
                    self.server_cookie.replace(server_cookie);
                    Ok(())
                } else {
                    Err(CookieError::ServerCookieLength(server_cookie_len))
                }
            }
            None => {
                self.server_cookie.take();
                Ok(())
            }
        }
    }

    pub fn get_server_cookie(&self) -> Option<&[u8]> {
        self.server_cookie.as_deref()
    }
}

impl Display for Cookie {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}", encode(self.client_cookie))?;
        match &self.server_cookie {
            Some(server_cookie) => write!(f, " {}", encode(server_cookie)),
            None => Ok(()),
        }
    }
}
