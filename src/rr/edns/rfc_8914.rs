use std::{
    convert::TryFrom,
    fmt::{Display, Formatter, Result as FmtResult},
};
use thiserror::Error;

pub const EXTENDED_DNS_ERROR_EXTRA_TEXT_ERROR: usize =
    u16::MAX as usize - std::mem::size_of::<u16>();

try_from_enum_to_integer! {
    #[repr(u16)]
    /// The [Extended DNS Error Codes] field in the [Extended DNS Errors].
    ///
    /// [type]: https://tools.ietf.org/html/rfc8914#section-5.2-3
    /// [Extended DNS Errors]: crate::rr::edns::ExtendedDNSErrors
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum ExtendedDNSErrorCodes {
        /// The [Other] type.
        ///
        /// [Other]: https://datatracker.ietf.org/doc/html/rfc8914#name-extended-dns-error-code-0-o
        Other = 0,
        /// The [Unsupported DNSKEY Algorithm] type.
        ///
        /// [Unsupported DNSKEY Algorithm]: https://datatracker.ietf.org/doc/html/rfc8914#name-extended-dns-error-code-1-u
        UnsupportedDNSKEYAlgorithm = 1,
        /// The [Unsupported DS Digest Type] type.
        ///
        /// [Unsupported DS Digest Type]: https://datatracker.ietf.org/doc/html/rfc8914#name-extended-dns-error-code-2-u
        UnsupportedDSDigestType = 2,
        /// The [Stale Answer] type.
        ///
        /// [Stale Answer]: https://datatracker.ietf.org/doc/html/rfc8914#name-extended-dns-error-code-3-s
        StaleAnswer = 3,
        /// The [Forged Answer] type.
        ///
        /// [Forged Answer]: https://datatracker.ietf.org/doc/html/rfc8914#name-extended-dns-error-code-4-f
        ForgedAnswer = 4,
        /// The [DNSSEC Indeterminate] type.
        ///
        /// [DNSSEC Indeterminate]: https://datatracker.ietf.org/doc/html/rfc8914#name-extended-dns-error-code-5-d
        DNSSECIndeterminate = 5,
        /// The [DNSSEC Bogus] type.
        ///
        /// [DNSSEC Bogus]: https://datatracker.ietf.org/doc/html/rfc8914#name-extended-dns-error-code-6-d
        DNSSECBogus = 6,
        /// The [Signature Expired] type.
        ///
        /// [Signature Expired]: https://datatracker.ietf.org/doc/html/rfc8914#name-extended-dns-error-code-7-s
        SignatureExpired = 7,
        /// The [Signature Not Yet Valid] type.
        ///
        /// [Signature Not Yet Valid]: https://datatracker.ietf.org/doc/html/rfc8914#name-extended-dns-error-code-8-s
        SignatureNotYetValid = 8,
        /// The [DNSKEY Missing] type.
        ///
        /// [DNSKEY Missing]: https://datatracker.ietf.org/doc/html/rfc8914#name-extended-dns-error-code-9-d
        DNSKEYMissing = 9,
        /// The [RRSIGs Missing] type.
        ///
        /// [RRSIGs Missing]: https://datatracker.ietf.org/doc/html/rfc8914#name-extended-dns-error-code-10-
        RRSIGsMissing = 10,
        /// The [No Zone Key Bit Set] type.
        ///
        /// [No Zone Key Bit Set]: https://datatracker.ietf.org/doc/html/rfc8914#name-extended-dns-error-code-11-
        NoZoneKeyBitSet = 11,
        /// The [NSEC Missing] type.
        ///
        /// [NSEC Missing]: https://datatracker.ietf.org/doc/html/rfc8914#name-extended-dns-error-code-12-
        NSECMissing = 12,
        /// The [Cached Error] type.
        ///
        /// [Cached Error]: https://datatracker.ietf.org/doc/html/rfc8914#name-extended-dns-error-code-13-
        CachedError = 13,
        /// The [Not Ready] type.
        ///
        /// [Not Ready]: https://datatracker.ietf.org/doc/html/rfc8914#name-extended-dns-error-code-14-
        NotReady = 14,
        /// The [Blocked] type.
        ///
        /// [Blocked]: https://datatracker.ietf.org/doc/html/rfc8914#name-extended-dns-error-code-15-
        Blocked = 15,
        /// The [Censored] type.
        ///
        /// [Censored]: https://datatracker.ietf.org/doc/html/rfc8914#name-extended-dns-error-code-16-
        Censored = 16,
        /// The [Filtered] type.
        ///
        /// [Filtered]: https://datatracker.ietf.org/doc/html/rfc8914#name-extended-dns-error-code-17-
        Filtered = 17,
        /// The [Prohibited] type.
        ///
        /// [Prohibited]: https://datatracker.ietf.org/doc/html/rfc8914#name-extended-dns-error-code-18-
        Prohibited = 18,
        /// The [Stale NXDOMAIN Answer] type.
        ///
        /// [Stale NXDOMAIN Answer]: https://datatracker.ietf.org/doc/html/rfc8914#name-extended-dns-error-code-19-
        StaleNXDomainAnswer = 19,
        /// The [Not Authoritative] type.
        ///
        /// [Not Authoritative]: https://datatracker.ietf.org/doc/html/rfc8914#name-extended-dns-error-code-20-
        NotAuthoritative = 20,
        /// The [Not Supported] type.
        ///
        /// [Not Supported]: https://datatracker.ietf.org/doc/html/rfc8914#name-extended-dns-error-code-21-
        NotSupported = 21,
        /// The [No Reachable Authority] type.
        ///
        /// [No Reachable Authority]: https://datatracker.ietf.org/doc/html/rfc8914#name-extended-dns-error-code-22-
        NoReachableAuthority = 22,
        /// The [Network Error] type.
        ///
        /// [Network Error]: https://datatracker.ietf.org/doc/html/rfc8914#name-extended-dns-error-code-23-
        NetworkError = 23,
        /// The [Invalid Data] type.
        ///
        /// [Invalid Data]: https://datatracker.ietf.org/doc/html/rfc8914#name-extended-dns-error-code-24-
        InvalidData = 24,
    }
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct ExtendedDNSErrorExtraText {
    inner: String,
}

impl Display for ExtendedDNSErrorExtraText {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}", self.inner)
    }
}

impl AsRef<str> for ExtendedDNSErrorExtraText {
    fn as_ref(&self) -> &str {
        &self.inner
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Error)]
pub enum ExtendedDNSErrorExtraTextError {
    #[error("Text too big {0}")]
    TooBig(usize),
}

impl TryFrom<&str> for ExtendedDNSErrorExtraText {
    type Error = ExtendedDNSErrorExtraTextError;

    fn try_from(text: &str) -> Result<Self, Self::Error> {
        let len = text.len();
        if len <= EXTENDED_DNS_ERROR_EXTRA_TEXT_ERROR {
            Ok(ExtendedDNSErrorExtraText {
                inner: text.to_owned(),
            })
        } else {
            Err(ExtendedDNSErrorExtraTextError::TooBig(len))
        }
    }
}

impl TryFrom<String> for ExtendedDNSErrorExtraText {
    type Error = ExtendedDNSErrorExtraTextError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        let len = text.len();
        if len <= EXTENDED_DNS_ERROR_EXTRA_TEXT_ERROR {
            Ok(ExtendedDNSErrorExtraText { inner: text })
        } else {
            Err(ExtendedDNSErrorExtraTextError::TooBig(len))
        }
    }
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct ExtendedDNSErrors {
    pub info_code: ExtendedDNSErrorCodes,
    pub extra_text: ExtendedDNSErrorExtraText,
}

impl Display for ExtendedDNSErrors {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "Extended DNS Errors {} {}",
            self.info_code, self.extra_text
        )
    }
}
