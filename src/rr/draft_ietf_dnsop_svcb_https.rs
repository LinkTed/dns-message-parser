use crate::rr::draft_ietf_dnsop_svcb_https::ServiceBindingMode::{Alias, Service};
use crate::rr::{ToType, Type};
use crate::DomainName;
use base64::{engine::general_purpose::STANDARD as Base64Standard, Engine};
use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::hash::{Hash, Hasher};
use std::net::{Ipv4Addr, Ipv6Addr};

/// A Service Binding record for locating alternative endpoints for a service.
///
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ServiceBinding {
    pub name: DomainName,
    pub ttl: u32,

    // The class is always IN (Internet, 0x0001)
    /// The `SvcPriority` field, a value between 0 and 65535
    /// SVCB resource records with a smaller priority SHOULD be given priority over resource records
    /// with a larger value.
    pub priority: u16,
    pub target_name: DomainName,
    pub parameters: BTreeSet<ServiceParameter>,
    /// Indicates whether or not this is an HTTPS record (RFC section 8)
    pub https: bool,
}

impl ToType for ServiceBinding {
    fn to_type(&self) -> Type {
        if self.https {
            Type::HTTPS
        } else {
            Type::SVCB
        }
    }
}

/// The modes inferred from the `SvcPriority` field
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ServiceBindingMode {
    /// "go to the target name and do another service binding query"
    /// enables apex aliasing for participating clients
    Alias,

    /// Indicates that this record contains an arbitrary (IANA controlled) key value data store
    /// The record contains anything the client _may_ need to know in order to connect to the server.
    Service,
}

impl Display for ServiceBinding {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let record_type = if self.https { "HTTPS" } else { "SVCB" };
        write!(
            f,
            "{} {} IN {} {} {}",
            self.name, self.ttl, record_type, self.priority, self.target_name
        )?;
        self.parameters
            .iter()
            .try_for_each(|parameter| -> FmtResult {
                write!(f, " ")?;
                parameter.fmt(f)
            })
    }
}

impl ServiceBinding {
    pub fn mode(&self) -> ServiceBindingMode {
        if self.priority == 0 {
            Alias
        } else {
            Service
        }
    }
}

#[derive(Debug, Clone, Eq)]
pub enum ServiceParameter {
    /// Mandatory keys in this resource record (service mode only)
    MANDATORY {
        /// the key IDs the client must support in order for this resource record to function properly
        /// RFC section 7
        key_ids: Vec<u16>,
    },
    /// Additional supported protocols
    ALPN {
        /// The default set of ALPNs, which SHOULD NOT be empty, e.g. "h3", "h2", "http/1.1".
        alpn_ids: Vec<String>,
    },
    /// No support for default protocol
    ///
    /// When this is specified in a resource record, `ALPN` must also be specified in order to be
    /// "self-consistent".
    NO_DEFAULT_ALPN,
    /// Port for alternative endpoint
    PORT { port: u16 },
    /// IPv4 address hints
    IPV4_HINT { hints: Vec<Ipv4Addr> },
    /// Encrypted ClientHello information (RFC Section 9)
    ///
    /// This conveys the ECH configuration of an alternative endpoint.
    ECH { config_list: Vec<u8> },
    /// IPv6 address hints
    IPV6_HINT { hints: Vec<Ipv6Addr> },
    /// Private use keys 65280-65534
    PRIVATE { number: u16, wire_data: Vec<u8> },
    /// Reserved ("Invalid key")
    KEY_65535,
}

impl PartialEq for ServiceParameter {
    fn eq(&self, other: &Self) -> bool {
        self.get_registered_number()
            .eq(&other.get_registered_number())
    }
}

impl Hash for ServiceParameter {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u16(self.get_registered_number())
    }
}

impl PartialOrd for ServiceParameter {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ServiceParameter {
    fn cmp(&self, other: &Self) -> Ordering {
        self.get_registered_number()
            .cmp(&other.get_registered_number())
    }
}

impl ServiceParameter {
    pub fn get_registered_number(&self) -> u16 {
        match self {
            ServiceParameter::MANDATORY { .. } => 0,
            ServiceParameter::ALPN { .. } => 1,
            ServiceParameter::NO_DEFAULT_ALPN => 2,
            ServiceParameter::PORT { .. } => 3,
            ServiceParameter::IPV4_HINT { .. } => 4,
            ServiceParameter::ECH { .. } => 5,
            ServiceParameter::IPV6_HINT { .. } => 6,
            ServiceParameter::PRIVATE {
                number,
                wire_data: _,
            } => *number,
            ServiceParameter::KEY_65535 => 65535,
        }
    }

    fn id_to_presentation_name(id: u16) -> String {
        match id {
            0 => "mandatory".to_string(),
            1 => "alpn".to_string(),
            2 => "no-default-alpn".to_string(),
            3 => "port".to_string(),
            4 => "ipv4hint".to_string(),
            5 => "ech".to_string(),
            6 => "ipv6hint".to_string(),
            65535 => "reserved".to_string(),
            number => format!("key{}", number),
        }
    }
}

/// Escape backslashes and commas in an ALPN ID
fn escape_alpn(alpn: &str) -> String {
    let mut result = String::new();
    for char in alpn.chars() {
        if char == '\\' {
            result.push_str("\\\\\\");
        } else if char == ',' {
            result.push('\\');
        }
        result.push(char);
    }
    result
}

impl Display for ServiceParameter {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            ServiceParameter::MANDATORY { key_ids } => {
                let mut key_ids = key_ids.clone();
                key_ids.sort_unstable();
                let mandatory_keys = key_ids
                    .iter()
                    .map(|id| ServiceParameter::id_to_presentation_name(*id))
                    .collect::<Vec<String>>()
                    .join(",");

                write!(f, "mandatory={}", mandatory_keys)
            }
            ServiceParameter::ALPN { alpn_ids } => {
                let mut escape = false;
                let mut escaped_ids = vec![];
                for id in alpn_ids {
                    let escaped = escape_alpn(id);
                    if escaped != *id {
                        escape |= true;
                    }
                    escaped_ids.push(escaped);
                }
                let value = escaped_ids.join(",");
                if escape {
                    write!(f, "alpn=\"{}\"", value)
                } else {
                    write!(f, "alpn={}", value)
                }
            }
            ServiceParameter::NO_DEFAULT_ALPN => write!(f, "no-default-alpn"),
            ServiceParameter::PORT { port } => write!(f, "port={}", port),
            ServiceParameter::IPV4_HINT { hints } => {
                write!(
                    f,
                    "ipv4hint={}",
                    hints
                        .iter()
                        .map(|hint| hint.to_string())
                        .collect::<Vec<String>>()
                        .join(",")
                )
            }
            ServiceParameter::ECH { config_list } => {
                write!(f, "ech={}", Base64Standard.encode(config_list))
            }
            ServiceParameter::IPV6_HINT { hints } => {
                write!(
                    f,
                    "ipv6hint=\"{}\"",
                    hints
                        .iter()
                        .map(|hint| hint.to_string())
                        .collect::<Vec<String>>()
                        .join(",")
                )
            }
            ServiceParameter::PRIVATE { number, wire_data } => {
                let key = format!("key{}", number);
                let value = String::from_utf8(wire_data.clone());
                if let Ok(value) = value {
                    write!(f, "{}={}", key, value)
                } else {
                    let mut escaped = vec![];
                    for byte in wire_data {
                        if *byte < b'0'
                            || (*byte > b'9' && *byte < b'A')
                            || (*byte > b'Z' && *byte < b'a')
                            || *byte > b'z'
                        {
                            escaped.extend_from_slice(format!("\\{}", *byte).as_bytes());
                        } else {
                            escaped.push(*byte);
                        }
                    }
                    if let Ok(value) = String::from_utf8(escaped) {
                        write!(f, "{}=\"{}\"", key, value)
                    } else {
                        write!(f, "{}=\"{}\"", key, Base64Standard.encode(wire_data))
                    }
                }
            }
            ServiceParameter::KEY_65535 => write!(f, "reserved"),
        }
    }
}
