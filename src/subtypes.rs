use std::fmt::{Display, Formatter, Result as FmtResult};

#[derive(Debug, Clone, FromPrimitive, ToPrimitive, PartialEq)]
pub enum Opcode {
    Query = 0,
    IQuery = 1,
    Status = 2,

    Notify = 4,
    Update = 5,
    DSO = 6,
}

impl Display for Opcode {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Opcode::Query => write!(f, "Query"),
            Opcode::IQuery => write!(f, "IQuery"),
            Opcode::Status => write!(f, "Status"),
            Opcode::Notify => write!(f, "Notify"),
            Opcode::Update => write!(f, "Update"),
            Opcode::DSO => write!(f, "DSO"),
        }
    }
}

#[derive(Debug, Clone, FromPrimitive, ToPrimitive, PartialEq)]
pub enum RCode {
    NoError = 0,
    FormErr = 1,
    ServFail = 2,
    NXDomain = 3,
    NotImp = 4,
    Refused = 5,
    YXDomain = 6,
    YXRRSet = 7,
    NXRRSet = 8,
    NotAuth = 9,
    NotZone = 10,
    DSOTYPENI = 11,

    BADVERS = 16,
    BADKEY = 17,
    BADTIME = 18,
    BADMODE = 19,
    BADNAME = 20,
    BADALG = 21,
    BADTRUNC = 22,
    BADCOOKIE = 23,
}

impl Display for RCode {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            RCode::NoError => write!(f, "NoError"),
            RCode::FormErr => write!(f, "FormErr"),
            RCode::ServFail => write!(f, "ServFail"),
            RCode::NXDomain => write!(f, "NXDomain"),
            RCode::NotImp => write!(f, "NotImp"),
            RCode::Refused => write!(f, "Refused"),
            RCode::YXDomain => write!(f, "YXDomain"),
            RCode::YXRRSet => write!(f, "YXRRSet"),
            RCode::NXRRSet => write!(f, "NXRRSet"),
            RCode::NotAuth => write!(f, "NotAuth"),
            RCode::NotZone => write!(f, "NotZone"),
            RCode::DSOTYPENI => write!(f, "DSOTYPENI"),
            RCode::BADVERS => write!(f, "BADVERS"),
            RCode::BADKEY => write!(f, "BADKEY"),
            RCode::BADTIME => write!(f, "BADTIME"),
            RCode::BADMODE => write!(f, "BADMODE"),
            RCode::BADNAME => write!(f, "BADNAME"),
            RCode::BADALG => write!(f, "BADALG"),
            RCode::BADTRUNC => write!(f, "BADTRUNC"),
            RCode::BADCOOKIE => write!(f, "BADCOOKIE"),
        }
    }
}
