use std::fmt::{Display, Formatter, Result as FmtResult};

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct Padding(pub u16);

impl Display for Padding {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}", self.0)
    }
}
