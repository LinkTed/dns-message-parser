use std::fmt::{Display, Formatter, Result as FmtResult};

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct Expire {
    pub seconds: Option<u32>,
}

impl Display for Expire {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "Expire")?;
        if let Some(seconds) = self.seconds {
            write!(f, " {}", seconds)?;
        }
        Ok(())
    }
}
