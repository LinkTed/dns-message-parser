use std::{
    convert::TryFrom,
    fmt::{Display, Formatter, Result as FmtResult},
    hash::{Hash, Hasher},
    str::FromStr,
};
use thiserror::Error;

pub const LABEL_MAX_LENGTH: usize = 64;

#[derive(Debug, PartialEq, Eq, Error)]
pub enum LabelError {
    #[error("Label is too big: {LABEL_MAX_LENGTH} <= {0}")]
    Length(usize),
    #[error("Label is empty")]
    Empty,
}

#[derive(Debug, Clone, Eq)]
pub struct Label(pub(super) String);

#[inline]
fn check_label(label: &str) -> Result<(), LabelError> {
    let label_length = label.len();
    if label_length == 0 {
        Err(LabelError::Empty)
    } else if label_length < LABEL_MAX_LENGTH {
        Ok(())
    } else {
        Err(LabelError::Length(label_length))
    }
}

impl Label {
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl TryFrom<String> for Label {
    type Error = LabelError;

    fn try_from(label: String) -> Result<Self, <Self as TryFrom<String>>::Error> {
        check_label(&label)?;
        Ok(Label(label))
    }
}

impl FromStr for Label {
    type Err = LabelError;

    fn from_str(label: &str) -> Result<Self, <Self as FromStr>::Err> {
        check_label(label)?;
        Ok(Label(label.to_owned()))
    }
}

impl Display for Label {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for Label {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl PartialEq<&str> for Label {
    fn eq(&self, other: &&str) -> bool {
        self.0.to_lowercase() == other.to_lowercase()
    }
}

impl PartialEq<Label> for Label {
    fn eq(&self, other: &Label) -> bool {
        self.0.to_lowercase() == other.0.to_lowercase()
    }
}

impl Hash for Label {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_lowercase().hash(state);
    }
}
