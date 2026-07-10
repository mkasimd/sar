#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldPresence<T> {
    Absent,
    PresentInactive(T),
    PresentActive(T),
}

impl<T> FieldPresence<T> {
    pub fn is_absent(&self) -> bool {
        matches!(self, Self::Absent)
    }

    pub fn is_present(&self) -> bool {
        !self.is_absent()
    }

    pub fn is_active(&self) -> bool {
        matches!(self, Self::PresentActive(_))
    }

    pub fn value(&self) -> Option<&T> {
        match self {
            Self::Absent => None,
            Self::PresentInactive(value) | Self::PresentActive(value) => Some(value),
        }
    }

    pub fn active_value(&self) -> Option<&T> {
        match self {
            Self::PresentActive(value) => Some(value),
            _ => None,
        }
    }

    pub fn into_active_value(self) -> Option<T> {
        match self {
            Self::PresentActive(value) => Some(value),
            _ => None,
        }
    }

    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> FieldPresence<U> {
        match self {
            Self::Absent => FieldPresence::Absent,
            Self::PresentInactive(value) => FieldPresence::PresentInactive(f(value)),
            Self::PresentActive(value) => FieldPresence::PresentActive(f(value)),
        }
    }
}
