#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    NotFound,
    Exists,
    Unavailable,
    AuthDenied,
}

impl Reason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotFound => "NOT_FOUND",
            Self::Exists => "EXISTS",
            Self::Unavailable => "UNAVAILABLE",
            Self::AuthDenied => "AUTH_DENIED",
        }
    }
}

#[derive(Debug)]
pub struct OpError {
    pub status: i64,
    pub reason: Option<Reason>,
    pub message: &'static str,
}

impl OpError {
    pub fn request(message: &'static str) -> Self {
        Self {
            status: -1,
            reason: None,
            message,
        }
    }
    pub fn native(status: u32, reason: Reason, message: &'static str) -> Self {
        Self {
            status: i64::from(status),
            reason: Some(reason),
            message,
        }
    }
}
