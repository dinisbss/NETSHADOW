
use std::error::Error;
use std::fmt;

/// Categorias de erros do NETSHADOW.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetShadowError {
    InvalidInput(String),
    PermissionDenied(String),
    NetworkError(String),
    DiscoveryError(String),
    MonitoringError(String),
    PortAuditError(String),
    InternalError(String),
}

impl fmt::Display for NetShadowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(message) => {
                write!(f, "Invalid input: {message}")
            }
            Self::PermissionDenied(message) => {
                write!(f, "Permission denied: {message}")
            }
            Self::NetworkError(message) => {
                write!(f, "Network error: {message}")
            }
            Self::DiscoveryError(message) => {
                write!(f, "Discovery error: {message}")
            }
            Self::MonitoringError(message) => {
                write!(f, "Monitoring error: {message}")
            }
            Self::PortAuditError(message) => {
                write!(f, "Port audit error: {message}")
            }
            Self::InternalError(message) => {
                write!(f, "Internal error: {message}")
            }
        }
    }
}

impl Error for NetShadowError {}

pub type NetShadowResult<T> = Result<T, NetShadowError>;
