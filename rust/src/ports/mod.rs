
use crate::common::{NetShadowError, NetShadowResult};

/// Protocolo associado a uma porta.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortProtocol {
    TCP,
    UDP,
}

/// Estado observado de uma porta.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    OpenFiltered,
    ClosedFiltered,
    Unknown,
}

/// Resultado de uma observação de porta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortResult {
    pub port: u16,
    pub protocol: PortProtocol,
    pub state: PortState,
}

/// Cria um resultado validado.
pub fn create_result(
    port: u16,
    protocol: PortProtocol,
    state: PortState,
) -> NetShadowResult<PortResult> {
    if port == 0 {
        return Err(NetShadowError::InvalidInput(
            "Port number must be between 1 and 65535".to_string(),
        ));
    }

    Ok(PortResult {
        port,
        protocol,
        state,
    })
}

/// Devolve o nome do estado.
pub fn state_name(state: PortState) -> &'static str {
    match state {
        PortState::Open => "open",
        PortState::Closed => "closed",
        PortState::Filtered => "filtered",
        PortState::OpenFiltered => "open|filtered",
        PortState::ClosedFiltered => "closed|filtered",
        PortState::Unknown => "unknown",
    }
}
