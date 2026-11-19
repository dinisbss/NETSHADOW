
use crate::common::{NetShadowError, NetShadowResult};
use std::net::IpAddr;

/// Protocolo de transporte identificado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportProtocol {
    TCP,
    UDP,
    ICMP,
    Other(String),
}

/// Metadados de um pacote observado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketMetadata {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub protocol: TransportProtocol,
    pub size: usize,
    pub timestamp: u64,
}

/// Valida e cria metadados de um pacote.
pub fn create_metadata(
    source: IpAddr,
    destination: IpAddr,
    protocol: TransportProtocol,
    size: usize,
    timestamp: u64,
) -> NetShadowResult<PacketMetadata> {
    if size == 0 {
        return Err(NetShadowError::InvalidInput(
            "Packet size cannot be zero".to_string(),
        ));
    }

    Ok(PacketMetadata {
        source,
        destination,
        protocol,
        size,
        timestamp,
    })
}

/// Verifica se os dois endereços pertencem à mesma versão IP.
pub fn same_ip_version(metadata: &PacketMetadata) -> bool {
    matches!(
        (metadata.source, metadata.destination),
        (IpAddr::V4(_), IpAddr::V4(_))
            | (IpAddr::V6(_), IpAddr::V6(_))
    )
}
