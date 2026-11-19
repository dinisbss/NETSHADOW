
use crate::common::{NetShadowError, NetShadowResult};
use std::net::IpAddr;

/// Representa informação básica de uma rede.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkInfo {
    pub address: IpAddr,
    pub prefix: u8,
}

/// Valida um endereço IP.
pub fn validate_ip(address: &str) -> NetShadowResult<IpAddr> {
    address
        .parse::<IpAddr>()
        .map_err(|_| NetShadowError::InvalidInput(
            format!("Invalid IP address: {address}")
        ))
}

/// Cria uma estrutura NetworkInfo validada.
pub fn create_network_info(
    address: &str,
    prefix: u8,
) -> NetShadowResult<NetworkInfo> {
    let ip = validate_ip(address)?;

    let max_prefix = match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };

    if prefix > max_prefix {
        return Err(NetShadowError::InvalidInput(
            format!("Invalid prefix: {prefix}")
        ));
    }

    Ok(NetworkInfo {
        address: ip,
        prefix,
    })
}

/// Devolve o tipo de endereço IP.
pub fn ip_version(address: &IpAddr) -> &'static str {
    match address {
        IpAddr::V4(_) => "IPv4",
        IpAddr::V6(_) => "IPv6",
    }
}
