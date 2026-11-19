
use crate::common::{NetShadowError, NetShadowResult};
use std::net::IpAddr;

/// Representa um dispositivo identificado na rede.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredDevice {
    pub address: IpAddr,
    pub hostname: Option<String>,
    pub mac_address: Option<String>,
    pub vendor: Option<String>,
}

/// Gestor de resultados de descoberta.
#[derive(Debug, Default)]
pub struct DiscoveryManager {
    devices: Vec<DiscoveredDevice>,
}

impl DiscoveryManager {
    pub fn new() -> Self {
        Self {
            devices: Vec::new(),
        }
    }

    /// Regista um dispositivo já identificado.
    pub fn register(
        &mut self,
        device: DiscoveredDevice,
    ) -> NetShadowResult<()> {
        if self.devices.iter().any(|item| item.address == device.address) {
            return Err(NetShadowError::DiscoveryError(
                "Device already registered".to_string(),
            ));
        }

        self.devices.push(device);
        Ok(())
    }

    /// Devolve os dispositivos registados.
    pub fn get_all(&self) -> &[DiscoveredDevice] {
        &self.devices
    }

    /// Procura um dispositivo pelo endereço IP.
    pub fn find(&self, address: IpAddr) -> Option<&DiscoveredDevice> {
        self.devices
            .iter()
            .find(|device| device.address == address)
    }

    /// Remove todos os resultados guardados.
    pub fn clear(&mut self) {
        self.devices.clear();
    }

    pub fn count(&self) -> usize {
        self.devices.len()
    }
}
