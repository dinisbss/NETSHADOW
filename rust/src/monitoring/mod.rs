
use crate::common::{NetShadowError, NetShadowResult};

/// Estatísticas de monitorização passiva.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MonitoringSnapshot {
    pub observations: u64,
    pub devices_observed: u64,
    pub bytes_observed: u64,
    pub last_update: Option<u64>,
}

/// Gestor de estatísticas de monitorização.
#[derive(Debug, Default)]
pub struct MonitoringManager {
    snapshot: MonitoringSnapshot,
}

impl MonitoringManager {
    /// Cria um gestor vazio.
    pub fn new() -> Self {
        Self::default()
    }

    /// Regista uma observação já recolhida.
    pub fn record_observation(
        &mut self,
        bytes: u64,
        timestamp: u64,
    ) -> NetShadowResult<()> {
        if timestamp == 0 {
            return Err(NetShadowError::MonitoringError(
                "Invalid observation timestamp".to_string(),
            ));
        }

        self.snapshot.observations = self.snapshot
            .observations
            .checked_add(1)
            .ok_or_else(|| NetShadowError::MonitoringError(
                "Observation counter overflow".to_string(),
            ))?;

        self.snapshot.bytes_observed = self.snapshot
            .bytes_observed
            .checked_add(bytes)
            .ok_or_else(|| NetShadowError::MonitoringError(
                "Byte counter overflow".to_string(),
            ))?;

        self.snapshot.last_update = Some(timestamp);

        Ok(())
    }

    /// Regista um dispositivo observado.
    pub fn record_device(&mut self) -> NetShadowResult<()> {
        self.snapshot.devices_observed = self.snapshot
            .devices_observed
            .checked_add(1)
            .ok_or_else(|| NetShadowError::MonitoringError(
                "Device counter overflow".to_string(),
            ))?;

        Ok(())
    }

    /// Devolve uma cópia das estatísticas.
    pub fn snapshot(&self) -> MonitoringSnapshot {
        self.snapshot.clone()
    }

    /// Repõe as estatísticas.
    pub fn reset(&mut self) {
        self.snapshot = MonitoringSnapshot::default();
    }

    /// Devolve o número de observações.
    pub fn observations_count(&self) -> u64 {
        self.snapshot.observations
    }

    /// Devolve o número de dispositivos observados.
    pub fn devices_count(&self) -> u64 {
        self.snapshot.devices_observed
    }

    /// Devolve o total de bytes observados.
    pub fn bytes_count(&self) -> u64 {
        self.snapshot.bytes_observed
    }
}
