// Exporta o módulo de configurações
pub mod settings;

// Re-exporta os tipos principais para facilitar o uso
pub use settings::ConsensusConfig;
pub use settings::InteroperabilityConfig;
pub use settings::NodeConfig;
pub use settings::P2PConfig;
pub use settings::QuantumSecurityConfig;
pub use settings::Settings;

// Re-exporta funções úteis

pub use settings::Settings as SettingsStruct;
pub fn default() -> SettingsStruct {
    SettingsStruct::default()
}
pub fn from_file<P: AsRef<std::path::Path>>(path: P) -> Result<SettingsStruct, String> {
    SettingsStruct::from_file(path)
}
