use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct SerializableInstant {
    elapsed_millis: u64,
}

impl From<Instant> for SerializableInstant {
    fn from(instant: Instant) -> Self {
        // Calcula o tempo decorrido desde o início do programa
        let elapsed = instant.elapsed();
        SerializableInstant {
            elapsed_millis: elapsed.as_millis() as u64,
        }
    }
}

impl SerializableInstant {
    pub fn to_instant(&self) -> Instant {
        // Converte de volta para Instant
        Instant::now() - Duration::from_millis(self.elapsed_millis)
    }
}

impl SerializableInstant {
    pub fn elapsed(&self) -> Duration {
        Duration::from_millis(self.elapsed_millis)
    }
}

impl Serialize for SerializableInstant {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Serializa o tempo decorrido em milissegundos
        serializer.serialize_u64(self.elapsed_millis)
    }
}

impl<'de> Deserialize<'de> for SerializableInstant {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Desserializa o tempo decorrido em milissegundos
        let millis = u64::deserialize(deserializer)?;
        Ok(SerializableInstant {
            elapsed_millis: millis,
        })
    }
}
