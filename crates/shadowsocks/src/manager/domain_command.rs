use std::fmt;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainCommand {
    pub command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<String>,
    #[serde(serialize_with = "serialize_uuid", deserialize_with = "deserialize_uuid")]
    pub id: Uuid,
}
fn serialize_uuid<S>(uuid: &Uuid, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&uuid.to_string())
}

fn deserialize_uuid<'de, D>(deserializer: D) -> Result<Uuid, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Uuid::parse_str(&s).map_err(serde::de::Error::custom)
}

impl fmt::Display for DomainCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DomainCommand {{ command: {}, response: {:?}, id: {} }}",
            self.command.as_deref().unwrap_or("None"),
            self.response.as_deref().unwrap_or("None"),
            self.id
        )
    }
}
impl DomainCommand {
    /// Serialize the Command struct to a JSON string
    pub fn to_string(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
    pub fn set_response(&mut self, response: &str) {
        self.response = Some(response.to_string());
    }
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error>  {
        serde_json::to_vec(self)
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<DomainCommand, serde_json::Error>  {
        serde_json::from_slice(bytes)
    }
    /// Deserialize a JSON string into a Command struct
    pub fn from_string(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }
    pub fn from_response(rsp: &str, uuid: Uuid) -> DomainCommand {
        DomainCommand {
            command: None,
            response: Some(rsp.to_string()),
            id: uuid,
        }
    }
    pub fn new(cmd: &str) -> DomainCommand {
        DomainCommand {
            command: Some(cmd.to_string()),
            response: None,
            id: Uuid::new_v4(),
        }
    }
}


#[cfg(test)]
mod tests {
    use crate::manager::domain_command::DomainCommand;

    #[test]
    fn test_domain_command() {
        let json = r#"{"command": "test", "id": "550e8400-e29b-41d4-a716-446655440000", "response": "test response"}"#;
        let cmd: DomainCommand = serde_json::from_str(json).unwrap();
        println!("{}",cmd);

        assert!(cmd.command.eq(&Some("test".to_string())));
        // assert!(url.contains("@127.0.0.1:8387"));
        // assert!(url.contains("#My%20Server"));
    }

}