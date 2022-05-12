use crate::base64;
use blake2::{Blake2s256, Digest};
use serde_derive::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

#[derive(Serialize_repr, Deserialize_repr, PartialEq, Debug)]
#[repr(u8)]
pub enum Type {
    Error = 0,
    Register = 1,
    EvmTrace = 2,
    ZkProof = 3,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct Msg {
    #[serde(rename = "type")]
    pub msg_type: Type,
    #[serde(with = "base64")]
    pub payload: Vec<u8>,
}

impl Msg {
    pub fn is_error(&self) -> bool {
        self.msg_type == Type::Error
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AuthMsg {
    pub message: Identity,
    pub signature: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Identity {
    pub name: String,
    pub timestamp: i64,
    #[serde(rename = "publicKey")]
    pub public_key: String,
}

impl Identity {
    pub fn hash(&self) -> Vec<u8> {
        let json_bytes = serde_json::to_vec(&self).unwrap();
        let mut hasher = Blake2s256::new();
        hasher.update(json_bytes);
        hasher.finalize().to_vec()
    }
}
