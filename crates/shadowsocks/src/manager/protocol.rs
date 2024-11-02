//! Shadowsocks server manager protocol

use std::{
    collections::HashMap,
    io::{self, ErrorKind},
    str,
    string::ToString,
};
use log::{debug, error};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use crate::manager::protocol::ManagerRequest::AddUser;

/// Abstract Manager Protocol
pub trait ManagerProtocol: Sized {
    fn from_bytes(buf: &[u8]) -> Result<Self, Error>;
    fn to_bytes(&self) -> Result<Vec<u8>, Error>;
}

/// Server's user configuration
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServerUserConfig {
    pub name: String,
    pub password: String,
}

/// Server's configuration
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServerConfigOther {
    pub server_port: u16,
    pub password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_delay: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plugin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plugin_opts: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plugin_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub users: Option<Vec<ServerUserConfig>>,
}

/// `add User` request
#[derive(Debug, Clone)]
pub struct AURequest {
    pub config: ServerConfigOther
}
// pub type AURequest = ServerConfig;

impl ManagerProtocol for AURequest {
    fn from_bytes(buf: &[u8]) -> Result<Self, Error> {
        debug!("<< from_bytes: {:?}", buf);
        let mut nsplit = buf.splitn(2, |b| *b == b':');

        let cmd = nsplit.next().expect("first element shouldn't be None");
        let cmd = str::from_utf8(cmd)?.trim();
        if cmd != "addu" {
            return Err(Error::UnrecognizedCommand(cmd.to_owned()));
        }

        match nsplit.next() {
            None => Err(Error::MissingParameter),
            Some(param) => {
                debug!("<< Itsa mee: {:?}", param);
                let req = serde_json::from_slice(param)?;
                Ok(AURequest{config:req})
            }
        }
    }

    fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut buf = b"addu: ".to_vec();
        serde_json::to_writer(&mut buf, &self.config)?;
        buf.push(b'\n');
        Ok(buf)
    }
}

/// `add User` response
#[derive(Debug, Clone)]
pub struct AUResponse(pub String);

impl ManagerProtocol for AUResponse {
    fn from_bytes(buf: &[u8]) -> Result<Self, Error> {
        Ok(AUResponse(str::from_utf8(buf)?.trim().to_owned()))
    }

    fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut v = b"addUser".to_vec();//self.0.as_bytes().to_owned();
        v.push(b'\n');
        Ok(v)
    }
}

/// `add` request
pub type AddRequest = ServerConfigOther;

impl ManagerProtocol for AddRequest {
    fn from_bytes(buf: &[u8]) -> Result<Self, Error> {
        let mut nsplit = buf.splitn(2, |b| *b == b':');

        let cmd = nsplit.next().expect("first element shouldn't be None");
        let cmd = str::from_utf8(cmd)?.trim();
        if cmd != "add" {
            return Err(Error::UnrecognizedCommand(cmd.to_owned()));
        }

        match nsplit.next() {
            None => Err(Error::MissingParameter),
            Some(param) => {
                let req = serde_json::from_slice(param)?;
                Ok(req)
            }
        }
    }

    fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut buf = b"add: ".to_vec();
        serde_json::to_writer(&mut buf, self)?;
        buf.push(b'\n');
        Ok(buf)
    }
}

/// `add` response
#[derive(Debug, Clone)]
pub struct AddResponse(pub String);

impl ManagerProtocol for AddResponse {
    fn from_bytes(buf: &[u8]) -> Result<Self, Error> {
        Ok(AddResponse(str::from_utf8(buf)?.trim().to_owned()))
    }

    fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut v = self.0.as_bytes().to_owned();
        v.push(b'\n');
        Ok(v)
    }
}

/// `remove` request
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RemoveRequest {
    pub server_port: u16,
}

impl ManagerProtocol for RemoveRequest {
    fn from_bytes(buf: &[u8]) -> Result<Self, Error> {
        let mut nsplit = buf.splitn(2, |b| *b == b':');

        let cmd = nsplit.next().expect("first element shouldn't be None");
        let cmd = str::from_utf8(cmd)?.trim();
        if cmd != "remove" {
            return Err(Error::UnrecognizedCommand(cmd.to_owned()));
        }

        match nsplit.next() {
            None => Err(Error::MissingParameter),
            Some(param) => {
                let req = serde_json::from_slice(param)?;
                Ok(req)
            }
        }
    }

    fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut buf = b"remove: ".to_vec();
        serde_json::to_writer(&mut buf, self)?;
        buf.push(b'\n');
        Ok(buf)
    }
}

/// `remove` response
#[derive(Debug, Clone)]
pub struct RemoveResponse(pub String);

impl ManagerProtocol for RemoveResponse {
    fn from_bytes(buf: &[u8]) -> Result<Self, Error> {
        Ok(RemoveResponse(str::from_utf8(buf)?.trim().to_owned()))
    }

    fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut v = self.0.as_bytes().to_owned();
        v.push(b'\n');
        Ok(v)
    }
}

/// `list` request
#[derive(Debug, Clone)]
pub struct ListRequest;

impl ManagerProtocol for ListRequest {
    fn from_bytes(buf: &[u8]) -> Result<Self, Error> {
        let cmd = str::from_utf8(buf)?;
        if cmd != "list" {
            return Err(Error::UnrecognizedCommand(cmd.to_owned()));
        }

        Ok(ListRequest)
    }

    fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        Ok(b"list\n".to_vec())
    }
}

/// `list` response
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(transparent)]
pub struct ListResponse {
    pub servers: Vec<ServerConfigOther>,
}

impl ManagerProtocol for ListResponse {
    fn from_bytes(buf: &[u8]) -> Result<Self, Error> {
        let req = serde_json::from_slice(buf)?;
        Ok(req)
    }

    fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut buf = serde_json::to_vec(self)?;
        buf.push(b'\n');
        Ok(buf)
    }
}

/// `ping` request
#[derive(Debug, Clone)]
pub struct PingRequest;

impl ManagerProtocol for PingRequest {
    fn from_bytes(buf: &[u8]) -> Result<Self, Error> {
        let cmd = str::from_utf8(buf)?;
        if cmd != "ping" {
            return Err(Error::UnrecognizedCommand(cmd.to_owned()));
        }

        Ok(PingRequest)
    }

    fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        Ok(b"ping\n".to_vec())
    }
}

/// `ping` response
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(transparent)]
pub struct PingResponse {
    pub stat: HashMap<u16, u64>,
}

impl ManagerProtocol for PingResponse {
    fn from_bytes(buf: &[u8]) -> Result<Self, Error> {
        let mut nsplit = buf.splitn(2, |b| *b == b':');

        let cmd = nsplit.next().expect("first element shouldn't be None");
        let cmd = str::from_utf8(cmd)?.trim();
        if cmd != "stat" {
            return Err(Error::UnrecognizedCommand(cmd.to_owned()));
        }

        match nsplit.next() {
            None => Err(Error::MissingParameter),
            Some(param) => {
                let req = serde_json::from_slice(param)?;
                Ok(req)
            }
        }
    }

    fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut buf = b"stat: ".to_vec();
        serde_json::to_writer(&mut buf, self)?;
        buf.push(b'\n');
        Ok(buf)
    }
}

/// `stat` request
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(transparent)]
pub struct StatRequest {
    pub stat: HashMap<u16, u64>,
}

impl ManagerProtocol for StatRequest {
    fn from_bytes(buf: &[u8]) -> Result<Self, Error> {
        let mut nsplit = buf.splitn(2, |b| *b == b':');

        let cmd = nsplit.next().expect("first element shouldn't be None");
        let cmd = str::from_utf8(cmd)?.trim();
        if cmd != "stat" {
            return Err(Error::UnrecognizedCommand(cmd.to_owned()));
        }

        match nsplit.next() {
            None => Err(Error::MissingParameter),
            Some(param) => {
                let req = serde_json::from_slice(param)?;
                Ok(req)
            }
        }
    }

    fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut buf = b"stat: ".to_vec();
        serde_json::to_writer(&mut buf, self)?;
        buf.push(b'\n');
        Ok(buf)
    }
}

/// Server's error message
#[derive(Debug, Clone)]
pub struct ErrorResponse<E: ToString>(pub E);

impl<E: ToString> ManagerProtocol for ErrorResponse<E> {
    fn from_bytes(_: &[u8]) -> Result<Self, Error> {
        panic!("ErrorResponse is only for sending errors from manager servers");
    }

    fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut v = self.0.to_string().into_bytes();
        v.push(b'\n');
        Ok(v)
    }
}

/// Collections of Manager's request
#[derive(Debug, Clone)]
pub enum ManagerRequest {
    Add(AddRequest),
    Remove(RemoveRequest),
    List(ListRequest),
    Ping(PingRequest),
    Stat(StatRequest),
    AddUser(AURequest),
}

impl ManagerRequest {
    /// Command key
    pub fn command(&self) -> &'static str {
        match *self {
            ManagerRequest::Add(..) => "add",
            ManagerRequest::Remove(..) => "remove",
            ManagerRequest::List(..) => "list",
            ManagerRequest::Ping(..) => "ping",
            ManagerRequest::Stat(..) => "stat",
            ManagerRequest::AddUser(..) => "addu",
        }
    }
}

impl ManagerProtocol for ManagerRequest {
    fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        match *self {
            ManagerRequest::Add(ref req) => req.to_bytes(),
            ManagerRequest::Remove(ref req) => req.to_bytes(),
            ManagerRequest::List(ref req) => req.to_bytes(),
            ManagerRequest::Ping(ref req) => req.to_bytes(),
            ManagerRequest::Stat(ref req) => req.to_bytes(),
            ManagerRequest::AddUser(ref req) => req.to_bytes(),
        }
    }

    fn from_bytes(buf: &[u8]) -> Result<ManagerRequest, Error> {
        let mut nsplit = buf.splitn(2, |b| *b == b':');

        let cmd = nsplit.next().expect("first element shouldn't be None");
        match str::from_utf8(cmd)?.trim() {
            "add" => match nsplit.next() {
                None => Err(Error::MissingParameter),
                Some(param) => {
                    let req = serde_json::from_slice(param)?;
                    Ok(ManagerRequest::Add(req))
                }
            },
            "addu" => match nsplit.next() {
                None => {
                    error!("<<<< blahhh");
                    Err(Error::MissingParameter)
                },
                Some(param) => {
                    debug!("<< param:: up: {:?}", String::from_utf8(param.to_vec()));
                    let req = serde_json::from_slice(param)?;
                    debug!("<< req {:?}", req);
                    Ok(ManagerRequest::AddUser(AURequest{config:req}))
                }
            },
            "remove" => match nsplit.next() {
                None => Err(Error::MissingParameter),
                Some(param) => {
                    let req = serde_json::from_slice(param)?;
                    Ok(ManagerRequest::Remove(req))
                }
            },
            "list" => {
                if nsplit.next().is_some() {
                    return Err(Error::RedundantParameter);
                }
                Ok(ManagerRequest::List(ListRequest))
            }
            "ping" => {
                if nsplit.next().is_some() {
                    return Err(Error::RedundantParameter);
                }
                Ok(ManagerRequest::Ping(PingRequest))
            }
            "stat" => match nsplit.next() {
                None => Err(Error::MissingParameter),
                Some(param) => {
                    let req = serde_json::from_slice(param)?;
                    Ok(ManagerRequest::Stat(req))
                }
            },
            cmd => Err(Error::UnrecognizedCommand(cmd.to_owned())),
        }
    }
}

/// Manager's Error
#[derive(Error, Debug)]
pub enum Error {
    #[error("{0}")]
    JsonError(#[from] serde_json::Error),
    #[error("{0}")]
    FromUtf8Error(#[from] std::str::Utf8Error),
    #[error("missing parameter")]
    MissingParameter,
    #[error("redundant parameter")]
    RedundantParameter,
    #[error("unrecognized command \"{0}\"")]
    UnrecognizedCommand(String),
}

impl From<Error> for io::Error {
    fn from(err: Error) -> io::Error {
        io::Error::new(ErrorKind::Other, err.to_string())
    }
}
