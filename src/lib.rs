use bendy::{
    encoding::{self, AsString, SingleItemEncoder, ToBencode},
    value::Value,
};
use std::{net::SocketAddrV4, ops::Deref};

trait IntoBytes {
    fn into_bytes(&self) -> Vec<u8>;
}

impl IntoBytes for Vec<Node> {
    fn into_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for node in self {
            bytes.extend_from_slice(&node.into_bytes());
        }
        bytes
    }
}

impl IntoBytes for SocketAddrV4 {
    fn into_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.ip().octets());
        bytes.extend_from_slice(&self.port().to_be_bytes());
        bytes
    }
}

impl IntoBytes for &Node {
    fn into_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.id);
        bytes.extend_from_slice(&self.addr.into_bytes());
        bytes
    }
}

#[derive(Debug)]
pub struct Hash {
    pub bytes: [u8; 20],
}

impl Deref for Hash {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl ToBencode for Hash {
    const MAX_DEPTH: usize = 1;
    fn encode(&self, encoder: SingleItemEncoder) -> Result<(), encoding::Error> {
        encoder.emit_bytes(&self.bytes)
    }
}

#[derive(Debug)]
pub struct Ping {
    pub id: Hash,
}

impl ToBencode for Ping {
    const MAX_DEPTH: usize = 1;
    fn encode(&self, encoder: SingleItemEncoder) -> Result<(), encoding::Error> {
        encoder.emit_dict(|mut e| {
            // ping query contains only single field - id
            e.emit_pair(b"id", &self.id)
        })
    }
}

#[derive(Debug)]
pub struct FindNode {
    pub id: Hash,
    pub target: Hash,
}

impl ToBencode for FindNode {
    const MAX_DEPTH: usize = 1;
    fn encode(&self, encoder: SingleItemEncoder) -> Result<(), encoding::Error> {
        encoder.emit_dict(|mut e| {
            e.emit_pair(b"id", &self.id)?;
            e.emit_pair(b"target", &self.target)
        })
    }
}

#[derive(Debug)]
pub struct GetPeers {
    pub id: Hash,
    pub info_hash: Hash,
}

impl ToBencode for GetPeers {
    const MAX_DEPTH: usize = 1;
    fn encode(&self, encoder: SingleItemEncoder) -> Result<(), encoding::Error> {
        encoder.emit_dict(|mut e| {
            e.emit_pair(b"id", &self.id)?;
            e.emit_pair(b"info_hash", &self.info_hash)
        })
    }
}

#[derive(Debug)]
pub struct AnnouncePeer {
    pub id: Hash,
    pub implied_port: Option<bool>,
    pub info_hash: Hash,
    pub port: u16,
    pub token: Vec<u8>,
}

impl ToBencode for AnnouncePeer {
    const MAX_DEPTH: usize = 1;
    fn encode(&self, encoder: SingleItemEncoder) -> Result<(), encoding::Error> {
        encoder.emit_dict(|mut e| {
            e.emit_pair(b"id", &self.id)?;

            if let Some(i) = self.implied_port {
                e.emit_pair(b"implied_port", i as i64)?;
            }

            e.emit_pair(b"info_hash", &self.info_hash)?;
            e.emit_pair(b"port", &self.port)?;
            // token not a list, it is a byte str
            e.emit_pair(b"token", AsString(&self.token))
        })
    }
}

#[derive(Debug)]
pub struct Node {
    pub id: Hash,
    pub addr: SocketAddrV4,
}

#[derive(Debug)]
pub struct Response {
    id: Hash,
    nodes: Option<Vec<Node>>,
    values: Option<Vec<SocketAddrV4>>,
    token: Option<Vec<u8>>,
}

impl ToBencode for Response {
    const MAX_DEPTH: usize = 1;
    fn encode(&self, encoder: SingleItemEncoder) -> Result<(), encoding::Error> {
        encoder.emit_dict(|mut e| {
            // adding "id"
            e.emit_pair(b"id", &self.id)?;

            // adding "nodes"
            if let Some(nodes) = &self.nodes {
                e.emit_pair(b"nodes", AsString(nodes.into_bytes()))?;
            }

            if let Some(token) = &self.token {
                e.emit_pair(b"token", AsString(token))?;
            }

            // adding "values"
            if let Some(values) = &self.values {
                e.emit_pair(
                    b"values",
                    values.iter().map(|s| AsString(s.into_bytes())).collect::<Vec<_>>(),
                )?;
            }
            Ok(())
        })
    }
}

#[derive(Debug)]
pub struct Error {
    pub code: i64,
    pub message: String,
}

impl ToBencode for Error {
    const MAX_DEPTH: usize = 1;
    fn encode(&self, encoder: SingleItemEncoder) -> Result<(), encoding::Error> {
        encoder.emit_list(|e| {
            // adding "code"
            e.emit_int(self.code)?;

            // adding "message"
            e.emit_str(&self.message)
        })
    }
}

pub enum PayloadType {
    Query,
    Response,
    Error,
}

impl PayloadType {
    pub fn bencode_key(&self) -> [u8; 1] {
        match self {
            Self::Query => *b"a",
            Self::Response => *b"r",
            Self::Error => *b"e",
        }
    }
}

impl ToBencode for PayloadType {
    const MAX_DEPTH: usize = 1;

    fn encode(&self, encoder: SingleItemEncoder) -> Result<(), encoding::Error> {
        let t = match self {
            Self::Query => b"q",
            Self::Response => b"r",
            Self::Error => b"e",
        };
        encoder.emit_bytes(t)
    }
}

pub enum Payload {
    Ping(Ping),
    FindNode(FindNode),
    GetPeers(GetPeers),
    AnnouncePeer(AnnouncePeer),
    Response(Response),
    Error(Error),
}

impl Payload {
    pub fn get_type(&self) -> PayloadType {
        match self {
            Self::Ping(_) | Self::FindNode(_) | Self::GetPeers(_) | Self::AnnouncePeer(_) => {
                PayloadType::Query
            }
            Self::Response(_) => PayloadType::Response,
            Self::Error(_) => PayloadType::Error,
        }
    }
    pub fn query_name(&self) -> Option<String> {
        match self {
            Self::Ping(_) => Some("ping".into()),
            Self::FindNode(_) => Some("find_node".into()),
            Self::GetPeers(_) => Some("get_peers".into()),
            Self::AnnouncePeer(_) => Some("announce_peer".into()),
            Self::Response(_) => None,
            Self::Error(_) => None,
        }
    }
}

impl ToBencode for Payload {
    const MAX_DEPTH: usize = 1;
    fn encode(&self, encoder: SingleItemEncoder) -> Result<(), encoding::Error> {
        match self {
            Self::Ping(p) => p.encode(encoder),
            Self::FindNode(f) => f.encode(encoder),
            Self::GetPeers(g) => g.encode(encoder),
            Self::AnnouncePeer(a) => a.encode(encoder),
            Self::Response(r) => r.encode(encoder),
            Self::Error(e) => e.encode(encoder),
        }
    }
}

pub struct Message {
    pub transaction_id: u16,
    pub payload: Payload,
}

impl Message {
    // construct ping query and others
    pub fn ping(transaction_id: u16, our_node_id: [u8; 20]) -> Message {
        Message {
            transaction_id,
            payload: Payload::Ping(Ping {
                id: Hash { bytes: our_node_id },
            }),
        }
    }
    pub fn find_node(
        transaction_id: u16,
        our_node_id: [u8; 20],
        peer_node_id: [u8; 20],
    ) -> Message {
        Message {
            transaction_id,
            payload: Payload::FindNode(FindNode {
                id: Hash { bytes: our_node_id },
                target: Hash {
                    bytes: peer_node_id,
                },
            }),
        }
    }
    pub fn get_peers(transaction_id: u16, our_node_id: [u8; 20], info_hash: [u8; 20]) -> Message {
        Message {
            transaction_id,
            payload: Payload::GetPeers(GetPeers {
                id: Hash { bytes: our_node_id },
                info_hash: Hash { bytes: info_hash },
            }),
        }
    }
    pub fn announce_peer(
        transaction_id: u16,
        our_node_id: [u8; 20],
        info_hash: [u8; 20],
        implied_port: Option<bool>,
        port: u16,
        token: Vec<u8>,
    ) -> Message {
        Message {
            transaction_id,
            payload: Payload::AnnouncePeer(AnnouncePeer {
                id: Hash { bytes: our_node_id },
                implied_port,
                info_hash: Hash { bytes: info_hash },
                port,
                token,
            }),
        }
    }
    pub fn response(
        transaction_id: u16,
        our_node_id: [u8; 20],
        nodes: Option<Vec<Node>>,
        values: Option<Vec<SocketAddrV4>>,
        token: Option<Vec<u8>>,
    ) -> Message {
        Message {
            transaction_id,
            payload: Payload::Response(Response {
                id: Hash { bytes: our_node_id },
                nodes,
                values,
                token,
            }),
        }
    }
    pub fn error(transaction_id: u16, code: i64, message: &str) -> Message {
        Message {
            transaction_id,
            payload: Payload::Error(Error {
                code,
                message: message.to_string(),
            }),
        }
    }
}

impl ToBencode for Message {
    const MAX_DEPTH: usize = 4;
    fn encode(&self, encoder: SingleItemEncoder) -> Result<(), encoding::Error> {
        encoder.emit_unsorted_dict(|e| {
            // adding "id"
            e.emit_pair(b"t", AsString(&self.transaction_id.to_be_bytes()))?;

            // adding "q"
            if let Some(q) = self.payload.query_name() {
                e.emit_pair(b"q", q)?;
            }

            // adding "y"
            e.emit_pair(b"y", self.payload.get_type())?;

            // adding payload "a"|"r"|"e":{..}
            e.emit_pair(&self.payload.get_type().bencode_key(), &self.payload)
        })
    }
}

