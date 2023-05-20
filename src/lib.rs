use bendy::{
    decoding::{self, FromBencode, Object, ResultExt},
    encoding::{self, AsString, SingleItemEncoder, ToBencode},
    value::Value,
};
use std::{
    fmt,
    net::{IpAddr, SocketAddr, SocketAddrV4},
    ops::Deref,
};

trait IntoBytes {
    fn into_bytes(&self) -> Vec<u8>;
}

trait FromBytes {
    type Output;
    fn from_bytes(bytes: &[u8]) -> Self::Output;
}

#[derive(Debug)]
struct MalformedContent {
    msg: String,
}

impl From<&str> for MalformedContent {
    fn from(msg: &str) -> Self {
        MalformedContent { msg: msg.into() }
    }
}

impl fmt::Display for MalformedContent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.msg)
    }
}

impl std::error::Error for MalformedContent {}

impl FromBytes for Vec<Node> {
    type Output = Result<Self, decoding::Error>;
    fn from_bytes(bytes: &[u8]) -> Self::Output {
        let chunks = bytes.chunks(26);
        let mut v = Vec::new();
        for chunk in chunks {
            v.push(Node::from(<[u8; 26]>::try_from(chunk)?));
        }
        Ok(v)
    }
}

impl FromBytes for Vec<SocketAddrV4> {
    type Output = Result<Self, decoding::Error>;
    fn from_bytes(bytes: &[u8]) -> Self::Output {
        let chunks = bytes.chunks(6);
        let mut v = Vec::new();
        for chunk in chunks {
            v.push(SocketAddrV4::from_bytes(bytes)?);
        }
        Ok(v)
    }
}

impl FromBytes for SocketAddrV4 {
    type Output = Result<Self, decoding::Error>;
    fn from_bytes(bytes: &[u8]) -> Self::Output {
        if bytes.len() != 6 {
            return Err(decoding::Error::malformed_content(MalformedContent::from(
                "sockaddr must be 6 bytes len",
            )));
        }
        let (ip, port) = bytes.split_at(4);
        let ip = IpAddr::from(<[u8; 4]>::try_from(ip).unwrap());
        let port = u16::from_be_bytes(<[u8; 2]>::try_from(port).unwrap());
        Ok(match SocketAddr::from((ip, port)) {
            SocketAddr::V4(a) => a,
            _ => panic!(),
        })
    }
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

impl FromBencode for Hash {
    const EXPECTED_RECURSION_DEPTH: usize = 0;
    fn decode_bencode_object(object: Object) -> Result<Self, decoding::Error> {
        Ok(Hash {
            bytes: object.try_into_bytes()?.try_into()?,
        })
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

impl From<[u8; 26]> for Node {
    fn from(bytes: [u8; 26]) -> Self {
        let (id, addr) = bytes.split_at(20);
        Node {
            id: Hash {
                bytes: id.try_into().unwrap(),
            },
            addr: SocketAddrV4::from_bytes(addr).unwrap(),
        }
    }
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
                    values
                        .iter()
                        .map(|s| AsString(s.into_bytes()))
                        .collect::<Vec<_>>(),
                )?;
            }
            Ok(())
        })
    }
}

impl FromBencode for Response {
    const EXPECTED_RECURSION_DEPTH: usize = 0;
    fn decode_bencode_object(object: Object) -> Result<Self, decoding::Error> {
        let mut id = None;
        let mut nodes = None;
        let mut values = None;
        let mut token = None;

        let mut dict = object.try_into_dictionary()?;
        while let Some(pair) = dict.next_pair()? {
            match pair {
                (b"id", value) => {
                    id = Hash::decode_bencode_object(value).context("y").map(Some)?;
                }
                (b"nodes", value) => {
                    nodes = Vec::<Node>::from_bytes(value.try_into_bytes().context("nodes")?)
                        .map(Some)?;
                }
                (b"values", value) => {
                    values = Vec::<SocketAddrV4>::from_bytes(value.try_into_bytes().context("values")?)
                        .map(Some)?;
                }
                (b"token", value) => {
                    token = Some(value.try_into_bytes().context("token")?.to_vec())
                }
                _ => continue,
            }
        }
        Ok(Response {
            id: id.ok_or_else(|| decoding::Error::missing_field("id"))?,
            nodes,
            values,
            token,
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

impl FromBencode for Error {
    const EXPECTED_RECURSION_DEPTH: usize = 0;

    fn decode_bencode_object(object: Object) -> Result<Self, decoding::Error> {

        let mut list = object.try_into_list()?;
        let code = list.next_object()?.ok_or(decoding::Error::missing_field("code"))?;
        let code = i64::decode_bencode_object(code)?;
        let message = list.next_object()?.ok_or(decoding::Error::missing_field("code"))?;
        let message = String::decode_bencode_object(message)?;
        Ok(Error {
            code,
            message
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

struct A {
    id: Hash,
    target: Option<Hash>,
    info_hash: Option<Hash>,
    implied_port: Option<bool>,
    port: Option<u16>,
    token: Option<Vec<u8>>,
}

impl FromBencode for A {
    const EXPECTED_RECURSION_DEPTH: usize = 0;
    fn decode_bencode_object(object: Object) -> Result<Self, decoding::Error> {
        let mut id = None;
        let mut target = None;
        let mut info_hash = None;
        let mut implied_port = None;
        let mut port = None;
        let mut token = None;

        let mut dict = object.try_into_dictionary()?;
        while let Some(pair) = dict.next_pair()? {
            match pair {
                (b"id", value) => {
                    id = Hash::decode_bencode_object(value).context("y").map(Some)?;
                }
                (b"target", value) => {
                    target = Hash::decode_bencode_object(value)
                        .context("target")
                        .map(Some)?;
                }
                (b"info_hash", value) => {
                    info_hash = Hash::decode_bencode_object(value)
                        .context("info_hash")
                        .map(Some)?;
                }
                (b"implied_port", value) => {
                    implied_port = Some(
                        value
                            .try_into_integer()
                            .context("implied_port")?
                            .parse::<u8>()?
                            > 0,
                    )
                }
                (b"port", value) => {
                    port = value
                        .try_into_integer()
                        .context("port")?
                        .parse::<u16>()
                        .map(Some)?;
                }
                (b"token", value) => {
                    token = Some(value.try_into_bytes().context("token")?.to_vec())
                }
                _ => continue,
            }
        }
        Ok(A {
            id: id.ok_or_else(|| decoding::Error::missing_field("id"))?,
            implied_port,
            target,
            info_hash,
            port,
            token,
        })
    }
}

impl FromBencode for Message {
    const EXPECTED_RECURSION_DEPTH: usize = 2;

    fn decode_bencode_object(object: Object) -> Result<Self, decoding::Error> {
        let mut transaction_id = None;
        let mut msg_type = None;
        let mut query_type = None;
        let mut a = None;
        let mut r = None;
        let mut e = None;

        let mut dict = object.try_into_dictionary()?;
        while let Some(pair) = dict.next_pair()? {
            match pair {
                (b"t", value) => {
                    transaction_id = Some(u16::from_be_bytes(value.try_into_bytes()?.try_into()?));
                }
                (b"y", value) => {
                    msg_type = String::decode_bencode_object(value)
                        .context("y")
                        .map(Some)?;
                }
                (b"q", value) => {
                    query_type = String::decode_bencode_object(value)
                        .context("q")
                        .map(Some)?;
                }
                (b"a", value) => {
                    a = A::decode_bencode_object(value).context("y").map(Some)?;
                }
                (b"r", value) => {
                    r = Response::decode_bencode_object(value)
                        .context("r")
                        .map(Some)?;
                }
                (b"e", value) => {
                    e = Error::decode_bencode_object(value)
                        .context("e")
                        .map(Some)?;
                }
                _ => continue,
            }
        }

        let transaction_id =
            transaction_id.ok_or_else(|| decoding::Error::missing_field("transaction_id"))?;
        todo!()
    }
}
