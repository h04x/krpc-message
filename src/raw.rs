use std::{
    fmt::{self, Debug, Display},
    net::{IpAddr, SocketAddr, SocketAddrV4}, ops::Deref,
};

use bendy::{
    decoding::{FromBencode, Object, ResultExt},
    encoding::{AsString, SingleItemEncoder, ToBencode},
};

#[derive(Debug)]
pub struct MalformedError<T: Display>(pub T);
impl<T: Display + Debug> std::error::Error for MalformedError<T> {}
impl<T: Display> Display for MalformedError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
macro_rules! malformed {
    ($m:expr) => {
        bendy::decoding::Error::malformed_content(MalformedError($m))
    };
}
macro_rules! missing {
    ($m:expr) => {
        bendy::decoding::Error::missing_field($m)
    };
}

pub(crate) use malformed;
pub(crate) use missing;

#[derive(PartialEq, Clone)]
pub struct Hash {
    pub bytes: [u8; 20],
}

impl FromBencode for Hash {
    const EXPECTED_RECURSION_DEPTH: usize = 0;
    fn decode_bencode_object(object: Object) -> Result<Self, bendy::decoding::Error> {
        let s = object.try_into_bytes()?;
        Ok(Hash {
            bytes: s
                .try_into()
                .map_err(|_| malformed!("expected 20 bytes str"))?,
        })
    }
}

impl ToBencode for Hash {
    const MAX_DEPTH: usize = 0;
    fn encode(&self, encoder: SingleItemEncoder) -> Result<(), bendy::encoding::Error> {
        encoder.emit_bytes(&self.bytes)
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for c in self.bytes {
            write!(f, "{:02x}", c)?;
        }
        Ok(())
    }
}

impl Deref for Hash {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl From<&[u8; 20]> for Hash {
    fn from(bytes: &[u8; 20]) -> Self {
        Hash { bytes: *bytes }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum MessageType {
    Query,
    Response,
    Error,
}

impl FromBencode for MessageType {
    const EXPECTED_RECURSION_DEPTH: usize = 0;
    fn decode_bencode_object(object: Object) -> Result<Self, bendy::decoding::Error> {
        let s = object.try_into_bytes()?;
        Ok(match s {
            b"q" => Self::Query,
            b"r" => Self::Response,
            b"e" => Self::Error,
            _ => {
                return Err(malformed!("'y' must be q, r, or e"));
            }
        })
    }
}

impl ToBencode for MessageType {
    const MAX_DEPTH: usize = 0;

    fn encode(&self, encoder: SingleItemEncoder) -> Result<(), bendy::encoding::Error> {
        encoder.emit_bytes(match self {
            Self::Query => b"q",
            Self::Response => b"r",
            Self::Error => b"e",
        })
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum QueryType {
    Ping,
    FindNone,
    GetPeers,
    AnnouncePeer,
}

impl FromBencode for QueryType {
    const EXPECTED_RECURSION_DEPTH: usize = 0;
    fn decode_bencode_object(object: Object) -> Result<Self, bendy::decoding::Error> {
        let s = object.try_into_bytes()?;
        Ok(match s {
            b"ping" => Self::Ping,
            b"find_node" => Self::FindNone,
            b"get_peers" => Self::GetPeers,
            b"announce_peer" => Self::AnnouncePeer,
            _ => {
                return Err(malformed!("'q' must be one of 4 query types"));
            }
        })
    }
}

impl ToBencode for QueryType {
    const MAX_DEPTH: usize = 0;

    fn encode(&self, encoder: SingleItemEncoder) -> Result<(), bendy::encoding::Error> {
        encoder.emit_bytes(match self {
            Self::Ping => b"ping",
            Self::FindNone => b"find_node",
            Self::GetPeers => b"get_peers",
            Self::AnnouncePeer => b"announce_peer",
        })
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct QueryArgs {
    pub sender_id: Hash, // id
    pub target: Option<Hash>,
    pub info_hash: Option<Hash>,
    pub implied_port: Option<bool>,
    pub port: Option<u16>,
    pub token: Option<Vec<u8>>,
}

impl FromBencode for QueryArgs {
    const EXPECTED_RECURSION_DEPTH: usize = 0;
    fn decode_bencode_object(object: Object) -> Result<Self, bendy::decoding::Error> {
        let mut sender_id = None;
        let mut target = None;
        let mut info_hash = None;
        let mut implied_port = None;
        let mut port = None;
        let mut token = None;

        let mut dict = object.try_into_dictionary()?;
        while let Some(pair) = dict.next_pair()? {
            match pair {
                (b"id", value) => {
                    sender_id = Hash::decode_bencode_object(value).context("id").map(Some)?;
                }
                (b"implied_port", value) => {
                    implied_port = value
                        .try_into_integer()
                        .context("implied_port")
                        .map(|i| Some(i == "1"))?;
                }
                (b"info_hash", value) => {
                    info_hash = Hash::decode_bencode_object(value)
                        .context("info_hash")
                        .map(Some)?;
                }
                (b"port", value) => {
                    port = value
                        .try_into_integer()
                        .context("port")?
                        .parse::<u16>()
                        .map_err(|_| malformed!("must be valid integer"))
                        .map(Some)?;
                }
                (b"target", value) => {
                    target = Hash::decode_bencode_object(value)
                        .context("target")
                        .map(Some)?;
                }
                (b"token", value) => {
                    token = AsString::decode_bencode_object(value)
                        .context("token")
                        .map(|i| Some(i.0))?;
                }
                _ => continue,
            }
        }
        let sender_id = sender_id.ok_or(missing!("sender_id"))?;
        Ok(QueryArgs {
            sender_id,
            target,
            info_hash,
            implied_port,
            port,
            token,
        })
    }
}

impl ToBencode for QueryArgs {
    const MAX_DEPTH: usize = 0;

    fn encode(&self, encoder: SingleItemEncoder) -> Result<(), bendy::encoding::Error> {
        encoder.emit_dict(|mut e| {
            e.emit_pair(b"id", &self.sender_id)?;
            if let Some(implied_port) = &self.implied_port {
                e.emit_pair(b"implied_port", *implied_port as u8)?;
            }
            if let Some(info_hash) = &self.info_hash {
                e.emit_pair(b"info_hash", info_hash)?;
            }
            if let Some(port) = &self.port {
                e.emit_pair(b"port", port)?;
            }
            if let Some(target) = &self.target {
                e.emit_pair(b"target", target)?;
            }
            if let Some(token) = &self.token {
                e.emit_pair(b"token", AsString(token))?;
            }
            Ok(())
        })
    }
}

struct SocketAddrV4Wrap<T>(T);

impl TryFrom<&[u8]> for SocketAddrV4Wrap<SocketAddrV4> {
    type Error = ();
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != 6 {
            return Err(());
        }
        let (ip, port) = bytes.split_at(4);
        let ip = IpAddr::from(<[u8; 4]>::try_from(ip).unwrap());
        let port = u16::from_be_bytes(<[u8; 2]>::try_from(port).unwrap());
        Ok(match SocketAddr::from((ip, port)) {
            SocketAddr::V4(a) => SocketAddrV4Wrap(a),
            _ => unreachable!(),
        })
    }
}

impl From<&SocketAddrV4Wrap<&SocketAddrV4>> for [u8; 6] {
    fn from(addr: &SocketAddrV4Wrap<&SocketAddrV4>) -> Self {
        let mut bytes = [0u8; 6];
        bytes[0..4].copy_from_slice(&addr.0.ip().octets());
        bytes[4..6].copy_from_slice(&addr.0.port().to_be_bytes());
        bytes
    }
}

/*impl From<SocketAddrV4Wrap<&SocketAddrV4>> for [u8; 6] {
    fn from(addr: SocketAddrV4Wrap<&SocketAddrV4>) -> Self {
        let mut bytes = [0u8; 6];
        bytes[0..4].copy_from_slice(&addr.0.ip().octets());
        bytes[4..6].copy_from_slice(&addr.0.port().to_be_bytes());
        bytes
    }
}*/

impl From<SocketAddrV4Wrap<SocketAddrV4>> for [u8; 6] {
    fn from(addr: SocketAddrV4Wrap<SocketAddrV4>) -> Self {
        let mut bytes = [0u8; 6];
        bytes[0..4].copy_from_slice(&addr.0.ip().octets());
        bytes[4..6].copy_from_slice(&addr.0.port().to_be_bytes());
        bytes
    }
}

impl FromBencode for SocketAddrV4Wrap<SocketAddrV4> {
    const EXPECTED_RECURSION_DEPTH: usize = 0;
    fn decode_bencode_object(object: Object) -> Result<Self, bendy::decoding::Error> {
        let bytes = object.try_into_bytes()?;
        SocketAddrV4Wrap::try_from(bytes).map_err(|_| malformed!(" SocketAddrV4 must be 6 bytes"))
    }
}

impl ToBencode for SocketAddrV4Wrap<&SocketAddrV4> {
    const MAX_DEPTH: usize = 0;

    fn encode(&self, encoder: SingleItemEncoder) -> Result<(), bendy::encoding::Error> {
        encoder.emit_bytes(&Into::<[u8; 6]>::into(self))
    }
}

impl From<SocketAddrV4Wrap<SocketAddrV4>> for SocketAddrV4 {
    fn from(wrap: SocketAddrV4Wrap<SocketAddrV4>) -> Self {
        wrap.0
    }
}

#[derive(Debug, PartialEq, Clone)]
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
            addr: SocketAddrV4Wrap::try_from(addr).unwrap().into(),
        }
    }
}

impl From<&Node> for [u8; 26] {
    fn from(node: &Node) -> Self {
        let mut bytes = [0u8; 26];
        bytes[0..20].copy_from_slice(&node.id.bytes);
        bytes[20..26].copy_from_slice(&Into::<[u8; 6]>::into(SocketAddrV4Wrap(node.addr)));
        bytes
    }
}

impl From<(Hash, SocketAddrV4)> for Node {
    fn from(pair: (Hash, SocketAddrV4)) -> Self {
        let (id, addr) = pair;
        Node { id, addr }
    }
}

struct VecNodeWrap<T>(T);

impl FromBencode for VecNodeWrap<Vec<Node>> {
    const EXPECTED_RECURSION_DEPTH: usize = 0;
    fn decode_bencode_object(object: Object) -> Result<Self, bendy::decoding::Error> {
        let bytes = object.try_into_bytes()?;
        let chunks = bytes.chunks(26);
        let mut v = Vec::new();
        for chunk in chunks {
            v.push(Node::from(
                <[u8; 26]>::try_from(chunk).map_err(|_| malformed!("node must be 26 bytes"))?,
            ));
        }
        Ok(VecNodeWrap(v))
    }
}

impl<T> ToBencode for VecNodeWrap<T>
where
    T: AsRef<[Node]>,
{
    const MAX_DEPTH: usize = 0;

    fn encode(&self, encoder: SingleItemEncoder) -> Result<(), bendy::encoding::Error> {
        let mut bytes = Vec::new();
        for node in self.0.as_ref() {
            bytes.extend_from_slice(&Into::<[u8; 26]>::into(node))
        }
        encoder.emit_bytes(&bytes)
    }
}

impl From<VecNodeWrap<Vec<Node>>> for Vec<Node> {
    fn from(wrap: VecNodeWrap<Vec<Node>>) -> Self {
        wrap.0
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct Response {
    pub sender_id: Hash, // id
    pub nodes: Option<Vec<Node>>,
    pub values: Option<Vec<SocketAddrV4>>,
    pub token: Option<Vec<u8>>,
}

impl FromBencode for Response {
    const EXPECTED_RECURSION_DEPTH: usize = 0;
    fn decode_bencode_object(object: Object) -> Result<Self, bendy::decoding::Error> {
        let mut sender_id = None;
        let mut nodes: Option<Vec<Node>> = None;
        let mut values: Option<Vec<SocketAddrV4>> = None;
        let mut token = None;

        let mut dict = object.try_into_dictionary()?;
        while let Some(pair) = dict.next_pair()? {
            match pair {
                (b"id", value) => {
                    sender_id = Hash::decode_bencode_object(value).context("id").map(Some)?;
                }
                (b"nodes", value) => {
                    nodes = VecNodeWrap::decode_bencode_object(value)
                        .context("nodes")
                        .map(|i| Some(i.into()))?;
                }
                (b"values", value) => {
                    values = Vec::<SocketAddrV4Wrap<SocketAddrV4>>::decode_bencode_object(value)
                        .context("values")
                        .map(|v| Some(v.into_iter().map(|i| i.into()).collect()))?;
                }
                (b"token", value) => {
                    token = AsString::decode_bencode_object(value)
                        .context("token")
                        .map(|i| Some(i.0))?;
                }
                _ => continue,
            }
        }
        let sender_id = sender_id.ok_or(missing!("sender_id"))?;
        Ok(Response {
            sender_id,
            nodes,
            values,
            token,
        })
    }
}

impl ToBencode for Response {
    const MAX_DEPTH: usize = 0;

    fn encode(&self, encoder: SingleItemEncoder) -> Result<(), bendy::encoding::Error> {
        encoder.emit_dict(|mut e| {
            e.emit_pair(b"id", &self.sender_id)?;

            if let Some(nodes) = &self.nodes {
                e.emit_pair(b"nodes", VecNodeWrap(nodes))?;
            }
            if let Some(token) = &self.token {
                e.emit_pair(b"token", AsString(token))?;
            }
            if let Some(values) = &self.values {
                e.emit_pair(
                    b"values",
                    values.iter().map(SocketAddrV4Wrap).collect::<Vec<_>>(),
                )?;
            }
            Ok(())
        })
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct Error {
    pub code: i64,
    pub message: String,
}

impl FromBencode for Error {
    const EXPECTED_RECURSION_DEPTH: usize = 0;
    fn decode_bencode_object(object: Object) -> Result<Self, bendy::decoding::Error> {
        let mut list = object.try_into_list()?;
        let code = list.next_object()?.ok_or(missing!("code"))?;
        let code = i64::decode_bencode_object(code)?;
        let message = list.next_object()?.ok_or(missing!("message"))?;
        let message = String::decode_bencode_object(message)?;
        Ok(Error { code, message })
    }
}

impl ToBencode for Error {
    const MAX_DEPTH: usize = 0;

    fn encode(&self, encoder: SingleItemEncoder) -> Result<(), bendy::encoding::Error> {
        encoder.emit_list(|e| {
            e.emit_int(self.code)?;
            e.emit_str(&self.message)
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct Message {
    pub transaction_id: u16,           // t
    pub msg_type: MessageType,         // y
    pub query_type: Option<QueryType>, // q
    pub query_args: Option<QueryArgs>, // a
    pub response: Option<Response>,    // r
    pub error: Option<Error>,          // e
}

impl FromBencode for Message {
    const EXPECTED_RECURSION_DEPTH: usize = 3;
    fn decode_bencode_object(object: Object) -> Result<Self, bendy::decoding::Error> {
        let mut transaction_id = None;
        let mut msg_type = None;
        let mut query_type = None;
        let mut query_args = None;
        let mut response = None;
        let mut error = None;

        let mut dict = object.try_into_dictionary()?;
        while let Some(pair) = dict.next_pair()? {
            match pair {
                (b"t", value) => {
                    transaction_id = Some(u16::from_be_bytes(
                        value
                            .try_into_bytes()
                            .context("t")?
                            .try_into()
                            .map_err(|_| malformed!("t must be 2 byte str"))?,
                    ));
                }
                (b"y", value) => {
                    msg_type = MessageType::decode_bencode_object(value)
                        .context("y")
                        .map(Some)?;
                }
                (b"q", value) => {
                    query_type = QueryType::decode_bencode_object(value)
                        .context("q")
                        .map(Some)?;
                }
                (b"a", value) => {
                    query_args = QueryArgs::decode_bencode_object(value)
                        .context("a")
                        .map(Some)?;
                }
                (b"r", value) => {
                    response = Response::decode_bencode_object(value)
                        .context("r")
                        .map(Some)?;
                }
                (b"e", value) => {
                    error = Error::decode_bencode_object(value).context("e").map(Some)?;
                }
                _ => continue,
            }
        }
        let transaction_id = transaction_id.ok_or(missing!("t"))?;
        let msg_type = msg_type.ok_or(missing!("y"))?;
        Ok(Message {
            transaction_id,
            msg_type,
            query_type,
            query_args,
            response,
            error,
        })
    }
}

impl ToBencode for Message {
    const MAX_DEPTH: usize = 3;

    fn encode(&self, encoder: SingleItemEncoder) -> Result<(), bendy::encoding::Error> {
        encoder.emit_dict(|mut e| {
            if let Some(query_args) = &self.query_args {
                e.emit_pair(b"a", query_args)?;
            }
            if let Some(error) = &self.error {
                e.emit_pair(b"e", error)?;
            }
            if let Some(query_type) = &self.query_type {
                e.emit_pair(b"q", query_type)?;
            }
            if let Some(response) = &self.response {
                e.emit_pair(b"r", response)?;
            }
            e.emit_pair(b"t", AsString(self.transaction_id.to_be_bytes()))?;
            e.emit_pair(b"y", &self.msg_type)?;
            Ok(())
        })
    }
}
