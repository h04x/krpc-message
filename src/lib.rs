use std::{
    borrow::{Borrow, Cow},
    collections::BTreeMap,
    fmt::{self, Debug, Display},
    net::{IpAddr, SocketAddr, SocketAddrV4},
};

use bendy::{
    decoding::{FromBencode, Object, ResultExt},
    value::Value,
};

#[derive(Debug)]
struct MalformedError<T: Display>(T);
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

trait UnwrapValue<'a> {
    fn try_bytes(&self) -> Option<&Cow<'a, [u8]>>;
}

impl<'a> UnwrapValue<'a> for Value<'a> {
    fn try_bytes(&self) -> Option<&Cow<'a, [u8]>> {
        match self {
            Value::Bytes(v) => Some(v),
            _ => None,
        }
    }
}

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

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for c in self.bytes {
            write!(f, "{:02x}", c)?;
        }
        Ok(())
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

#[derive(Debug, PartialEq, Clone)]
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

#[derive(Debug, PartialEq, Clone)]
pub struct QueryArgs {
    sender_id: Hash, // id
    target: Option<Hash>,
    info_hash: Option<Hash>,
    implied_port: Option<bool>,
    port: Option<u16>,
    token: Option<Vec<u8>>,
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
                    implied_port = value
                        .try_into_integer()
                        .context("implied_port")
                        .map(|i| Some(i == "1"))?;
                }
                (b"port", value) => {
                    port = value
                        .try_into_integer()
                        .context("port")?
                        .parse::<u16>()
                        .map_err(|_| malformed!("must be valid integer"))
                        .map(Some)?;
                }
                (b"token", value) => {
                    token = Vec::<u8>::decode_bencode_object(value)
                        .context("token")
                        .map(Some)?;
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

struct SocketAddrV4Wrap(SocketAddrV4);

impl FromBencode for SocketAddrV4Wrap {
    const EXPECTED_RECURSION_DEPTH: usize = 0;
    fn decode_bencode_object(object: Object) -> Result<Self, bendy::decoding::Error> {
        let bytes = object.try_into_bytes()?;
        if bytes.len() != 6 {
            return Err(malformed!("sockaddr4 must be 6 bytes len"));
        }
        let (ip, port) = bytes.split_at(4);
        let ip = IpAddr::from(<[u8; 4]>::try_from(ip).unwrap());
        let port = u16::from_be_bytes(<[u8; 2]>::try_from(port).unwrap());
        Ok(match SocketAddr::from((ip, port)) {
            SocketAddr::V4(a) => SocketAddrV4Wrap(a),
            _ => panic!(),
        })
    }
}

impl From<SocketAddrV4Wrap> for SocketAddrV4 {
    fn from(wrap: SocketAddrV4Wrap) -> Self {
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
            addr: SocketAddrV4Wrap::from_bencode(addr).unwrap().into(),
        }
    }
}

struct VecNodeWrap(Vec<Node>);

impl FromBencode for VecNodeWrap {
    const EXPECTED_RECURSION_DEPTH: usize = 0;
    fn decode_bencode_object(object: Object) -> Result<Self, bendy::decoding::Error> {
        let bytes = object.try_into_bytes()?;
        let chunks = bytes.chunks(26);
        let mut v = Vec::new();
        for chunk in chunks {
            v.push(Node::from(
                <[u8; 26]>::try_from(chunk).map_err(|e| malformed!("node must be 26 bytes"))?,
            ));
        }
        Ok(VecNodeWrap(v))
    }
}

impl From<VecNodeWrap> for Vec<Node> {
    fn from(wrap: VecNodeWrap) -> Self {
        wrap.0
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct Response {
    pub sender_id: Hash,
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
                    values = Vec::<SocketAddrV4Wrap>::decode_bencode_object(value)
                        .context("values")
                        .map(|v| Some(v.into_iter().map(|i| i.into()).collect()))?;
                }
                (b"token", value) => {
                    token = Vec::<u8>::decode_bencode_object(value)
                        .context("token")
                        .map(Some)?;
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

#[derive(Debug)]
pub struct Message {
    transaction_id: u16,           // t
    msg_type: MessageType,         // y
    query_type: Option<QueryType>, // q
    query_args: Option<QueryArgs>,       // a
    response: Option<Response>,    // r
    error: Option<Error>,          // e
}

impl FromBencode for Message {
    const EXPECTED_RECURSION_DEPTH: usize = 2;
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
