pub mod raw;
#[cfg(test)]
mod raw_tests;

use std::net::SocketAddrV4;

use bendy::{decoding::FromBencode, encoding::ToBencode};
use raw::{missing, Hash, MessageType, Node, QueryArgs, QueryType};

#[derive(Clone, Debug, PartialEq)]
pub struct Ping {
    transaction_id: u16,
    sender_id: Hash,
}

impl Ping {
    pub fn new<T: Into<Hash>>(transaction_id: u16, sender_id: T) -> Self {
        Ping {
            transaction_id,
            sender_id: sender_id.into(),
        }
    }

    pub fn encode(self) -> Result<Vec<u8>, bendy::encoding::Error> {
        raw::Message {
            transaction_id: self.transaction_id,
            msg_type: MessageType::Query,
            query_type: Some(QueryType::Ping),
            query_args: Some(QueryArgs {
                sender_id: self.sender_id,
                target: None,
                info_hash: None,
                implied_port: None,
                port: None,
                token: None,
            }),
            response: None,
            error: None,
        }
        .to_bencode()
    }

    fn from_raw_msg(rm: raw::Message) -> Result<Self, bendy::decoding::Error> {
        let a = rm.query_args.ok_or(missing!("a"))?;
        Ok(Ping {
            transaction_id: rm.transaction_id,
            sender_id: a.sender_id,
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct FindNode {
    transaction_id: u16,
    sender_id: Hash,
    target: Hash,
}

impl FindNode {
    pub fn new<T, B>(transaction_id: u16, sender_id: T, target: B) -> Self
    where
        T: Into<Hash>,
        B: Into<Hash>,
    {
        FindNode {
            transaction_id,
            sender_id: sender_id.into(),
            target: target.into(),
        }
    }

    pub fn encode(self) -> Result<Vec<u8>, bendy::encoding::Error> {
        raw::Message {
            transaction_id: self.transaction_id,
            msg_type: MessageType::Query,
            query_type: Some(QueryType::FindNone),
            query_args: Some(QueryArgs {
                sender_id: self.sender_id,
                target: Some(self.target),
                info_hash: None,
                implied_port: None,
                port: None,
                token: None,
            }),
            response: None,
            error: None,
        }
        .to_bencode()
    }

    fn from_raw_msg(rm: raw::Message) -> Result<Self, bendy::decoding::Error> {
        let a = rm.query_args.ok_or(missing!("a"))?;
        Ok(FindNode {
            transaction_id: rm.transaction_id,
            sender_id: a.sender_id,
            target: a.target.ok_or(missing!("target"))?,
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct GetPeers {
    transaction_id: u16,
    sender_id: Hash,
    info_hash: Hash,
}

impl GetPeers {
    pub fn encode(self) -> Result<Vec<u8>, bendy::encoding::Error> {
        raw::Message {
            transaction_id: self.transaction_id,
            msg_type: MessageType::Query,
            query_type: Some(QueryType::GetPeers),
            query_args: Some(QueryArgs {
                sender_id: self.sender_id,
                target: None,
                info_hash: Some(self.info_hash),
                implied_port: None,
                port: None,
                token: None,
            }),
            response: None,
            error: None,
        }
        .to_bencode()
    }

    fn from_raw_msg(rm: raw::Message) -> Result<Self, bendy::decoding::Error> {
        let a = rm.query_args.ok_or(missing!("a"))?;
        Ok(GetPeers {
            transaction_id: rm.transaction_id,
            sender_id: a.sender_id,
            info_hash: a.info_hash.ok_or(missing!("info_hash"))?,
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct AnnouncePeer {
    transaction_id: u16,
    sender_id: Hash,
    info_hash: Hash,
    implied_port: Option<bool>,
    port: u16,
    token: Vec<u8>,
}

impl AnnouncePeer {
    pub fn encode(self) -> Result<Vec<u8>, bendy::encoding::Error> {
        raw::Message {
            transaction_id: self.transaction_id,
            msg_type: MessageType::Query,
            query_type: Some(QueryType::AnnouncePeer),
            query_args: Some(QueryArgs {
                sender_id: self.sender_id,
                target: None,
                info_hash: Some(self.info_hash),
                implied_port: self.implied_port,
                port: Some(self.port),
                token: Some(self.token),
            }),
            response: None,
            error: None,
        }
        .to_bencode()
    }

    fn from_raw_msg(rm: raw::Message) -> Result<Self, bendy::decoding::Error> {
        let a = rm.query_args.ok_or(missing!("a"))?;
        Ok(AnnouncePeer {
            transaction_id: rm.transaction_id,
            sender_id: a.sender_id,
            info_hash: a.info_hash.ok_or(missing!("info_hash"))?,
            implied_port: a.implied_port,
            port: a.port.ok_or(missing!("port"))?,
            token: a.token.ok_or(missing!("token"))?,
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Error {
    pub transaction_id: u16,
    pub code: i64,
    pub message: String,
}

impl Error {
    pub fn encode(self) -> Result<Vec<u8>, bendy::encoding::Error> {
        raw::Message {
            transaction_id: self.transaction_id,
            msg_type: MessageType::Error,
            query_type: None,
            query_args: None,
            response: None,
            error: Some(raw::Error {
                code: self.code,
                message: self.message,
            }),
        }
        .to_bencode()
    }

    fn from_raw_msg(rm: raw::Message) -> Result<Self, bendy::decoding::Error> {
        let e = rm.error.ok_or(missing!("e"))?;
        Ok(Error {
            transaction_id: rm.transaction_id,
            code: e.code,
            message: e.message,
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Response {
    pub transaction_id: u16,
    pub sender_id: Hash,
    pub nodes: Option<Vec<Node>>,
    pub values: Option<Vec<SocketAddrV4>>,
    pub token: Option<Vec<u8>>,
}

impl Response {
    pub fn encode(self) -> Result<Vec<u8>, bendy::encoding::Error> {
        raw::Message {
            transaction_id: self.transaction_id,
            msg_type: MessageType::Response,
            query_type: None,
            query_args: None,
            response: Some(raw::Response {
                sender_id: self.sender_id,
                nodes: self.nodes,
                values: self.values,
                token: self.token,
            }),
            error: None,
        }
        .to_bencode()
    }

    fn from_raw_msg(rm: raw::Message) -> Result<Self, bendy::decoding::Error> {
        let r = rm.response.ok_or(missing!("r"))?;
        Ok(Response {
            transaction_id: rm.transaction_id,
            sender_id: r.sender_id,
            nodes: r.nodes,
            values: r.values,
            token: r.token,
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Message {
    Ping(Ping),
    FindNode(FindNode),
    GetPeers(GetPeers),
    AnnouncePeer(AnnouncePeer),
    Response(Response),
    Error(Error),
}

impl Message {
    pub fn decode(bytes: &[u8]) -> Result<Self, bendy::decoding::Error> {
        let rm = raw::Message::from_bencode(bytes)?;
        Ok(match rm.msg_type {
            MessageType::Query => {
                let qt = rm.query_type.ok_or(missing!("q"))?;
                match qt {
                    QueryType::Ping => Message::Ping(Ping::from_raw_msg(rm)?),
                    QueryType::FindNone => Message::FindNode(FindNode::from_raw_msg(rm)?),
                    QueryType::GetPeers => Message::GetPeers(GetPeers::from_raw_msg(rm)?),
                    QueryType::AnnouncePeer => {
                        Message::AnnouncePeer(AnnouncePeer::from_raw_msg(rm)?)
                    }
                }
            }
            MessageType::Response => Message::Response(Response::from_raw_msg(rm)?),
            MessageType::Error => Message::Error(Error::from_raw_msg(rm)?),
        })
    }

    pub fn encode(self) -> Result<Vec<u8>, bendy::encoding::Error> {
        match self {
            Self::Ping(p) => p.encode(),
            Self::FindNode(f) => f.encode(),
            Self::GetPeers(g) => g.encode(),
            Self::AnnouncePeer(a) => a.encode(),
            Self::Response(r) => r.encode(),
            Self::Error(e) => e.encode(),
        }
    }
}
