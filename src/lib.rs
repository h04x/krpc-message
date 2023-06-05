mod raw;
#[cfg(test)]
mod raw_tests;

use std::net::SocketAddrV4;

use bendy::{decoding::FromBencode, encoding::ToBencode};
use raw::{malformed, missing, Hash, MalformedError, MessageType, Node, QueryType, QueryArgs};

pub struct Ping {
    transaction_id: u16,
    sender_id: Hash,
}



impl TryFrom<raw::Message> for Ping {
    type Error = bendy::decoding::Error;
    fn try_from(rm: raw::Message) -> Result<Self, Self::Error> {
        let a = rm.query_args.ok_or(missing!("a"))?;
        Ok(Ping {
            transaction_id: rm.transaction_id,
            sender_id: a.sender_id,
        })
    }
}

impl Ping {
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
        }.to_bencode()
    }
}

pub struct FindNode {
    transaction_id: u16,
    sender_id: Hash,
    target: Hash,
}

impl TryFrom<raw::Message> for FindNode {
    type Error = bendy::decoding::Error;
    fn try_from(rm: raw::Message) -> Result<Self, Self::Error> {
        let a = rm.query_args.ok_or(missing!("a"))?;
        Ok(FindNode {
            transaction_id: rm.transaction_id,
            sender_id: a.sender_id,
            target: a.target.ok_or(missing!("target"))?,
        })
    }
}

impl FindNode {
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
        }.to_bencode()
    }
}

pub struct GetPeers {
    transaction_id: u16,
    sender_id: Hash,
    info_hash: Hash,
}

impl TryFrom<raw::Message> for GetPeers {
    type Error = bendy::decoding::Error;
    fn try_from(rm: raw::Message) -> Result<Self, Self::Error> {
        let a = rm.query_args.ok_or(missing!("a"))?;
        Ok(GetPeers {
            transaction_id: rm.transaction_id,
            sender_id: a.sender_id,
            info_hash: a.info_hash.ok_or(missing!("info_hash"))?,
        })
    }
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
        }.to_bencode()
    }
}

pub struct AnnouncePeer {
    transaction_id: u16,
    sender_id: Hash,
    info_hash: Hash,
    implied_port: Option<bool>,
    port: u16,
    token: Vec<u8>,
}

impl TryFrom<raw::Message> for AnnouncePeer {
    type Error = bendy::decoding::Error;
    fn try_from(rm: raw::Message) -> Result<Self, Self::Error> {
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
        }.to_bencode()
    }
}

pub struct Error {
    pub transaction_id: u16,
    pub code: i64,
    pub message: String,
}

impl TryFrom<raw::Message> for Error {
    type Error = bendy::decoding::Error;
    fn try_from(rm: raw::Message) -> Result<Self, Self::Error> {
        let e = rm.error.ok_or(missing!("e"))?;
        Ok(Error {
            transaction_id: rm.transaction_id,
            code: e.code,
            message: e.message,
        })
    }
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
        }.to_bencode()
    }
}

pub struct Response {
    pub transaction_id: u16,
    pub sender_id: Hash,
    pub nodes: Option<Vec<Node>>,
    pub values: Option<Vec<SocketAddrV4>>,
    pub token: Option<Vec<u8>>,
}

impl TryFrom<raw::Message> for Response {
    type Error = bendy::decoding::Error;
    fn try_from(rm: raw::Message) -> Result<Self, Self::Error> {
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
                token: self.token 
            }),
            error: None,
        }.to_bencode()
    }
}

enum Message {
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
                    QueryType::Ping => Message::Ping(rm.try_into()?),
                    QueryType::FindNone => Message::FindNode(rm.try_into()?),
                    QueryType::GetPeers => Message::GetPeers(rm.try_into()?),
                    QueryType::AnnouncePeer => Message::AnnouncePeer(rm.try_into()?),
                }
            }
            MessageType::Response => Message::Response(rm.try_into()?),
            MessageType::Error => Message::Error(rm.try_into()?),
        })
    }

    pub fn encode(self) -> Result<Vec<u8>, bendy::encoding::Error> {
        match self {
            Self::Ping(p) => p.encode(),
            Self::FindNode(f) => f.encode(),
            Self::GetPeers(g) => g.encode(),
            Self::AnnouncePeer(a) => a.encode(),
            Self::Response(r) => r.encode(),
            Self::Error(e) => e.encode()
        }
    }
}
