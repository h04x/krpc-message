mod raw;
#[cfg(test)]
mod raw_tests;

use std::net::SocketAddrV4;

use bendy::decoding::FromBencode;
use raw::{malformed, missing, Hash, MalformedError, MessageType, Node, QueryType};

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
}
