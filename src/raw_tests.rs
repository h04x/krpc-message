use bendy::{decoding::FromBencode, encoding::ToBencode};

use crate::raw::{Error, Hash, Message, MessageType, Node, QueryArgs, QueryType, Response};

fn ser_deser(bytes: &[u8], msg: Message) {
    let m = Message::from_bencode(bytes).unwrap();
    assert_eq!(m, msg);
    let b = m.to_bencode().unwrap();
    assert_eq!(b, bytes);
}

#[test]
fn test() {
    let ping = (
        b"d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe",
        Message {
            transaction_id: 24929,
            msg_type: MessageType::Query,
            query_type: Some(QueryType::Ping),
            query_args: Some(QueryArgs {
                sender_id: b"abcdefghij0123456789".into(),
                target: None,
                info_hash: None,
                implied_port: None,
                port: None,
                token: None,
            }),
            response: None,
            error: None,
        },
    );
    ser_deser(ping.0, ping.1);

    let find_node = (
        b"d1:ad2:id20:abcdefghij01234567896:target20:mnopqrstuvwxyz123456e1:q9:find_node1:t2:aa1:y1:qe", 
        Message {
            transaction_id: 24929,
            msg_type: MessageType::Query,
            query_type: Some(QueryType::FindNone),
            query_args: Some(QueryArgs {
                sender_id: b"abcdefghij0123456789".into(),
                target: Some(b"mnopqrstuvwxyz123456".into()),
                info_hash: None,
                implied_port: None,
                port: None,
                token: None,
            }),
            response: None,
            error: None,
        }
    );
    ser_deser(find_node.0, find_node.1);

    let get_peers = (
        b"d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz123456e1:q9:get_peers1:t2:aa1:y1:qe",
        Message {
            transaction_id: 24929,
            msg_type: MessageType::Query,
            query_type: Some(QueryType::GetPeers),
            query_args: Some(QueryArgs {
                sender_id: b"abcdefghij0123456789".into(),
                target: None,
                info_hash: Some(b"mnopqrstuvwxyz123456".into()),
                implied_port: None,
                port: None,
                token: None,
            }),
            response: None,
            error: None,
        }
    );
    ser_deser(get_peers.0, get_peers.1);

    let announce_peer = (
        b"d1:ad2:id20:abcdefghij012345678912:implied_porti1e9:info_hash20:mnopqrstuvwxyz1234564:porti6881e5:token8:aoeusnthe1:q13:announce_peer1:t2:aa1:y1:qe",
        Message {
            transaction_id: 24929,
            msg_type: MessageType::Query,
            query_type: Some(QueryType::AnnouncePeer),
            query_args: Some(QueryArgs {
                sender_id: b"abcdefghij0123456789".into(),
                target: None,
                info_hash: Some(b"mnopqrstuvwxyz123456".into()),
                implied_port: Some(true),
                port: Some(6881),
                token: Some(b"aoeusnth".to_vec()),
            }),
            response: None,
            error: None,
        }
    );
    ser_deser(announce_peer.0, announce_peer.1);

    let response1 = (
        b"d1:rd2:id20:abcdefghij01234567895:token8:aoeusnth6:valuesl6:ABCDaa6:EFGHaaee1:t2:aa1:y1:re",
        Message {
            transaction_id: 24929,
            msg_type: MessageType::Response,
            query_type: None,
            query_args: None,
            response: Some(Response {
                sender_id: b"abcdefghij0123456789".into(), 
                nodes: None,
                values: Some(vec![
                    "65.66.67.68:24929".parse().unwrap(), 
                    "69.70.71.72:24929".parse().unwrap()]), 
                token: Some(b"aoeusnth".to_vec()) 
            }),
            error: None,
        }
    );
    ser_deser(response1.0, response1.1);

    let response2 = (
        b"d1:rd2:id20:abcdefghij01234567895:nodes52:mnopqrstuvwxyz123456ABCDaa11111111111111111111EFGHaa5:token8:aoeusnthe1:t2:aa1:y1:re",
        Message {
            transaction_id: 24929,
            msg_type: MessageType::Response,
            query_type: None,
            query_args: None,
            response: Some(Response {
                sender_id: b"abcdefghij0123456789".into(), 
                nodes: Some(vec![
                    (b"mnopqrstuvwxyz123456".into(), "65.66.67.68:24929".parse().unwrap()).into(),
                    (b"11111111111111111111".into(), "69.70.71.72:24929".parse().unwrap()).into()]), 
                values: None,
                token: Some(b"aoeusnth".to_vec()) 
            }),
            error: None,
        }
    );
    ser_deser(response2.0, response2.1);

    let error = (
        b"d1:eli201e23:A Generic Error Ocurrede1:t2:aa1:y1:ee",
        Message {
            transaction_id: 24929,
            msg_type: MessageType::Error,
            query_type: None,
            query_args: None,
            response: None,
            error: Some(Error {
                code: 201,
                message: "A Generic Error Ocurred".to_string(),
            }),
        },
    );
    ser_deser(error.0, error.1);
}
