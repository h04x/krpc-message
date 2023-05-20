use std::assert_eq;

use bendy::{decoding::FromBencode, encoding::ToBencode};
use krpc_message::{Hash, Message, Node};

fn main() {
    let ping = Message::ping(24929 /* aa */, *b"abcdefghij0123456789");
    let ping_bencode = ping.to_bencode().unwrap();
    assert_eq!(
        &ping_bencode,
        b"d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe"
    );
    let find_node = Message::find_node(24929, *b"abcdefghij0123456789", *b"mnopqrstuvwxyz123456");
    let find_node_bencode = find_node.to_bencode().unwrap();
    assert_eq!(
        &find_node_bencode,
        b"d1:ad2:id20:abcdefghij01234567896:target20:mnopqrstuvwxyz123456e1:q9:find_node1:t2:aa1:y1:qe"
    );
    let get_peers = Message::get_peers(24929, *b"abcdefghij0123456789", *b"mnopqrstuvwxyz123456");
    let get_peers_bencode = get_peers.to_bencode().unwrap();
    assert_eq!(
        &get_peers_bencode,
        b"d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz123456e1:q9:get_peers1:t2:aa1:y1:qe"
    );
    let announce_peer = Message::announce_peer(
        24929,
        *b"abcdefghij0123456789",
        *b"mnopqrstuvwxyz123456",
        Some(true),
        6881,
        b"aoeusnth".to_vec(),
    );
    let announce_peer_bencode = announce_peer.to_bencode().unwrap();
    assert_eq!(
        &announce_peer_bencode,
        b"d1:ad2:id20:abcdefghij012345678912:implied_porti1e9:info_hash20:mnopqrstuvwxyz1234564:porti6881e5:token8:aoeusnthe1:q13:announce_peer1:t2:aa1:y1:qe"
    );
    let nodes = vec![
        Node {
            id: Hash {
                bytes: *b"mnopqrstuvwxyz123456",
            },
            addr: "65.66.67.68:24929".parse().unwrap(),
        },
        Node {
            id: Hash {
                bytes: *b"11111111111111111111",
            },
            addr: "69.70.71.72:24929".parse().unwrap(),
        },
    ];
    let values = vec![
        "65.66.67.68:24929".parse().unwrap(),
        "69.70.71.72:24929".parse().unwrap(),
    ];
    let response1 = Message::response(
        24929,
        *b"abcdefghij0123456789",
        None, // Some(nodes),
        Some(values),
        Some(b"aoeusnth".to_vec()),
    );
    let response1_bencode = response1.to_bencode().unwrap();
    assert_eq!(
        &response1_bencode,
        b"d1:rd2:id20:abcdefghij01234567895:token8:aoeusnth6:valuesl6:ABCDaa6:EFGHaaee1:t2:aa1:y1:re"
    );
    let response2 = Message::response(
        24929,
        *b"abcdefghij0123456789",
        Some(nodes),
        None, //Some(values),
        Some(b"aoeusnth".to_vec()),
    );
    let response2_bencode = response2.to_bencode().unwrap();
    assert_eq!(
        &response2_bencode,
        b"d1:rd2:id20:abcdefghij01234567895:nodes52:mnopqrstuvwxyz123456ABCDaa11111111111111111111EFGHaa5:token8:aoeusnthe1:t2:aa1:y1:re"
    );
    let error = Message::error(24929, 201, "A Generic Error Ocurred");
    let error_bencode = error.to_bencode().unwrap();
    assert_eq!(
        &error_bencode,
        b"d1:eli201e23:A Generic Error Ocurrede1:t2:aa1:y1:ee"
    );

    let msg = Message::from_bencode(&ping_bencode).unwrap();
    assert_eq!(ping, msg);
    let msg = Message::from_bencode(&find_node_bencode).unwrap();
    assert_eq!(find_node, msg);
    let msg = Message::from_bencode(&get_peers_bencode).unwrap();
    assert_eq!(get_peers, msg);
    let msg = Message::from_bencode(&announce_peer_bencode).unwrap();
    assert_eq!(announce_peer, msg);
    let msg = Message::from_bencode(&response1_bencode).unwrap();
    assert_eq!(response1, msg);
    let msg = Message::from_bencode(&response2_bencode).unwrap();
    assert_eq!(response2, msg);
    let msg = Message::from_bencode(&error_bencode).unwrap();
    assert_eq!(error, msg);
}
