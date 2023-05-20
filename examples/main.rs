use bendy::{decoding::FromBencode, encoding::ToBencode};
use krpc_message::{Hash, Message, Node};

fn main() {
    let ping = Message::ping(24929 /* aa */, *b"abcdefghij0123456789");
    assert_eq!(
        &ping.to_bencode().unwrap(),
        b"d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe"
    );
    let find_node = Message::find_node(24929, *b"abcdefghij0123456789", *b"mnopqrstuvwxyz123456");
    assert_eq!(
        &find_node.to_bencode().unwrap(),
        b"d1:ad2:id20:abcdefghij01234567896:target20:mnopqrstuvwxyz123456e1:q9:find_node1:t2:aa1:y1:qe"
    );
    let get_peers = Message::get_peers(24929, *b"abcdefghij0123456789", *b"mnopqrstuvwxyz123456");
    assert_eq!(
        &get_peers.to_bencode().unwrap(),
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
    assert_eq!(
        &announce_peer.to_bencode().unwrap(),
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
    let response = Message::response(
        24929,
        *b"abcdefghij0123456789",
        None, // Some(nodes),
        Some(values),
        Some(b"aoeusnth".to_vec()),
    );
    assert_eq!(
        &response.to_bencode().unwrap(),
        b"d1:rd2:id20:abcdefghij01234567895:token8:aoeusnth6:valuesl6:ABCDaa6:EFGHaaee1:t2:aa1:y1:re"
    );
    let response = Message::response(
        24929,
        *b"abcdefghij0123456789",
        Some(nodes),
        None, //Some(values),
        Some(b"aoeusnth".to_vec()),
    );
    assert_eq!(
        &response.to_bencode().unwrap(),
        b"d1:rd2:id20:abcdefghij01234567895:nodes52:mnopqrstuvwxyz123456ABCDaa11111111111111111111EFGHaa5:token8:aoeusnthe1:t2:aa1:y1:re"
    );
    let error = Message::error(24929, 201, "A Generic Error Ocurred");
    assert_eq!(
        &error.to_bencode().unwrap(),
        b"d1:eli201e23:A Generic Error Ocurrede1:t2:aa1:y1:ee"
    );

    let msg = Message::from_bencode(&ping.to_bencode().unwrap()).unwrap();
}
