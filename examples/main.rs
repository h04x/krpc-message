use std::assert_eq;

use bendy::{decoding::FromBencode, encoding::ToBencode};
use krpc_message::Message;

fn main() {
    //let deserialized = bendy::serde::from_bytes::<Foo>(b"d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe").unwrap();
    let ping =
        Message::from_bencode(b"d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe").unwrap();
    let find_node = Message::from_bencode(b"d1:ad2:id20:abcdefghij01234567896:target20:mnopqrstuvwxyz123456e1:q9:find_node1:t2:aa1:y1:qe").unwrap();
    let get_peers = Message::from_bencode( b"d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz123456e1:q9:get_peers1:t2:aa1:y1:qe").unwrap();
    let announce_peer = Message::from_bencode(b"d1:ad2:id20:abcdefghij012345678912:implied_porti1e9:info_hash20:mnopqrstuvwxyz1234564:porti6881e5:token8:aoeusnthe1:q13:announce_peer1:t2:aa1:y1:qe").unwrap();
    let response = Message::from_bencode(b"d1:rd2:id20:abcdefghij01234567895:token8:aoeusnth6:valuesl6:ABCDaa6:EFGHaaee1:t2:aa1:y1:re").unwrap();
    let response2 = Message::from_bencode(b"d1:rd2:id20:abcdefghij01234567895:nodes52:mnopqrstuvwxyz123456ABCDaa11111111111111111111EFGHaa5:token8:aoeusnthe1:t2:aa1:y1:re").unwrap();
    let error =
        Message::from_bencode(b"d1:eli201e23:A Generic Error Ocurrede1:t2:aa1:y1:ee").unwrap();

    dbg!(String::from_utf8_lossy(&ping.to_bencode().unwrap()));
}
