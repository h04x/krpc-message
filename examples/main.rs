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

    let msg = Message::from_bencode(&ping_bencode).unwrap();
    assert_eq!(ping, msg);
}
