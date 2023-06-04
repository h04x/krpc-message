use std::assert_eq;

use bendy::decoding::FromBencode;
use krpc_message::Message;

fn main() {
    //let deserialized = bendy::serde::from_bytes::<Foo>(b"d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe").unwrap();
    let m =
        Message::from_bencode(b"d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe").unwrap();
        dbg!(m);
}
