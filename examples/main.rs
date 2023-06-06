use krpc_message::{raw::Hash, Message, Ping};
use std::assert_eq;

fn main() {
    let ping = Ping::new(24929, b"abcdefghij0123456789");
    let bencode = b"d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe";

    assert_eq!(ping.clone().encode().unwrap(), bencode);
    assert_eq!(Message::Ping(ping), Message::decode(bencode).unwrap());
}
