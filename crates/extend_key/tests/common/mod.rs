use extend_key::base58::*;
use extend_key::ecdsa_key::{PrvKeyBytes, PubKeyBytes};
use extend_key::extkey::*;
use hdpath::node::Node;
use hdpath::path::HDPath;

pub trait PrvPub<'a> {
    fn private(&self) -> &'a str;
    fn public(&self) -> &'a str;
}

impl<'a> PrvPub<'a> for (&'a str, &'a str) {
    fn private(&self) -> &'a str {
        self.0
    }

    fn public(&self) -> &'a str {
        self.1
    }
}

fn do_check<'a, A: PrvPub<'a>>(parent: A, node: Node, child: A) -> A {
    fn parse_key(s: &str) -> DecodedExtKey {
        let a = s.parse().unwrap();
        assert_eq!(s, s.to_string().as_str());
        a
    }

    let parent_prv: ExtKey<PrvKeyBytes> = parse_key(parent.private()).try_into().unwrap();
    let parent_pub: ExtKey<PubKeyBytes> = parse_key(parent.public()).try_into().unwrap();

    assert_eq!(parent.private(), parent_prv.to_string().as_str());
    assert_eq!(parent.public(), parent_pub.to_string().as_str());

    assert_eq!(parent_pub, parent_prv.get_public().unwrap());

    let child_prv = parent_prv.get_child(node).unwrap();
    let child_pub = child_prv.get_public().unwrap();
    if node.is_normal() {
        assert_eq!(child_pub, parent_pub.get_child_normal_only(node).unwrap());
    }

    assert_eq!(child.private(), child_prv.to_string().as_str());
    assert_eq!(child.public(), child_pub.to_string().as_str());

    assert_eq!(child_prv, parse_key(child.private()).try_into().unwrap());
    assert_eq!(child_pub, parse_key(child.public()).try_into().unwrap());

    child
}

pub fn check_vector<'a, A>(chain: &[A], hdpath: &HDPath)
where
    A: PrvPub<'a>,
    A: Copy,
{
    hdpath
        .path()
        .iter()
        .zip(&chain[1..])
        .fold(chain[0], |parent, (node, child)| {
            do_check(parent, *node, *child)
        });
}
