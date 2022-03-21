use extend_key::base58::*;
use extend_key::ecdsa_key::{PrvKeyBytes, PubKeyBytes};
use extend_key::extkey::*;

const M_PUB: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
const M_PRV: &str = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";

const M_0H_PUB: &str = "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw";
const M_0H_PRV: &str = "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7";

const M_0H_1_PUB: &str = "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ";
const M_0H_1_PRV: &str = "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs";

const M_0H_1_2H_PUB: &str = "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5";
const M_0H_1_2H_PRV: &str = "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM";

const M_0H_1_2H_2_PUB: &str = "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV";
const M_0H_1_2H_2_PRV: &str = "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334";

const M_0H_1_2H_2_1000000000_PUB: &str = "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy";
const M_0H_1_2H_2_1000000000_PRV: &str = "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76";

#[test]
fn prv_root() {
    let parsed_m_prv: DecodedExtKey = M_PRV.parse().unwrap();
    let parsed_m_pub: DecodedExtKey = M_PUB.parse().unwrap();
    let m_prv: ExtKey<PrvKeyBytes> = parsed_m_prv.try_into().unwrap();
    let m_pub_a: ExtKey<PubKeyBytes> = parsed_m_pub.try_into().unwrap();
    let m_pub = m_prv.get_public().unwrap();
    assert_eq!(m_prv.to_string(), M_PRV);
    assert_eq!(m_pub.to_string(), M_PUB);
    assert_eq!(m_pub, m_pub_a);

    let m_0h_prv = m_prv.get_child("0'".parse().unwrap()).unwrap();
    let m_0h_pub = m_0h_prv.get_public().unwrap();
    assert_eq!(m_0h_prv.to_string(), M_0H_PRV);
    assert_eq!(m_0h_pub.to_string(), M_0H_PUB);

    let m_0h_1_prv = m_0h_prv.get_child("1".parse().unwrap()).unwrap();
    let m_0h_1_pub_a = m_0h_pub
        .get_child_normal_only("1".parse().unwrap())
        .unwrap();
    let m_0h_1_pub = m_0h_1_prv.get_public().unwrap();
    assert_eq!(m_0h_1_prv.to_string(), M_0H_1_PRV);
    assert_eq!(m_0h_1_pub.to_string(), M_0H_1_PUB);
    assert_eq!(m_0h_1_pub, m_0h_1_pub_a);

    let m_0h_1_2h_prv = m_0h_1_prv.get_child("2'".parse().unwrap()).unwrap();
    let m_0h_1_2h_pub = m_0h_1_2h_prv.get_public().unwrap();
    assert_eq!(m_0h_1_2h_prv.to_string(), M_0H_1_2H_PRV);
    assert_eq!(m_0h_1_2h_pub.to_string(), M_0H_1_2H_PUB);

    let m_0h_1_2h_2_prv = m_0h_1_2h_prv.get_child("2".parse().unwrap()).unwrap();
    let m_0h_1_2h_2_pub_a = m_0h_1_2h_pub
        .get_child_normal_only("2".parse().unwrap())
        .unwrap();
    let m_0h_1_2h_2_pub = m_0h_1_2h_2_prv.get_public().unwrap();
    assert_eq!(m_0h_1_2h_2_prv.to_string(), M_0H_1_2H_2_PRV);
    assert_eq!(m_0h_1_2h_2_pub.to_string(), M_0H_1_2H_2_PUB);
    assert_eq!(m_0h_1_2h_2_pub, m_0h_1_2h_2_pub_a);

    let m_0h_1_2h_2_1g_prv = m_0h_1_2h_2_prv
        .get_child("1000000000".parse().unwrap())
        .unwrap();
    let m_0h_1_2h_2_1g_pub = m_0h_1_2h_2_1g_prv.get_public().unwrap();
    let m_0h_1_2h_2_1g_pub_a = m_0h_1_2h_2_pub
        .get_child_normal_only("1000000000".parse().unwrap())
        .unwrap();
    assert_eq!(m_0h_1_2h_2_1g_prv.to_string(), M_0H_1_2H_2_1000000000_PRV);
    assert_eq!(m_0h_1_2h_2_1g_pub.to_string(), M_0H_1_2H_2_1000000000_PUB);
    assert_eq!(m_0h_1_2h_2_1g_pub, m_0h_1_2h_2_1g_pub_a);
}
