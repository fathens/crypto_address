use std::str::FromStr;

use crate::node::Node;

const PATH_SEPARATOR: char = '/';

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HDPathError {
    reason: String,
}

impl std::fmt::Display for HDPathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.reason.fmt(f)
    }
}

impl From<<Node as FromStr>::Err> for HDPathError {
    fn from(src: <Node as FromStr>::Err) -> Self {
        Self {
            reason: src.to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HDPath(Vec<Node>);

impl HDPath {
    #[inline]
    pub fn path(&self) -> &[Node] {
        &self.0
    }
}

impl TryFrom<Vec<Node>> for HDPath {
    type Error = HDPathError;

    fn try_from(ps: Vec<Node>) -> Result<Self, Self::Error> {
        if ps.is_empty() {
            return Err(HDPathError {
                reason: "empty path".to_owned(),
            });
        }
        if contains_root(&ps[1..]) {
            return Err(HDPathError {
                reason: "invalid position of root path".to_owned(),
            });
        }
        if starts_root(&ps) {
            return Ok(HDPath(ps));
        }
        Err(HDPathError {
            reason: "invalid path".to_owned(),
        })
    }
}

impl FromStr for HDPath {
    type Err = HDPathError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.starts_with(PATH_SEPARATOR) || s.ends_with(PATH_SEPARATOR) {
            return Err(HDPathError {
                reason: "invalid path".to_owned(),
            });
        }
        let ps = split(s)?;
        ps.try_into()
    }
}

fn split(s: &str) -> Result<Vec<Node>, <Node as FromStr>::Err> {
    s.split(PATH_SEPARATOR)
        .into_iter()
        .map(Node::from_str)
        .collect()
}

fn starts_root(ps: &[Node]) -> bool {
    match ps.get(0) {
        Some(&Node::Root) => true,
        _ => false,
    }
}

fn contains_root(ps: &[Node]) -> bool {
    ps.contains(&Node::Root)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn from_vec() {
        let ps1 = vec![
            Node::Root,
            Node::from(1),
            Node::from(2),
            Node::from(3),
            Node::from(4),
        ];
        assert_eq!(HDPath(ps1.clone()), ps1.try_into().unwrap());

        let ps2 = vec![
            Node::Root,
            Node::from(1).to_hardened(),
            Node::from(2).to_hardened(),
            Node::from(3),
        ];
        assert_eq!(HDPath(ps2.clone()), ps2.try_into().unwrap());

        assert_eq!(
            None as Option<HDPath>,
            vec![
                Node::from(1),
                Node::from(2),
                Node::from(3),
                Node::from(4),
                Node::from(5)
            ]
            .try_into()
            .ok()
        );

        assert_eq!(
            None as Option<HDPath>,
            vec![
                Node::from(1),
                Node::Root,
                Node::from(2),
                Node::from(3),
                Node::from(4),
            ]
            .try_into()
            .ok()
        );

        assert_eq!(
            None as Option<HDPath>,
            vec![
                Node::Root,
                Node::from(1),
                Node::Root,
                Node::from(2),
                Node::from(3),
            ]
            .try_into()
            .ok()
        );
    }

    #[test]
    fn parse_str() {
        let ps1 = vec![
            Node::Root,
            Node::from(1),
            Node::from(2),
            Node::from(3),
            Node::from(4),
        ];
        assert_eq!(HDPath(ps1), "m/1/2/3/4".parse().unwrap());

        let ps2 = vec![
            Node::Root,
            Node::from(1).to_hardened(),
            Node::from(2).to_hardened(),
            Node::from(3),
        ];
        assert_eq!(HDPath(ps2), "m/1'/2'/3".parse().unwrap());

        assert_eq!(None as Option<HDPath>, "/m/1/2/3".parse().ok());
        assert_eq!(None as Option<HDPath>, "m/1/2/3/".parse().ok());
        assert_eq!(None as Option<HDPath>, "1/m/2/3".parse().ok());
        assert_eq!(None as Option<HDPath>, "m//1/2/3".parse().ok());
    }
}
