/*!
Types shared between `hypercore` and `hypercore-protocol`
*/
#![warn(
    unreachable_pub,
    missing_debug_implementations,
    missing_docs,
    redundant_lifetimes,
    unsafe_code,
    non_local_definitions,
    clippy::needless_pass_by_value,
    clippy::needless_pass_by_ref_mut,
    clippy::enum_glob_use
)]

use blake2::{
    Blake2b, Blake2bMac, Digest,
    digest::{FixedOutput, generic_array::GenericArray, typenum::U32},
};
use byteorder::{BigEndian, WriteBytesExt};
use compact_encoding::{
    CompactEncoding, EncodingError, FixedWidthEncoding, VecEncodable, as_array, encoded_size_usize,
    map_decode, map_encode, sum_encoded_size, to_encoded_bytes,
};
use ed25519_dalek::VerifyingKey;
use merkle_tree_stream::{Node as NodeTrait, NodeKind, NodeParts};
use pretty_hash::fmt as pretty_fmt;

use std::{
    cmp::Ordering,
    convert::AsRef,
    fmt::{self, Display},
    mem,
};
// https://en.wikipedia.org/wiki/Merkle_tree#Second_preimage_attack
const LEAF_TYPE: [u8; 1] = [0x00];
const PARENT_TYPE: [u8; 1] = [0x01];
const ROOT_TYPE: [u8; 1] = [0x02];
const HYPERCORE: [u8; 9] = *b"hypercore";

/// These the output of, see `hash_namespace` test below for how they are produced
/// https://github.com/holepunchto/hypercore/blob/cf08b72f14ed7d9ef6d497ebb3071ee0ae20967e/lib/caps.js#L16
pub const TREE: [u8; 32] = [
    0x9F, 0xAC, 0x70, 0xB5, 0xC, 0xA1, 0x4E, 0xFC, 0x4E, 0x91, 0xC8, 0x33, 0xB2, 0x4, 0xE7, 0x5B,
    0x8B, 0x5A, 0xAD, 0x8B, 0x58, 0x81, 0xBF, 0xC0, 0xAD, 0xB5, 0xEF, 0x38, 0xA3, 0x27, 0x5B, 0x9C,
];

pub(crate) type Blake2bResult = GenericArray<u8, U32>;
type Blake2b256 = Blake2b<U32>;

/// `BLAKE2b` hash.
#[derive(Debug, Clone, PartialEq)]
pub struct Hash {
    hash: Blake2bResult,
}

impl Hash {
    /// Hash a `Leaf` node.
    #[expect(dead_code)]
    pub(crate) fn from_leaf(data: &[u8]) -> Self {
        let size = u64_as_be(data.len() as u64);

        let mut hasher = Blake2b256::new();
        hasher.update(LEAF_TYPE);
        hasher.update(size);
        hasher.update(data);

        Self {
            hash: hasher.finalize(),
        }
    }

    /// Hash two `Leaf` nodes hashes together to form a `Parent` hash.
    #[expect(dead_code)]
    pub(crate) fn from_hashes(left: &Node, right: &Node) -> Self {
        let (node1, node2) = if left.index <= right.index {
            (left, right)
        } else {
            (right, left)
        };

        let size = u64_as_be(node1.length + node2.length);

        let mut hasher = Blake2b256::new();
        hasher.update(PARENT_TYPE);
        hasher.update(size);
        hasher.update(node1.hash());
        hasher.update(node2.hash());

        Self {
            hash: hasher.finalize(),
        }
    }

    /// Hash a public key. Useful to find the key you're looking for on a public
    /// network without leaking the key itself.
    #[expect(dead_code)]
    pub(crate) fn for_discovery_key(public_key: VerifyingKey) -> Self {
        let mut hasher =
            Blake2bMac::<U32>::new_with_salt_and_personal(public_key.as_bytes(), &[], &[]).unwrap();
        blake2::digest::Update::update(&mut hasher, &HYPERCORE);
        Self {
            hash: hasher.finalize_fixed(),
        }
    }

    /// Hash a vector of `Root` nodes.
    // Called `crypto.tree()` in the JS implementation.
    #[expect(dead_code)]
    pub(crate) fn from_roots(roots: &[impl AsRef<Node>]) -> Self {
        let mut hasher = Blake2b256::new();
        hasher.update(ROOT_TYPE);

        for node in roots {
            let node = node.as_ref();
            hasher.update(node.hash());
            hasher.update(u64_as_be(node.index()));
            hasher.update(u64_as_be(node.len()));
        }

        Self {
            hash: hasher.finalize(),
        }
    }

    /// Returns a byte slice of this `Hash`'s contents.
    pub fn as_bytes(&self) -> &[u8] {
        self.hash.as_slice()
    }

    // NB: The following methods mirror Javascript naming in
    // https://github.com/mafintosh/hypercore-crypto/blob/master/index.js
    // for v10 that use LE bytes.

    /// Hash data
    pub fn data(data: &[u8]) -> Self {
        let size =
            (|| Ok::<_, EncodingError>(to_encoded_bytes!((data.len() as u64).as_fixed_width())))()
                .expect("Encoding u64 should not fail");

        let mut hasher = Blake2b256::new();
        hasher.update(LEAF_TYPE);
        hasher.update(&size);
        hasher.update(data);

        Self {
            hash: hasher.finalize(),
        }
    }

    /// Hash a parent
    pub fn parent(left: &Node, right: &Node) -> Self {
        let (node1, node2) = if left.index <= right.index {
            (left, right)
        } else {
            (right, left)
        };

        let len = node1.length + node2.length;
        let size: Box<[u8]> =
            (|| Ok::<_, EncodingError>(to_encoded_bytes!(len.as_fixed_width())))()
                .expect("Encoding u64 should not fail");

        let mut hasher = Blake2b256::new();
        hasher.update(PARENT_TYPE);
        hasher.update(&size);
        hasher.update(node1.hash());
        hasher.update(node2.hash());

        Self {
            hash: hasher.finalize(),
        }
    }

    /// Hash a tree
    pub fn tree(roots: &[impl AsRef<Node>]) -> Self {
        let mut hasher = Blake2b256::new();
        hasher.update(ROOT_TYPE);

        for node in roots {
            let node = node.as_ref();
            let buffer = (|| {
                Ok::<_, EncodingError>(to_encoded_bytes!(
                    node.index().as_fixed_width(),
                    node.len().as_fixed_width()
                ))
            })()
            .expect("Encoding u64 should not fail");

            hasher.update(node.hash());
            hasher.update(&buffer[..8]);
            hasher.update(&buffer[8..]);
        }

        Self {
            hash: hasher.finalize(),
        }
    }
}

fn u64_as_be(n: u64) -> [u8; 8] {
    let mut size = [0u8; mem::size_of::<u64>()];
    size.as_mut().write_u64::<BigEndian>(n).unwrap();
    size
}

impl std::ops::Deref for Hash {
    type Target = Blake2bResult;

    fn deref(&self) -> &Self::Target {
        &self.hash
    }
}

impl std::ops::DerefMut for Hash {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.hash
    }
}

/// Nodes of the Merkle Tree that are persisted to disk.
// TODO: replace `hash: Vec<u8>` with `hash: Hash`. This requires patching /
// rewriting the Blake2b crate to support `.from_bytes()` to serialize from
// disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    /// This node's index in the Merkle tree
    pub index: u64,
    /// Hash of the data in this node
    // TODO make this [u8; 32] like:
    // https://github.com/holepunchto/hypercore/blob/d21ebdeca1b27eb4c2232f8af17d5ae939ee97f2/lib/messages.js#L246
    pub hash: Vec<u8>,
    /// Number of bytes in this [`Node::data`]
    pub length: u64,
    /// Index of this nodes parent
    pub(crate) parent: u64,
    /// Hypercore's data. Can be receieved after the rest of the node, so it's optional.
    pub(crate) data: Option<Vec<u8>>,
    /// If blank
    pub blank: bool,
}

impl Node {
    /// Create a new instance.
    // TODO: ensure sizes are correct.
    pub fn new(index: u64, hash: Vec<u8>, length: u64) -> Self {
        let mut blank = true;
        for byte in &hash {
            if *byte != 0 {
                blank = false;
                break;
            }
        }
        Self {
            index,
            hash,
            length,
            parent: flat_tree::parent(index),
            data: Some(Vec::with_capacity(0)),
            blank,
        }
    }

    /// Creates a new blank node
    pub fn new_blank(index: u64) -> Self {
        Self {
            index,
            hash: vec![0, 32],
            length: 0,
            parent: 0,
            data: None,
            blank: true,
        }
    }
}

impl NodeTrait for Node {
    #[inline]
    fn index(&self) -> u64 {
        self.index
    }

    #[inline]
    fn hash(&self) -> &[u8] {
        &self.hash
    }

    #[inline]
    fn len(&self) -> u64 {
        self.length
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.length == 0
    }

    #[inline]
    fn parent(&self) -> u64 {
        self.parent
    }
}

impl AsRef<Node> for Node {
    #[inline]
    fn as_ref(&self) -> &Self {
        self
    }
}

impl Display for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Node {{ index: {}, hash: {}, length: {} }}",
            self.index,
            pretty_fmt(&self.hash).unwrap(),
            self.length
        )
    }
}

impl PartialOrd for Node {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Node {
    fn cmp(&self, other: &Self) -> Ordering {
        self.index.cmp(&other.index)
    }
}

impl From<NodeParts<Hash>> for Node {
    fn from(parts: NodeParts<Hash>) -> Self {
        let partial = parts.node();
        let data = match partial.data() {
            NodeKind::Leaf(data) => Some(data.clone()),
            NodeKind::Parent => None,
        };
        let hash: Vec<u8> = parts.hash().as_bytes().into();
        let mut blank = true;
        for byte in &hash {
            if *byte != 0 {
                blank = false;
                break;
            }
        }

        Node {
            index: partial.index(),
            parent: partial.parent,
            length: partial.len(),
            hash,
            data,
            blank,
        }
    }
}

// ----------------------------------------------------------------------------------
//  The types from hypercore
// ----------------------------------------------------------------------------------
#[derive(Debug, Clone, PartialEq)]
/// Request of a DataBlock or DataHash from peer
pub struct RequestBlock {
    /// Hypercore index
    pub index: u64,
    /// TODO: document
    pub nodes: u64,
}

#[derive(Debug, Clone, PartialEq)]
/// Request for a DataUpgrade from peer
pub struct RequestUpgrade {
    /// Hypercore start index
    pub start: u64,
    /// Length of elements
    pub length: u64,
}

#[derive(Debug, Clone, PartialEq)]
/// Proof generated from corresponding requests
pub struct Proof {
    /// Fork
    pub fork: u64,
    /// Data block.
    pub block: Option<DataBlock>,
    /// Data hash
    pub hash: Option<DataHash>,
    /// Data seek
    pub seek: Option<DataSeek>,
    /// Data updrade
    pub upgrade: Option<DataUpgrade>,
}

#[derive(Debug, Clone, PartialEq)]
/// Request of a DataSeek from peer
pub struct RequestSeek {
    /// TODO: document
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq)]
/// TODO: Document
pub struct DataUpgrade {
    /// Starting block of this upgrade response
    pub start: u64,
    /// Number of blocks in this upgrade response
    pub length: u64,
    /// The nodes of the merkle tree
    pub nodes: Vec<Node>,
    /// TODO: Document
    pub additional_nodes: Vec<Node>,
    /// TODO: Document
    pub signature: Vec<u8>,
}
#[derive(Debug, Clone, PartialEq)]
/// Block of data to peer
pub struct DataBlock {
    /// Hypercore index
    pub index: u64,
    /// Data block value in bytes
    pub value: Vec<u8>,
    /// Nodes of the merkle tree
    pub nodes: Vec<Node>,
}

#[derive(Debug, Clone, PartialEq)]
/// Data hash to peer
pub struct DataHash {
    /// Hypercore index
    pub index: u64,
    /// TODO: document
    pub nodes: Vec<Node>,
}

#[derive(Debug, Clone, PartialEq)]
/// TODO: Document
pub struct DataSeek {
    /// TODO: Document
    pub bytes: u64,
    /// TODO: Document
    pub nodes: Vec<Node>,
}

impl CompactEncoding for Node {
    fn encoded_size(&self) -> Result<usize, EncodingError> {
        Ok(sum_encoded_size!(self.index, self.length) + 32)
    }

    fn encode<'a>(&self, buffer: &'a mut [u8]) -> Result<&'a mut [u8], EncodingError> {
        let hash = as_array::<32>(&self.hash)?;
        Ok(map_encode!(buffer, self.index, self.length, hash))
    }

    fn decode(buffer: &[u8]) -> Result<(Self, &[u8]), EncodingError>
    where
        Self: Sized,
    {
        let ((index, length, hash), rest) = map_decode!(buffer, [u64, u64, [u8; 32]]);
        Ok((Node::new(index, hash.to_vec(), length), rest))
    }
}

impl VecEncodable for Node {
    fn vec_encoded_size(vec: &[Self]) -> Result<usize, EncodingError>
    where
        Self: Sized,
    {
        let mut out = encoded_size_usize(vec.len());
        for x in vec {
            out += x.encoded_size()?;
        }
        Ok(out)
    }
}

impl CompactEncoding for RequestBlock {
    fn encoded_size(&self) -> Result<usize, EncodingError> {
        Ok(sum_encoded_size!(self.index, self.nodes))
    }

    fn encode<'a>(&self, buffer: &'a mut [u8]) -> Result<&'a mut [u8], EncodingError> {
        Ok(map_encode!(buffer, self.index, self.nodes))
    }

    fn decode(buffer: &[u8]) -> Result<(Self, &[u8]), EncodingError>
    where
        Self: Sized,
    {
        let ((index, nodes), rest) = map_decode!(buffer, [u64, u64]);
        Ok((RequestBlock { index, nodes }, rest))
    }
}

impl CompactEncoding for RequestSeek {
    fn encoded_size(&self) -> Result<usize, EncodingError> {
        self.bytes.encoded_size()
    }

    fn encode<'a>(&self, buffer: &'a mut [u8]) -> Result<&'a mut [u8], EncodingError> {
        self.bytes.encode(buffer)
    }

    fn decode(buffer: &[u8]) -> Result<(Self, &[u8]), EncodingError>
    where
        Self: Sized,
    {
        let (bytes, rest) = u64::decode(buffer)?;
        Ok((RequestSeek { bytes }, rest))
    }
}

impl CompactEncoding for RequestUpgrade {
    fn encoded_size(&self) -> Result<usize, EncodingError> {
        Ok(sum_encoded_size!(self.start, self.length))
    }

    fn encode<'a>(&self, buffer: &'a mut [u8]) -> Result<&'a mut [u8], EncodingError> {
        Ok(map_encode!(buffer, self.start, self.length))
    }

    fn decode(buffer: &[u8]) -> Result<(Self, &[u8]), EncodingError>
    where
        Self: Sized,
    {
        let ((start, length), rest) = map_decode!(buffer, [u64, u64]);
        Ok((RequestUpgrade { start, length }, rest))
    }
}

impl CompactEncoding for DataBlock {
    fn encoded_size(&self) -> Result<usize, EncodingError> {
        Ok(sum_encoded_size!(self.index, self.value, self.nodes))
    }

    fn encode<'a>(&self, buffer: &'a mut [u8]) -> Result<&'a mut [u8], EncodingError> {
        Ok(map_encode!(buffer, self.index, self.value, self.nodes))
    }

    fn decode(buffer: &[u8]) -> Result<(Self, &[u8]), EncodingError>
    where
        Self: Sized,
    {
        let ((index, value, nodes), rest) = map_decode!(buffer, [u64, Vec<u8>, Vec<Node>]);
        Ok((
            DataBlock {
                index,
                value,
                nodes,
            },
            rest,
        ))
    }
}

impl CompactEncoding for DataHash {
    fn encoded_size(&self) -> Result<usize, EncodingError> {
        Ok(sum_encoded_size!(self.index, self.nodes))
    }

    fn encode<'a>(&self, buffer: &'a mut [u8]) -> Result<&'a mut [u8], EncodingError> {
        Ok(map_encode!(buffer, self.index, self.nodes))
    }

    fn decode(buffer: &[u8]) -> Result<(Self, &[u8]), EncodingError>
    where
        Self: Sized,
    {
        let ((index, nodes), rest) = map_decode!(buffer, [u64, Vec<Node>]);
        Ok((DataHash { index, nodes }, rest))
    }
}

impl CompactEncoding for DataSeek {
    fn encoded_size(&self) -> Result<usize, EncodingError> {
        Ok(sum_encoded_size!(self.bytes, self.nodes))
    }

    fn encode<'a>(&self, buffer: &'a mut [u8]) -> Result<&'a mut [u8], EncodingError> {
        Ok(map_encode!(buffer, self.bytes, self.nodes))
    }

    fn decode(buffer: &[u8]) -> Result<(Self, &[u8]), EncodingError>
    where
        Self: Sized,
    {
        let ((bytes, nodes), rest) = map_decode!(buffer, [u64, Vec<Node>]);
        Ok((DataSeek { bytes, nodes }, rest))
    }
}

// from:
// https://github.com/holepunchto/hypercore/blob/d21ebdeca1b27eb4c2232f8af17d5ae939ee97f2/lib/messages.js#L394
impl CompactEncoding for DataUpgrade {
    fn encoded_size(&self) -> Result<usize, EncodingError> {
        Ok(sum_encoded_size!(
            self.start,
            self.length,
            self.nodes,
            self.additional_nodes,
            self.signature
        ))
    }

    fn encode<'a>(&self, buffer: &'a mut [u8]) -> Result<&'a mut [u8], EncodingError> {
        Ok(map_encode!(
            buffer,
            self.start,
            self.length,
            self.nodes,
            self.additional_nodes,
            self.signature
        ))
    }

    fn decode(buffer: &[u8]) -> Result<(Self, &[u8]), EncodingError>
    where
        Self: Sized,
    {
        let ((start, length, nodes, additional_nodes, signature), rest) =
            map_decode!(buffer, [u64, u64, Vec<Node>, Vec<Node>, Vec<u8>]);
        Ok((
            DataUpgrade {
                start,
                length,
                nodes,
                additional_nodes,
                signature,
            },
            rest,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use self::data_encoding::HEXLOWER;
    use data_encoding;

    fn hash_with_extra_byte(data: &[u8], byte: u8) -> Box<[u8]> {
        let mut hasher = Blake2b256::new();
        hasher.update(data);
        hasher.update([byte]);
        let hash = hasher.finalize();
        hash.as_slice().into()
    }

    fn hex_bytes(hex: &str) -> Vec<u8> {
        HEXLOWER.decode(hex.as_bytes()).unwrap()
    }

    fn check_hash(hash: Hash, hex: &str) {
        assert_eq!(hash.as_bytes(), &hex_bytes(hex)[..]);
    }

    #[test]
    fn leaf_hash() {
        check_hash(
            Hash::from_leaf(&[]),
            "5187b7a8021bf4f2c004ea3a54cfece1754f11c7624d2363c7f4cf4fddd1441e",
        );
        check_hash(
            Hash::from_leaf(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]),
            "e1001bb0bb9322b6b202b2f737dc12181b11727168d33ca48ffe361c66cd1abe",
        );
    }

    #[test]
    fn parent_hash() {
        let d1: &[u8] = &[0, 1, 2, 3, 4];
        let d2: &[u8] = &[42, 43, 44, 45, 46, 47, 48];
        let node1 = Node::new(0, Hash::from_leaf(d1).as_bytes().to_vec(), d1.len() as u64);
        let node2 = Node::new(1, Hash::from_leaf(d2).as_bytes().to_vec(), d2.len() as u64);
        check_hash(
            Hash::from_hashes(&node1, &node2),
            "6fac58578fa385f25a54c0637adaca71fdfddcea885d561f33d80c4487149a14",
        );
        check_hash(
            Hash::from_hashes(&node2, &node1),
            "6fac58578fa385f25a54c0637adaca71fdfddcea885d561f33d80c4487149a14",
        );
    }

    #[test]
    fn root_hash() {
        let d1: &[u8] = &[0, 1, 2, 3, 4];
        let d2: &[u8] = &[42, 43, 44, 45, 46, 47, 48];
        let node1 = Node::new(0, Hash::from_leaf(d1).as_bytes().to_vec(), d1.len() as u64);
        let node2 = Node::new(1, Hash::from_leaf(d2).as_bytes().to_vec(), d2.len() as u64);
        check_hash(
            Hash::from_roots(&[&node1, &node2]),
            "2d117e0bb15c6e5236b6ce764649baed1c41890da901a015341503146cc20bcd",
        );
        check_hash(
            Hash::from_roots(&[&node2, &node1]),
            "9826c8c2d28fc309cce73a4b6208e83e5e4b0433d2369bfbf8858272153849f1",
        );
    }

    #[test]
    fn discovery_key_hashing() -> Result<(), ed25519_dalek::SignatureError> {
        let public_key = VerifyingKey::from_bytes(&[
            119, 143, 141, 149, 81, 117, 201, 46, 76, 237, 94, 79, 85, 99, 246, 155, 254, 192, 200,
            108, 198, 246, 112, 53, 44, 69, 121, 67, 102, 111, 230, 57,
        ])?;

        let expected = &[
            37, 167, 138, 168, 22, 21, 132, 126, 186, 0, 153, 93, 242, 157, 212, 29, 126, 227, 15,
            59, 1, 248, 146, 32, 159, 121, 183, 90, 87, 217, 137, 225,
        ];

        assert_eq!(Hash::for_discovery_key(public_key).as_bytes(), expected);

        Ok(())
    }

    // The following uses test data from
    // https://github.com/mafintosh/hypercore-crypto/blob/master/test.js

    #[test]
    fn hash_leaf() {
        let data = b"hello world";
        check_hash(
            Hash::data(data),
            "9f1b578fd57a4df015493d2886aec9600eef913c3bb009768c7f0fb875996308",
        );
    }

    #[test]
    fn hash_parent() {
        let data = b"hello world";
        let len = data.len() as u64;
        let node1 = Node::new(0, Hash::data(data).as_bytes().to_vec(), len);
        let node2 = Node::new(1, Hash::data(data).as_bytes().to_vec(), len);
        check_hash(
            Hash::parent(&node1, &node2),
            "3ad0c9b58b771d1b7707e1430f37c23a23dd46e0c7c3ab9c16f79d25f7c36804",
        );
    }

    #[test]
    fn hash_tree() {
        let hash: [u8; 32] = [0; 32];
        let node1 = Node::new(3, hash.to_vec(), 11);
        let node2 = Node::new(9, hash.to_vec(), 2);
        check_hash(
            Hash::tree(&[&node1, &node2]),
            "0e576a56b478cddb6ffebab8c494532b6de009466b2e9f7af9143fc54b9eaa36",
        );
    }

    // This is the rust version from
    // https://github.com/hypercore-protocol/hypercore/blob/70b271643c4e4b1e5ecae5bb579966dfe6361ff3/lib/caps.js
    // and validates that our arrays match
    #[test]
    fn hash_namespace() {
        let mut hasher = Blake2b256::new();
        hasher.update(HYPERCORE);
        let hash = hasher.finalize();
        let ns = hash.as_slice();
        let tree: Box<[u8]> = { hash_with_extra_byte(ns, 0) };
        assert_eq!(tree, TREE.into());
    }
}
