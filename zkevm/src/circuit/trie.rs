use ethers_core::types::H256;

pub const NODE_TYPE_MIDDLE: u8 = 0;
pub const NODE_TYPE_LEAF: u8 = 1;
pub const NODE_TYPE_EMPTY: u8 = 2;

#[derive(Debug)]
pub enum TrieNode {
    Middle(TrieMiddleNode),
    Leaf(TrieLeafNode),
    Empty,
}

#[derive(Debug)]
pub struct TrieMiddleNode {
    pub child_r: H256,
    pub child_l: H256,
}

#[derive(Debug)]
pub struct TrieLeafNode {
    pub node_key: H256,
    pub compressed_flags: u32,
    pub value_preimage: Vec<[u8; 32]>,
    pub key_preimage: Option<[u8; 32]>,
}

#[derive(Debug)]
pub enum TrieNodeError {
    NodeBytesBadSize,
    InvalidNodeFound,
}

impl TryFrom<&[u8]> for TrieNode {
    type Error = TrieNodeError;

    // translated from go-ethereum NewNodeFromBytes
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        use TrieNodeError::*;

        if value.len() < 1 {
            return Err(NodeBytesBadSize);
        }
        let buf = &value[1..];
        match value[0] {
            NODE_TYPE_MIDDLE => {
                if buf.len() != 32 * 2 {
                    return Err(NodeBytesBadSize);
                }
                let child_l = H256::from(&buf[..32].try_into().unwrap());
                let child_r = H256::from(&buf[32..].try_into().unwrap());
                Ok(TrieNode::Middle(TrieMiddleNode { child_l, child_r }))
            }
            NODE_TYPE_LEAF => {
                if buf.len() < 32 + 4 {
                    return Err(NodeBytesBadSize);
                }
                let node_key = H256::from(&buf[..32].try_into().unwrap());
                let mark = u32::from_le_bytes((&buf[32..36]).try_into().unwrap());
                let preimage_len = (mark & 255) as usize;
                let compressed_flags = mark >> 8;
                let mut value_preimage = vec![[0u8; 32]; preimage_len];
                let cur_pos = 36;
                for (i, preimage) in value_preimage.iter_mut().enumerate() {
                    preimage.copy_from_slice(&buf[i * 32 + cur_pos..(i + 1) * 32 + cur_pos]);
                }
                let cur_pos = 36 + preimage_len * 32;
                let preimage_size = buf[cur_pos] as usize;
                let cur_pos = cur_pos + 1;
                let key_preimage: Option<[u8; 32]> = if preimage_size != 0 {
                    Some((&buf[cur_pos..cur_pos + preimage_size]).try_into().unwrap())
                } else {
                    None
                };
                Ok(TrieNode::Leaf(TrieLeafNode {
                    node_key,
                    compressed_flags,
                    value_preimage,
                    key_preimage,
                }))
            }
            NODE_TYPE_EMPTY => Ok(TrieNode::Empty),
            _ => Err(InvalidNodeFound),
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_middle_node() {
        const MIDDLE: &str = "00b50fa7ebcfbf879d2c87c30fa8da23205fec4876c05200c0211e27a330e9ca16444758a273fc0cfb23366a7a377630f0427fe495c9f78efbed9dc47a1e3f9e0e";
        let proof = hex::decode(MIDDLE).unwrap();

        let node: TrieNode = proof.as_slice().try_into().unwrap();
        println!("{:?}", node);
    }

    #[test]
    fn test_leaf_node() {
        const LEAF: &str = "013c6eff766107f2db0c4bf0ead086d4befa5d8675dcf54c50073efc389830fb060404000000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000cc0a77f6e063b4b62eb7d9ed6f427cf687d8d0071d751850cfe5d136bc60d3ab12b6a6aca3814be9efdc6b17540f6e7bb06457e9102149aba975e2210fd3617a00";
        let proof = hex::decode(LEAF).unwrap();
        let node: TrieNode = proof.as_slice().try_into().unwrap();
        println!("{:?}", node);
    }
}
