use eth_types::Word;
use ethers_core::types::{Address, Bytes, H256, U256, U64};
use std::{
    convert::TryFrom,
    io::{Error, ErrorKind, Read},
};
use num_bigint::BigUint;
use types::eth::{AccountProofWrapper, StorageProofWrapper, BlockResult};
use halo2_proofs::halo2curves::bn256::Fr;
use bus_mapping::state_db::StateDB;
use zkevm_circuits::evm_circuit::witness::{Block as BlockWitness, Rw, RwMap};

pub const NODE_TYPE_MIDDLE: u8 = 0;
pub const NODE_TYPE_LEAF: u8 = 1;
pub const NODE_TYPE_EMPTY: u8 = 2;

#[derive(Debug, Default, Copy, Clone)]
pub struct AccountData {
    pub nonce: u64,
    pub balance: U256,
    pub code_hash: H256,
    pub storage_root: H256,
}

impl From<&AccountProofWrapper> for AccountData {
    fn from(w: &AccountProofWrapper) -> Self {
        AccountData {
            nonce: w.nonce.unwrap(),
            balance: w.balance.unwrap(),
            code_hash: w.code_hash.unwrap(),
            storage_root: Default::default()
        }
    }
}

pub fn extend_address_to_h256(src: &Address) -> [u8; 32] {
    let mut bts: Vec<u8> = src.as_bytes().into();
    bts.resize(32, 0);
    bts.as_slice().try_into().expect("32 bytes")
}

pub trait CanRead: Sized {
    fn try_parse(rd: impl Read) -> Result<Self, Error>;
    fn parse_leaf(data: &[u8]) -> Result<Self, Error>{
        // notice the first 33 bytes has been read external
        Self::try_parse(&data[33..])
    }
}

impl CanRead for AccountData {
    fn try_parse(mut rd: impl Read) -> Result<Self, Error> {
        let mut uint_buf = [0; 4];
        rd.read_exact(&mut uint_buf)?;
        // check it is 0x04040000
        if uint_buf != [4, 4, 0, 0] {
            return Err(Error::new(ErrorKind::Other, "unexpected flags"));
        }

        let mut byte32_buf = [0; 32];
        rd.read_exact(&mut byte32_buf)?; //nonce
        let nonce = U64::from_big_endian(&byte32_buf[24..]);
        rd.read_exact(&mut byte32_buf)?; //balance
        let balance = U256::from_big_endian(&byte32_buf);
        rd.read_exact(&mut byte32_buf)?; //codehash
        let code_hash = H256::from(&byte32_buf);
        rd.read_exact(&mut byte32_buf)?; //storage root, not need yet
        let storage_root = H256::from(&byte32_buf);

        Ok(AccountData {
            nonce: nonce.as_u64(),
            balance,
            code_hash,
            storage_root,
        })
    }
}

impl Into<mpt_circuits::serde::AccountData> for AccountData {
    fn into(self) -> mpt_circuits::serde::AccountData {
        let mut balance : [u8; 32]= [0; 32];
        self.balance.to_big_endian(balance.as_mut_slice());
        let balance = BigUint::from_bytes_be(balance.as_slice());
        let code_hash = BigUint::from_bytes_be(self.code_hash.as_bytes());

        mpt_circuits::serde::AccountData {
            nonce: self.nonce,
            balance,
            code_hash
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct StorageData(Word);

impl AsRef<Word> for StorageData {
    fn as_ref(&self) -> &Word {
        &self.0
    }
}

impl CanRead for StorageData {
    fn try_parse(mut rd: impl Read) -> Result<Self, Error> {
        let mut uint_buf = [0; 4];
        rd.read_exact(&mut uint_buf)?;
        // check it is 0x01010000
        if uint_buf != [1, 1, 0, 0] {
            return Err(Error::new(ErrorKind::Other, "unexpected flags"));
        }
        let mut byte32_buf = [0; 32];
        rd.read_exact(&mut byte32_buf)?;
        Ok(StorageData(Word::from(byte32_buf)))
    }
}

#[derive(Debug, Default, Clone)]
pub struct TrieProof<T> {
    pub data: T,
    pub key: Option<H256>,
    // the path from top to bottom, in (left child, right child) form
    pub path: Vec<(U256, U256)>,
}

pub type AccountProof = TrieProof<AccountData>;
pub type StorageProof = TrieProof<StorageData>;

impl<T: CanRead + Default> TryFrom<&[Bytes]> for TrieProof<T> {
    type Error = Error;

    fn try_from(src: &[Bytes]) -> Result<Self, Self::Error> {
        let mut path : Vec<(U256, U256)> = Vec::new();
        for data in src {
            let mut rd = data.as_ref();
            let mut prefix = [0; 1];
            rd.read_exact(&mut prefix)?;
            match prefix[0] {
                NODE_TYPE_LEAF => {
                    let mut byte32_buf = [0; 32];
                    rd.read_exact(&mut byte32_buf)?;
                    let key = H256::from(byte32_buf);
                    let data = T::parse_leaf(data.as_ref())?;
                    return Ok(Self {
                        key: Some(key),
                        data,
                        path,
                    });
                }
                NODE_TYPE_EMPTY => {
                    return Ok(Self{
                        path,
                        ..Default::default()
                    });
                }
                NODE_TYPE_MIDDLE => {
                    let mut buf : [u8; 32] = [0; 32];
                    rd.read_exact(&mut buf)?;
                    let left = U256::from_big_endian(&buf);
                    rd.read_exact(&mut buf)?;
                    let right = U256::from_big_endian(&buf);
                    path.push((left, right));
                }
                _ => (),
            }
        }

        Err(Error::new(ErrorKind::UnexpectedEof, "no leaf key found"))
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct RwAccountId (u64, Address, Word);

impl From<&Rw> for RwAccountId {
    fn from(rw: &Rw) -> Self {
        Self(
            rw.field_tag().unwrap_or_default(), 
            rw.address().expect("should be account rw"), 
            rw.storage_key().unwrap_or_else(Word::zero),
        )
    }
}

pub fn mpt_entries_from_witness_block(mut sdb: StateDB, block_wit: &BlockWitness<Fr>) -> Vec<AccountProofWrapper>{

    use std::collections::HashMap;
    use zkevm_circuits::table::{AccountFieldTag, RwTableTag};

    let mut out_entries = Vec::new();

    let (rw_acc, rw_storage) = (
        block_wit.rws.0.get(&RwTableTag::Account),
        block_wit.rws.0.get(&RwTableTag::AccountStorage),
    );

    if let Some(rws) = rw_acc {

        let mut sorter = RwMap(HashMap::new());
        sorter.0.insert(RwTableTag::Account, rws.clone());
        let rws = sorter.table_assignments();

        let mut last_addr : Option<RwAccountId> = None;
        let mut write_entry = |last_addr: &RwAccountId, sdb: &StateDB|{
            let addr = last_addr.1;
            let (existed, acc_data) = sdb.get_account(&addr);
            assert!(existed, "account must be set in sdb");

            out_entries.push(AccountProofWrapper{
                address: Some(addr),
                nonce: Some(acc_data.nonce.as_u64()),
                balance: Some(acc_data.balance),
                code_hash: Some(acc_data.code_hash),
                ..Default::default()
            });            
        };

        for rw in rws {
            let rw_id : RwAccountId = From::from(&rw);
            if Some(rw_id) != last_addr {

                if let Some(last_addr) = last_addr.as_ref() {
                    write_entry(last_addr, &sdb);
                }

                last_addr = Some(rw_id);
            }

            let addr = rw_id.1;
            let (existed, acc_data) = sdb.get_account_mut(&addr);
            assert!(existed, "account must be inited in sdb");
            let (val, _) = rw.account_value_pair();
            match rw_id.0 {
                tag if tag == AccountFieldTag::Nonce as u64 => 
                    {acc_data.nonce = val;},
                tag if tag == AccountFieldTag::Balance as u64 =>
                    {acc_data.balance = val;},
                tag if tag == AccountFieldTag::CodeHash as u64 => {
                    let mut out_bytes : [u8; 32] = [0; 32];
                    val.to_big_endian(&mut out_bytes);
                    acc_data.code_hash = H256::from_slice(&out_bytes);
                },
                _ => unreachable!(),
            };            
        }

        if let Some(last_addr) = last_addr.as_ref() {
            write_entry(last_addr, &sdb);
        }        
    }

    if let Some(rws) = rw_storage {
        let mut sorter = RwMap(HashMap::new());
        sorter.0.insert(RwTableTag::AccountStorage, rws.clone());
        let rws = sorter.table_assignments();

        let mut last_addr : Option<RwAccountId> = None;
        let mut last_rw : Option<Rw> = None;

        let mut write_entry = |last_addr: &RwAccountId, rw: &Rw|{
            let addr = last_addr.1;
            let (existed, acc_data) = sdb.get_account(&addr);
            assert!(existed, "account must be set in sdb");

            let key = rw.storage_key().expect("should be storage rw");
            let (val, _, _, _) = rw.storage_value_aux();
            out_entries.push(AccountProofWrapper{
                address: Some(addr),
                nonce: Some(acc_data.nonce.as_u64()),
                balance: Some(acc_data.balance),
                code_hash: Some(acc_data.code_hash),
                storage: Some(StorageProofWrapper {
                    key: Some(key),
                    value: Some(val),
                    ..Default::default()
                }),
                ..Default::default()
            });           
        };

        for rw in rws {
            let rw_id : RwAccountId = From::from(&rw);
            if Some(rw_id) != last_addr {

                if let Some(last_addr) = last_addr.as_ref() {
                    write_entry(last_addr, &last_rw.take().expect("should have cached rw"));
                }
                last_addr = Some(rw_id);
            }

            last_rw = Some(rw);
        }
        if let Some(last_addr) = last_addr.as_ref() {
            write_entry(last_addr, &last_rw.take().expect("should have cached rw"));
        }        
    }

    
    out_entries
}

pub(crate) mod witness;
#[cfg(test)]
mod tests;
