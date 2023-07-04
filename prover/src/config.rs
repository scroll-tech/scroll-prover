use crate::utils::read_env_var;
use once_cell::sync::Lazy;
use std::collections::HashSet;

pub static INNER_DEGREE: Lazy<u32> = Lazy::new(|| read_env_var("INNER_DEGREE", 20));
pub static CHUNK_DEGREE: Lazy<u32> = Lazy::new(|| read_env_var("CHUNK_DEGREE", 25));
pub static AGG_DEGREE: Lazy<u32> = Lazy::new(|| read_env_var("AGG_DEGREE", 25));

pub static ALL_DEGREES: Lazy<Vec<u32>> =
    Lazy::new(|| Vec::from_iter(HashSet::from([*INNER_DEGREE, *CHUNK_DEGREE, *AGG_DEGREE])));
