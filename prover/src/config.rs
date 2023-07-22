use crate::utils::read_env_var;
use once_cell::sync::Lazy;
use std::collections::HashSet;

pub static INNER_DEGREE: Lazy<u32> = Lazy::new(|| read_env_var("INNER_DEGREE", 20));
pub static CHUNK_DEGREE: Lazy<u32> = Lazy::new(|| read_env_var("CHUNK_DEGREE", 24));

pub static AGG_LAYER1_DEGREE: Lazy<u32> = Lazy::new(|| read_env_var("AGG_LAYER1_DEGREE", 24));
pub static AGG_LAYER2_DEGREE: Lazy<u32> = Lazy::new(|| read_env_var("AGG_LAYER2_DEGREE", 24));
pub static AGG_LAYER3_DEGREE: Lazy<u32> = Lazy::new(|| read_env_var("AGG_LAYER3_DEGREE", 25));
pub static AGG_LAYER4_DEGREE: Lazy<u32> = Lazy::new(|| read_env_var("AGG_LAYER4_DEGREE", 25));

pub static ALL_AGG_DEGREES: Lazy<Vec<u32>> = Lazy::new(|| {
    Vec::from_iter(HashSet::from([
        *INNER_DEGREE,
        *CHUNK_DEGREE,
        *AGG_LAYER1_DEGREE,
        *AGG_LAYER2_DEGREE,
        *AGG_LAYER3_DEGREE,
        *AGG_LAYER4_DEGREE,
    ]))
});
