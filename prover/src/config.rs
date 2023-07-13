use crate::utils::read_env_var;
use once_cell::sync::Lazy;
use std::collections::HashSet;

pub static INNER_DEGREE: Lazy<u32> = Lazy::new(|| read_env_var("INNER_DEGREE", 20));
pub static LAYER1_DEGREE: Lazy<u32> = Lazy::new(|| read_env_var("LAYER1_DEGREE", 25));
pub static LAYER2_DEGREE: Lazy<u32> = Lazy::new(|| read_env_var("LAYER2_DEGREE", 25));
pub static LAYER3_DEGREE: Lazy<u32> = Lazy::new(|| read_env_var("LAYER3_DEGREE", 25));
pub static LAYER4_DEGREE: Lazy<u32> = Lazy::new(|| read_env_var("LAYER4_DEGREE", 25));

pub static ZKEVM_DEGREES: Lazy<Vec<u32>> = Lazy::new(|| {
    Vec::from_iter(HashSet::from([
        *INNER_DEGREE,
        *LAYER1_DEGREE,
        *LAYER2_DEGREE,
    ]))
});

pub static AGG_DEGREES: Lazy<Vec<u32>> = Lazy::new(|| {
    Vec::from_iter(HashSet::from([
        *LAYER2_DEGREE,
        *LAYER3_DEGREE,
        *LAYER4_DEGREE,
    ]))
});
