use crate::utils::read_env_var;
use once_cell::sync::Lazy;
use std::collections::HashSet;

pub static INNER_DEGREE: Lazy<u32> = Lazy::new(|| read_env_var("INNER_DEGREE", 20));
pub static LAYER1_DEGREE: Lazy<u32> = Lazy::new(|| read_env_var("LAYER1_DEGREE", 25));
pub static LAYER2_DEGREE: Lazy<u32> = Lazy::new(|| read_env_var("LAYER2_DEGREE", 25));
pub static LAYER3_DEGREE: Lazy<u32> = Lazy::new(|| read_env_var("LAYER3_DEGREE", 25));
pub static LAYER4_DEGREE: Lazy<u32> = Lazy::new(|| read_env_var("LAYER4_DEGREE", 25));

<<<<<<< HEAD
pub static AGG_LAYER1_DEGREE: Lazy<u32> = Lazy::new(|| read_env_var("AGG_LAYER1_DEGREE", 24));
pub static AGG_LAYER2_DEGREE: Lazy<u32> = Lazy::new(|| read_env_var("AGG_LAYER2_DEGREE", 24));
pub static AGG_LAYER3_DEGREE: Lazy<u32> = Lazy::new(|| read_env_var("AGG_LAYER3_DEGREE", 24));
pub static AGG_LAYER4_DEGREE: Lazy<u32> = Lazy::new(|| read_env_var("AGG_LAYER4_DEGREE", 24));

pub static ALL_AGG_DEGREES: Lazy<Vec<u32>> = Lazy::new(|| {
=======
pub static ZKEVM_DEGREES: Lazy<Vec<u32>> = Lazy::new(|| {
>>>>>>> main
    Vec::from_iter(HashSet::from([
        *INNER_DEGREE,
        *LAYER1_DEGREE,
        *LAYER2_DEGREE,
    ]))
});

pub static AGG_DEGREES: Lazy<Vec<u32>> = Lazy::new(|| {
    Vec::from_iter(HashSet::from([
        // TODO: optimize to decrease degree for padding.
        *LAYER1_DEGREE, // For layer-1 padding snark generation
        *LAYER2_DEGREE, // For layer-2 padding snark generation
        *LAYER3_DEGREE,
        *LAYER4_DEGREE,
    ]))
});
