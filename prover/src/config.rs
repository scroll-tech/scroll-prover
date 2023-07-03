use crate::utils::read_env_var;
use once_cell::sync::Lazy;

pub static INNER_DEGREE: Lazy<u32> = Lazy::new(|| read_env_var("DEGREE", 20));
pub static CHUNK_DEGREE: Lazy<u32> = Lazy::new(|| read_env_var("AGG_DEGREE", 25));
pub static AGG_DEGREE: Lazy<u32> = Lazy::new(|| read_env_var("AGG_DEGREE", 26));
