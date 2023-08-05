use crate::utils::read_env_var;
use aggregator::ConfigParams;
use once_cell::sync::Lazy;
use std::{collections::HashSet, fs::File, path::Path};

pub static INNER_DEGREE: Lazy<u32> = Lazy::new(|| read_env_var("SCROLL_PROVER_INNER_DEGREE", 20));

pub static ASSETS_DIR: Lazy<String> =
    Lazy::new(|| read_env_var("SCROLL_PROVER_ASSETS_DIR", "configs".to_string()));

pub static LAYER1_CONFIG_PATH: Lazy<String> = Lazy::new(|| asset_file_path("layer1.config"));
pub static LAYER2_CONFIG_PATH: Lazy<String> = Lazy::new(|| asset_file_path("layer2.config"));
pub static LAYER3_CONFIG_PATH: Lazy<String> = Lazy::new(|| asset_file_path("layer3.config"));
pub static LAYER4_CONFIG_PATH: Lazy<String> = Lazy::new(|| asset_file_path("layer4.config"));

pub static LAYER1_DEGREE: Lazy<u32> = Lazy::new(|| layer_degree(&LAYER1_CONFIG_PATH));
pub static LAYER2_DEGREE: Lazy<u32> = Lazy::new(|| layer_degree(&LAYER2_CONFIG_PATH));
pub static LAYER3_DEGREE: Lazy<u32> = Lazy::new(|| layer_degree(&LAYER3_CONFIG_PATH));
pub static LAYER4_DEGREE: Lazy<u32> = Lazy::new(|| layer_degree(&LAYER4_CONFIG_PATH));

pub static ZKEVM_DEGREES: Lazy<Vec<u32>> = Lazy::new(|| {
    Vec::from_iter(HashSet::from([
        *INNER_DEGREE,
        *LAYER1_DEGREE,
        *LAYER2_DEGREE,
    ]))
});

pub static AGG_DEGREES: Lazy<Vec<u32>> =
    Lazy::new(|| Vec::from_iter(HashSet::from([*LAYER3_DEGREE, *LAYER4_DEGREE])));

pub fn layer_config_path(id: &str) -> &str {
    match id {
        "layer1" => &LAYER1_CONFIG_PATH,
        "layer2" => &LAYER2_CONFIG_PATH,
        "layer3" => &LAYER3_CONFIG_PATH,
        "layer4" => &LAYER4_CONFIG_PATH,
        _ => panic!("Wrong id-{id} to get layer config path"),
    }
}

fn asset_file_path(filename: &str) -> String {
    Path::new(&*ASSETS_DIR)
        .join(filename)
        .to_string_lossy()
        .into_owned()
}

fn layer_degree(config_file: &str) -> u32 {
    let f = File::open(config_file).unwrap_or_else(|_| panic!("Failed to open {config_file}"));

    let params: ConfigParams =
        serde_json::from_reader(f).unwrap_or_else(|_| panic!("Failed to parse {config_file}"));

    params.degree
}
