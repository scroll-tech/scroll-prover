use rand::Rng;
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;

pub(crate) fn gen_rng() -> impl Rng + Send {
    let seed = [0u8; 16];
    XorShiftRng::from_seed(seed)
}

pub(crate) fn tick(desc: &str) {
    #[cfg(target_os = "linux")]
    let memory = match procfs::Meminfo::new() {
        Ok(m) => m.mem_total - m.mem_free,
        Err(_) => 0,
    };
    #[cfg(not(target_os = "linux"))]
    let memory = 0;
    log::debug!(
        "memory usage when {}: {:?}GB",
        desc,
        memory / 1024 / 1024 / 1024
    );
}
