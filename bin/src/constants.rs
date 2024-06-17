/// Copied from blob.rs. TODO: Export these to avoid copy?

/// The number of coefficients (BLS12-381 scalars) to represent the blob polynomial in evaluation
/// form.
pub const BLOB_WIDTH: usize = 4096;

/// The number data bytes we pack each BLS12-381 scalar into. The most-significant byte is 0.
pub const N_DATA_BYTES_PER_COEFFICIENT: usize = 31;

/// The number of bytes that we can fit in a blob. Note that each coefficient is represented in 32
/// bytes, however, since those 32 bytes must represent a BLS12-381 scalar in its canonical form,
/// we explicitly set the most-significant byte to 0, effectively utilising only 31 bytes.
pub const N_BLOB_BYTES: usize = BLOB_WIDTH * N_DATA_BYTES_PER_COEFFICIENT;
