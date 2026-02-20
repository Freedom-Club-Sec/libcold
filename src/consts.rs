pub const ML_DSA_87_PK_SIZE: usize = 2592;
pub const ML_DSA_87_SIGN_SIZE: usize = 4627;

pub const ML_KEM_1024_PK_SIZE: usize = 1568;
pub const ML_KEM_1024_CT_SIZE: usize = 1568;


pub const CLASSIC_MCELIECE_8_PK_SIZE: usize = 1357824;
pub const CLASSIC_MCELIECE_8_CT_SIZE: usize = 208; 


pub const SMP_NONCE_SIZE: usize = 64;
pub const SMP_TYPE_INIT_SMP: u8 = 0x00;


pub const PFS_TYPE_PFS_NEW: u8 = 0x01;

pub const PFS_TYPE_PFS_ACK: u8 = 0x02;

/// Maximum nonce size for ChaCha20Poly1305 (12 bytes for IETF variant)
pub const CHACHA20POLY1305_NONCE_SIZE: usize = 12;

/// Number of bytes used to store padding length
pub const CHACHA20POLY1305_SIZE_LEN: usize = 2;

/// Default maximum random padding
pub const CHACHA20POLY1305_MAX_RANDOM_PAD: usize = 64;

/// Must be always 16 bytes for interoperability with implementations that use libsodium.
pub const ARGON2ID_SALT_SIZE: usize = 16;

/// Memory cost in KiB (1 GB).
// TODO: Increase to 4 GB as double to the recommended RFC amount.
pub const ARGON2ID_MEM_COST: u32 = 1 * 1024; // DEBUG amount

/// Memory iterations.
pub const ARGON2ID_ITERS: u32 = 3;

pub const ARGON2ID_LANES: u32 = 1;

pub const ARGON2ID_OUTPUT_LEN: usize = 64;

pub const OTP_PAD_SIZE: usize = 11264;
pub const OTP_MAX_BUCKET: usize = 64;
pub const OTP_MAX_RANDOM_PAD: usize = 16;
pub const OTP_SIZE_LENGTH: usize = 2;

pub const OTP_MAX_MESSAGE_LEN: usize = OTP_PAD_SIZE - OTP_SIZE_LENGTH;

pub const MSG_TYPE_MSG_BATCH: u8 = 0x03;
pub const MSG_TYPE_MSG_NEW: u8 = 0x04;
