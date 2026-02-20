#[derive(Debug)]


#[non_exhaustive]
pub enum Error {
    InvalidState,
    CryptoFail,
    VerificationFail,
    UnexpectedMessageType,
    SMPAnswerEmpty,
    SMPnonceDuplicated,

    UninitializedContactKeys,

    RandomBytesGenerationFailed,
    SizeExceedsSHA3512,
    SigError,
    KemError,
    InvalidKemPublicKey,
    InvalidKemPublicKeyLength,
    InvalidKemSecretKey,
    InvalidKemCiphertextLength,
    InvalidSigPublicKey,
    InvalidSigSecretKey,
    InvalidChaCha20PaddingLength,
    InvalidChaCha20KeyLength,
    InvalidChaCha20NonceLength,
    ChaCha20EncryptionFailed,
    ChaCha20DecryptionFailed,
    ChaCha20MalformedPadding,

    
    InvalidSigningPublicKeyLength,
    InvalidSmpPlaintextLength,
    InvalidPfsPlaintextLength,
    InvalidPfsType,

    InvalidMsgsPlaintextLength,
    InvalidDataLength,

    Argon2IdHashingError,

    ProtocolViolation,
    SmpQuestionInvalidUtf8,

    SMPInvalidContactProof,
    SigVerificationFailed,
    InvalidHashChain,
    InvalidDataPlaintextLength,

    InvalidDataType,

    OTPKeyTooShort,
    InvalidOTPCiphertext
}
