#[derive(Debug)]


#[non_exhaustive]
pub enum Error {
    InvalidState,
    CryptoFail,
    VerificationFail,
    UnexpectedMessageType,
    SMPAnswerEmpty,
    SMPnonceDuplicated,

    RandomBytesGenerationFailed,
    SizeExceedsSHA3512,
    KemError,
    InvalidKemPublicKey,
    InvalidKemPublicKeyLength,
    InvalidKemSecretKey,
    InvalidKemCiphertextLength,
    InvalidChaCha20PaddingLength,
    InvalidChaCha20KeyLength,
    InvalidChaCha20NonceLength,
    ChaCha20EncryptionFailed,
    ChaCha20DecryptionFailed,
    ChaCha20MalformedPadding,

    
    InvalidSigningPublicKeyLength,
    InvalidSmpPlaintextLength,

    InvalidDataLength,

    Argon2IdHashingError,

    ProtocolViolation,
    SmpQuestionInvalidUtf8,

    SMPInvalidContactProof

}
