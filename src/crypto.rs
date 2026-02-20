use zeroize::Zeroizing;
use subtle::ConstantTimeEq;
use hmac::{
    Hmac, Mac
};
use sha3::{
    Digest, Sha3_512
};
use rand::{
    rngs::{OsRng}, 
    TryRngCore
};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce, Key
};
use argon2::{
    Argon2, Params
};
use crate::consts;
use crate::Error;

/// Encrypts plaintext with ChaCha20Poly1305, adding random padding and (optionally) using a random nonce.
///
/// Returns `(ciphertext, nonce)`.
pub fn encrypt_chacha20poly1305(key_bytes: &Zeroizing<Vec<u8>>, plaintext: &[u8], nonce_bytes: Option<&[u8]>, max_padding: usize) -> Result<(Vec<u8>, Nonce), Error> {
    if key_bytes.len() != 32 {
        return Err(Error::InvalidChaCha20KeyLength);
    }

    let key = Key::from_slice(key_bytes);

    // Check max_padding limits
    if max_padding > (2_usize.pow((consts::CHACHA20POLY1305_SIZE_LEN * 8) as u32) - 1) {
        return Err(Error::InvalidChaCha20PaddingLength);
    }


    // Generate nonce if not provided
    let nonce: Nonce = match nonce_bytes {
        Some(bytes) => {
            if bytes.len() != consts::CHACHA20POLY1305_NONCE_SIZE {
                return Err(Error::InvalidChaCha20NonceLength);
            }

            *Nonce::from_slice(bytes)
        },
        None => {
            // generate random nonce
            let random_bytes = generate_secure_random_bytes(consts::CHACHA20POLY1305_NONCE_SIZE)?;
            let hashed = hash_sha3_512(&random_bytes);
            let nonce_bytes = &hashed[..consts::CHACHA20POLY1305_NONCE_SIZE];
            *Nonce::from_slice(nonce_bytes)
        }
    };


    let padding_len = if max_padding > 0 {
        rand::random_range(0..=max_padding)
    } else {
        0
    };


    let padding = generate_secure_random_bytes(padding_len)?;

    // Prepend padding length and append padding
    let mut padded_plaintext = Vec::with_capacity(consts::CHACHA20POLY1305_SIZE_LEN + plaintext.len() + padding_len);
    padded_plaintext.extend_from_slice(&(padding_len as u16).to_be_bytes());
    padded_plaintext.extend_from_slice(plaintext);
    padded_plaintext.extend_from_slice(&padding);

    // Encrypt
    let cipher = ChaCha20Poly1305::new(key);
    let ciphertext = cipher.encrypt(&nonce, padded_plaintext.as_ref()).map_err(|_| Error::ChaCha20EncryptionFailed)?;

    Ok((ciphertext, nonce))
}

pub fn decrypt_chacha20poly1305(key_bytes: &Zeroizing<Vec<u8>>, nonce_bytes: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    if key_bytes.len() != 32 {
        return Err(Error::InvalidChaCha20KeyLength);
    }

    if nonce_bytes.len() != consts::CHACHA20POLY1305_NONCE_SIZE {
        return Err(Error::InvalidChaCha20NonceLength);
    }

    let key = Key::from_slice(key_bytes);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = ChaCha20Poly1305::new(key);

    // Decrypt ciphertext
    let padded_plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| Error::ChaCha20DecryptionFailed)?;

    // Ensure we have enough bytes for padding length
    if padded_plaintext.len() < consts::CHACHA20POLY1305_SIZE_LEN {
        return Err(Error::ChaCha20MalformedPadding);
    }

    // Read padding length
    let padding_length = u16::from_be_bytes([
        padded_plaintext[0],
        padded_plaintext[1],
    ]) as usize;

    if padding_length > padded_plaintext.len() - consts::CHACHA20POLY1305_SIZE_LEN {
        return Err(Error::ChaCha20MalformedPadding);
    }

    // Strip padding and return plaintext
    let plaintext = padded_plaintext[..padded_plaintext.len() - padding_length]
        [consts::CHACHA20POLY1305_SIZE_LEN..]
        .to_vec();

    Ok(Zeroizing::new(plaintext))
}


pub fn one_time_pad(plaintext: &[u8], key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
    if plaintext.len() > key.len() {
        return Err(Error::OTPKeyTooShort);
    }

    let otpd: Vec<u8> = plaintext.iter().zip(key.iter()).map(|(&p,&k)| p^k).collect();
    let remaining_key = key[otpd.len()..].to_vec();

    Ok((otpd, remaining_key))
}

pub fn otp_encrypt_with_padding(plaintext: &[u8], key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let pad_len = if plaintext.len() <= consts::OTP_MAX_BUCKET - consts::OTP_SIZE_LENGTH {
        consts::OTP_MAX_BUCKET - consts::OTP_SIZE_LENGTH - plaintext.len()
    } else {
        rand::random_range(0..=consts::OTP_MAX_RANDOM_PAD)
    };

    let padding = generate_secure_random_bytes(pad_len)?;

    let plaintext_len_bytes = (plaintext.len() as u64)
        .to_be_bytes()[8 - consts::OTP_SIZE_LENGTH..]
        .to_vec();

    let mut padded_plaintext = Vec::with_capacity(
        consts::OTP_SIZE_LENGTH + plaintext.len() + pad_len,
    );

    padded_plaintext.extend_from_slice(&plaintext_len_bytes);
    padded_plaintext.extend_from_slice(plaintext);
    padded_plaintext.extend_from_slice(&padding);

    one_time_pad(&padded_plaintext, key)
}



/// This doesnt return truncated pads, its up to caller to truncate his pads.
pub fn otp_decrypt_with_padding(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, Error> {
    let (plaintext_with_padding, _) = one_time_pad(ciphertext, key)?;

    if plaintext_with_padding.len() < consts::OTP_SIZE_LENGTH {
        return Err(Error::InvalidOTPCiphertext);
    }

    let mut len_buf = [0u8; 8];
    len_buf[8 - consts::OTP_SIZE_LENGTH..]
        .copy_from_slice(&plaintext_with_padding[..consts::OTP_SIZE_LENGTH]);

    let plaintext_len = u64::from_be_bytes(len_buf) as usize;

    if plaintext_len == 0 {
        return Err(Error::InvalidOTPCiphertext);
    }


    if consts::OTP_SIZE_LENGTH + plaintext_len > plaintext_with_padding.len() {
        return Err(Error::InvalidOTPCiphertext);
    }

    let plaintext_without_padding = plaintext_with_padding[consts::OTP_SIZE_LENGTH..consts::OTP_SIZE_LENGTH + plaintext_len].to_vec();

    Ok(plaintext_without_padding)
}

pub fn hash_argon2id(plaintext: &[u8], salt: &[u8]) -> Result<Vec<u8>, Error> {
    let mut output_key_material = [0u8; consts::ARGON2ID_OUTPUT_LEN];

    let params = Params::new(
        consts::ARGON2ID_MEM_COST,
        consts::ARGON2ID_ITERS,
        consts::ARGON2ID_LANES,
        Some(consts::ARGON2ID_OUTPUT_LEN),
    ).unwrap();


    // Version 0x13 = 19 in hex.
    let argon2id = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    argon2id.hash_password_into(plaintext, salt, &mut output_key_material)
        .map_err(|_| Error::Argon2IdHashingError)?;

    Ok(output_key_material.to_vec())
}

pub fn hash_sha3_512(data: &Zeroizing<Vec<u8>>) -> Zeroizing<Vec<u8>> {
    let mut hasher = Sha3_512::new();

    hasher.update(&*data);

    Zeroizing::new(hasher.finalize().to_vec())
}


pub fn generate_signing_keypair(alg: oqs::sig::Algorithm) -> oqs::Result<(Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>)> {    
    let sigalg = oqs::sig::Sig::new(alg)?;
    let (pk, sk) = sigalg.keypair()?;
    
    Ok((Zeroizing::new(pk.as_ref().to_vec()), Zeroizing::new(sk.as_ref().to_vec())))
}


pub fn generate_signature(alg: oqs::sig::Algorithm, secret_key_bytes: &[u8], data: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {    
    let sigalg = oqs::sig::Sig::new(alg)
        .map_err(|_| Error::SigError)?;

    let sk = sigalg
        .secret_key_from_bytes(secret_key_bytes)
        .ok_or(Error::InvalidSigSecretKey)?;

    let signature = sigalg.sign(data, &sk)
        .map_err(|_| Error::SigError)?;

    Ok(Zeroizing::new(signature.into_vec()))
}

pub fn verify_signature(alg: oqs::sig::Algorithm, public_key_bytes: &[u8], data: &[u8], signature_bytes: &[u8]) -> Result<(), Error> {    
    let sigalg = oqs::sig::Sig::new(alg)
        .map_err(|_| Error::SigError)?;

    let sig_pk = sigalg
        .public_key_from_bytes(public_key_bytes)
        .ok_or(Error::InvalidSigPublicKey)?;

    let signature = sigalg
        .signature_from_bytes(signature_bytes)
        .ok_or(Error::InvalidSigPublicKey)?;


    let sig_result = sigalg.verify(data, &signature, &sig_pk)
        .map_err(|_| Error::SigVerificationFailed)?;

    Ok(sig_result)
}



pub fn generate_kem_keypair(alg: oqs::kem::Algorithm) -> oqs::Result<(Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>)> {    
    let kemalg = oqs::kem::Kem::new(alg)?;
    let (pk, sk) = kemalg.keypair()?;
    
    Ok((Zeroizing::new(pk.as_ref().to_vec()), Zeroizing::new(sk.as_ref().to_vec())))
}


pub fn generate_secure_random_bytes(len: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut buf = Zeroizing::new(vec![0u8; len]);
    OsRng.try_fill_bytes(&mut buf).map_err(|_| Error::RandomBytesGenerationFailed)?;

    Ok(buf)
}

/// Same as generate_secure_random_bytes, but it whitens the entropy. 
/// Max len is 64 (SHA3-512 output)
pub fn generate_secure_random_bytes_whiten(len: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    if len > 64 {
        return Err(Error::SizeExceedsSHA3512);
    }

    let mut buf = Zeroizing::new(vec![0u8; len]);
    OsRng.try_fill_bytes(&mut buf).map_err(|_| Error::RandomBytesGenerationFailed)?;

    let hashed_buf = hash_sha3_512(&buf);
    let trimmed_hashed_buf = Zeroizing::new(hashed_buf[..len].to_vec());


    Ok(trimmed_hashed_buf)
}


pub fn generate_shared_secrets(public_key_bytes: &[u8], algorithm: oqs::kem::Algorithm, size: usize) -> Result<(Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>), Error> {
    let kem = oqs::kem::Kem::new(algorithm)
        .map_err(|_| Error::KemError)?;


    let pk_ref = kem
        .public_key_from_bytes(public_key_bytes)
        .ok_or(Error::InvalidKemPublicKey)?;

    let ss_len = kem.length_shared_secret();
    let ct_len = kem.length_ciphertext();
    let rounds = (size + ss_len - 1) / ss_len;

    let mut ciphertexts = Zeroizing::new(Vec::with_capacity(rounds * ct_len));
    let mut shared_secrets = Zeroizing::new(Vec::with_capacity(size));

    for _ in 0..rounds {
        let (ct, ss) = kem.encapsulate(&pk_ref)
            .map_err(|_| Error::KemError)?;

        ciphertexts.extend_from_slice(ct.as_ref());

        let remaining = size - shared_secrets.len();
        let take = remaining.min(ss.as_ref().len());
        shared_secrets.extend_from_slice(&ss.as_ref()[..take]);
    }

    Ok((ciphertexts, shared_secrets))
}


pub fn decrypt_shared_secrets(ciphertext_blob: &[u8], private_key_bytes: &Zeroizing<Vec<u8>>, algorithm: oqs::kem::Algorithm, size: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    let kem = oqs::kem::Kem::new(algorithm)
        .map_err(|_| Error::KemError)?;

    let sk_len = kem.length_secret_key();
    let ct_len = kem.length_ciphertext();

    if private_key_bytes.len() < sk_len {
        return Err(Error::InvalidKemSecretKey);
    }

    let sk = kem
        .secret_key_from_bytes(&private_key_bytes[..sk_len])
        .ok_or(Error::InvalidKemSecretKey)?;

    let mut shared_secrets = Zeroizing::new(Vec::with_capacity(size));
    let mut cursor = 0;

    while shared_secrets.len() < size {
        if cursor + ct_len > ciphertext_blob.len() {
            return Err(Error::InvalidKemCiphertextLength);
        }

        let ciphertext = &ciphertext_blob[cursor..cursor + ct_len];

        let ct = kem
        .ciphertext_from_bytes(ciphertext)
        .ok_or(Error::InvalidKemCiphertextLength)?;

        let ss = kem
            .decapsulate(&sk, &ct)
            .map_err(|_| Error::KemError)?;

        let remaining = size - shared_secrets.len();
        let take = remaining.min(ss.as_ref().len());

        shared_secrets.extend_from_slice(&ss.as_ref()[..take]);

        cursor += ct_len;
    }

    Ok(shared_secrets)
}



pub fn hmac_sha3_512(data: &[u8], key: &Zeroizing<Vec<u8>>) -> Zeroizing<Vec<u8>> {
    let mut mac = <Hmac<Sha3_512> as Mac>::new_from_slice(&*key)
        .expect("HMAC key length is invalid");

    mac.update(data);

    let result = mac.finalize().into_bytes();
    Zeroizing::new(result.to_vec())
}

pub fn compare_secrets(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).unwrap_u8() == 1
}


#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn test_secure_random_bytes() {
        let len = 32;

        let buf1 = generate_secure_random_bytes(len).expect("Failed to generate random bytes");
        let buf2 = generate_secure_random_bytes(len).expect("Failed to generate random bytes");

        assert_eq!(buf1.len(), len, "Generated buffer has incorrect length");
        assert_eq!(buf2.len(), len, "Generated buffer has incorrect length");

        assert_ne!(buf1.as_slice(), buf2.as_slice(), "Two generated random buffers are identical; unlikely");

        assert!(buf1.iter().any(|&b| b != 0), "Random buffer is all zeros, unlikely");
        assert!(buf2.iter().any(|&b| b != 0), "Random buffer is all zeros, unlikely");

    }

    #[test]
    fn test_encrypt_decrypt_roundtrip_no_padding() {
        let key = generate_secure_random_bytes(32).unwrap();
        let plaintext = b"Hello world!";
        let (ct, nonce) = encrypt_chacha20poly1305(&key, plaintext, None, 0).unwrap();
        assert_ne!(ct, nonce.as_slice(), "Ciphertext and nonce are equal");
        assert_ne!(ct, plaintext, "Ciphertext and plaintext are equal");
        assert_ne!(nonce.as_slice(), plaintext, "Nonce and plaintext are equal");
        assert_ne!(ct, key.as_slice(), "Ciphertext and key are equal");
        assert_ne!(nonce.as_slice(), key.as_slice(), "Nonce and key are equal");

        let pt = decrypt_chacha20poly1305(&key, &nonce, &ct).unwrap();
        assert_eq!(pt.as_slice(), plaintext, "Decrypted ciphertext is not equal to plaintext");
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip_with_padding() {
        let key = generate_secure_random_bytes(32).unwrap();
        let plaintext = b"Hello world!";
        let (ct, nonce) = encrypt_chacha20poly1305(&key, plaintext, None, 60).unwrap();
        assert_ne!(ct, nonce.as_slice(), "Ciphertext and nonce are equal");
        assert_ne!(ct, plaintext, "Ciphertext and plaintext are equal");
        assert_ne!(nonce.as_slice(), plaintext, "Nonce and plaintext are equal");
        assert_ne!(ct, key.as_slice(), "Ciphertext and key are equal");
        assert_ne!(nonce.as_slice(), key.as_slice(), "Nonce and key are equal");

        let pt = decrypt_chacha20poly1305(&key, &nonce, &ct).unwrap();
        assert_eq!(pt.as_slice(), plaintext, "Decrypted ciphertext is not equal to plaintext");
    }


    #[test]
    fn test_encrypt_invalid_nonce() {
        let key = generate_secure_random_bytes(32).unwrap();
        let plaintext = b"Hello world!";

        // Too short
        let short_nonce = generate_secure_random_bytes(consts::CHACHA20POLY1305_NONCE_SIZE - 1).unwrap();
        let err = encrypt_chacha20poly1305(&key, plaintext, Some(short_nonce.as_slice()), 0).unwrap_err();
        assert!(matches!(err, Error::InvalidChaCha20NonceLength));

        // Too long
        let long_nonce = generate_secure_random_bytes(consts::CHACHA20POLY1305_NONCE_SIZE + 1).unwrap();
        let err = encrypt_chacha20poly1305(&key, plaintext, Some(long_nonce.as_slice()), 0).unwrap_err();
        assert!(matches!(err, Error::InvalidChaCha20NonceLength));
    }



    #[test]
    fn test_encrypt_nonce_behaviour_no_padding() {
        let key = generate_secure_random_bytes(32).unwrap();
        let our_nonce = generate_secure_random_bytes(consts::CHACHA20POLY1305_NONCE_SIZE).unwrap();
        let plaintext = b"Hello world!";
        let (_, nonce_1) = encrypt_chacha20poly1305(&key, plaintext, Some(our_nonce.as_slice()), 0).unwrap();

        assert_eq!(nonce_1.as_slice(), our_nonce.as_slice(), "Nonce returned by function does not match nonce we supplied.");
      
        let (_, nonce_2) = encrypt_chacha20poly1305(&key, plaintext, None, 0).unwrap();

        assert_ne!(nonce_2.as_slice(), our_nonce.as_slice(), "Nonce returned by function somehow matches our_nonce??");
        assert_ne!(nonce_2.as_slice(), nonce_1.as_slice(), "Nonce returned by function equals to nonce_1. Hardcoded nonce?");

    }

    #[test]
    fn test_encrypt_nonce_behaviour_with_padding() {
        let key = generate_secure_random_bytes(32).unwrap();
        let our_nonce = generate_secure_random_bytes(consts::CHACHA20POLY1305_NONCE_SIZE).unwrap();
        let plaintext = b"Hello world!";
        let (_, nonce_1) = encrypt_chacha20poly1305(&key, plaintext, Some(our_nonce.as_slice()), 60).unwrap();

        assert_eq!(nonce_1.as_slice(), our_nonce.as_slice(), "Nonce returned by function does not match nonce we supplied.");
      
        let (_, nonce_2) = encrypt_chacha20poly1305(&key, plaintext, None, 60).unwrap();

        assert_ne!(nonce_2.as_slice(), our_nonce.as_slice(), "Nonce returned by function somehow matches our_nonce??");
        assert_ne!(nonce_2.as_slice(), nonce_1.as_slice(), "Nonce returned by function equals to nonce_1. Hardcoded nonce?");

    }



    #[test]
    fn test_otp_without_padding() {
        let plaintext = b"Hello world!";
        let pads = generate_secure_random_bytes(32).unwrap();

        let (ct, new_pads) = one_time_pad(plaintext, &pads).unwrap();
        assert_ne!(ct, plaintext, "Ciphertext and plaintext are equal");
        assert_ne!(new_pads, plaintext, "new_pads and plaintext are equal");
        assert_ne!(ct, new_pads, "Ciphertext and new_pads are equal");
        
        assert_ne!(pads.as_slice(), new_pads, "Pads and new_pads are equal");

        assert_eq!(ct.len(), plaintext.len(), "Ciphertext length and plaintext length not equal");

        let (decrypted_pt, new_pads) = one_time_pad(&ct, &pads).unwrap();
        assert_ne!(new_pads, decrypted_pt, "new_pads and decrypted plaintext are equal");
        assert_ne!(ct, new_pads, "Ciphertext and new_pads are equal");

        assert_ne!(pads.as_slice(), new_pads, "Pads and new_pads are equal");
        
        assert_eq!(decrypted_pt, plaintext, "Decrypted plaintext and original plaintext are not equal");
    }

    #[test]
    fn test_otp_with_padding_small() {
        let plaintext = b"Hello world!";
        let pads = generate_secure_random_bytes(70).unwrap();

        let (ct, new_pads) = otp_encrypt_with_padding(plaintext, &pads).unwrap();

        assert_eq!(ct.len(), consts::OTP_MAX_BUCKET, "Bucket padding does not match OTP_MAX_BUCKET");

        assert_ne!(ct, new_pads, "Ciphertext and new_pads are equal");
        assert_ne!(pads.as_slice(), new_pads, "Pads and new_pads are equal");


        let decrypted_pt = otp_decrypt_with_padding(&ct, &pads).unwrap();

        assert_eq!(decrypted_pt, plaintext, "Decrypted plaintext and original plaintext are not equal");
    }

}
