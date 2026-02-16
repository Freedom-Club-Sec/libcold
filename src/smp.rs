use zeroize::Zeroizing;
use crate::consts;
use crate::crypto;
use crate::error::Error;


pub fn calculate_proof(answer_secret: &Zeroizing<Vec<u8>>, proof_1: &[u8], proof_2: &[u8], proof_3: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut our_proof_plain = Zeroizing::new(Vec::with_capacity(proof_1.len() + proof_2.len() + proof_3.len()));
    our_proof_plain.extend_from_slice(proof_1);
    our_proof_plain.extend_from_slice(proof_2);
    our_proof_plain.extend_from_slice(proof_3);

    let our_proof = crypto::hmac_sha3_512(
        &our_proof_plain, 
        &answer_secret
    );


    Ok(our_proof)
}

pub fn calculate_answer_secret(smp_answer: &[u8], salt_1: &[u8], salt_2: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut argon2id_salt = Zeroizing::new(Vec::with_capacity(salt_1.len() + salt_2.len()));
    argon2id_salt.extend_from_slice(salt_1);
    argon2id_salt.extend_from_slice(salt_2);

    argon2id_salt = crypto::hash_sha3_512(&argon2id_salt);
    argon2id_salt = Zeroizing::new(argon2id_salt[..consts::ARGON2ID_SALT_SIZE].to_vec());

    let answer_secret = Zeroizing::new(crypto::hash_argon2id(
        smp_answer,
        &argon2id_salt
    ).unwrap());


    Ok(answer_secret)
}


pub fn normalize_smp_answer(s: Zeroizing<String>) -> Result<Zeroizing<String>, Error> {
    let s = s.trim();
    if s.is_empty() {
        return Err(Error::SMPAnswerEmpty);
    }

    let mut out = Zeroizing::new(String::with_capacity(s.len()));
    let mut chars = s.chars();
    if let Some(first) = chars.next() {
        for c in first.to_lowercase() {
            out.push(c);
        }
    }
    out.push_str(chars.as_str());

    Ok(out)
}
