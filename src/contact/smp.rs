use zeroize::Zeroizing;
use crate::consts;
use crate::crypto;
use crate::error::Error;

use super::*;


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


pub(crate) fn normalize_smp_answer(s: Zeroizing<String>) -> Result<Zeroizing<String>, Error> {
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


impl Contact {
    pub fn init_smp(&mut self, question: String, answer: String) -> Result<ContactOutput, Error> {
        // Normalize and store SMP answer
        let normalized = normalize_smp_answer(Zeroizing::new(answer))?;
        self.smp_answer = Some(normalized);
        self.smp_question = Some(question);

        self.init_tmp_kem_keypair()?;

         let pk = self.our_smp_tmp_pub_key
            .as_ref()
            .expect("SMP temp pubkey must exist");

        // append the SMP type byte to the start of the public key
        let mut out = Zeroizing::new(Vec::with_capacity(1 + pk.len()));
        out.push(consts::SMP_TYPE_INIT_SMP);
        out.extend_from_slice(pk);

        self.state = ContactState::SMPInit;

        Ok(ContactOutput::Wire(vec![WireMessage(out)]))
    }
     
    pub(super) fn do_smp_step_2(&mut self, data: &[u8]) -> Result<ContactOutput, Error> {
        if data.len() != 1 + consts::ML_KEM_1024_PK_SIZE {
            return Err(Error::InvalidKemPublicKeyLength);
        }

        let signing_pk = self.our_signing_pub_key.as_ref().expect("our_signing_pub_key must be initialized");
        

        let (key_ciphertexts, shared_secrets) = crypto::generate_shared_secrets(&data[1..], oqs::kem::Algorithm::MlKem1024, 64)?;

        let our_strand_key = Zeroizing::new(shared_secrets[0..32].to_vec());
        let contact_next_strand_key = Zeroizing::new(shared_secrets[32..64].to_vec());

        let our_next_strand_key = crypto::generate_secure_random_bytes_whiten(32)?;

        let our_next_strand_nonce = crypto::generate_secure_random_bytes_whiten(consts::CHACHA20POLY1305_NONCE_SIZE)?;

        let contact_next_strand_nonce = crypto::generate_secure_random_bytes_whiten(consts::CHACHA20POLY1305_NONCE_SIZE)?;

        let our_smp_nonce = crypto::generate_secure_random_bytes_whiten(consts::SMP_NONCE_SIZE)?;

        let mut inner_payload = Zeroizing::new(Vec::with_capacity(
            our_next_strand_key.len() +
            signing_pk.len() +
            our_smp_nonce.len() +
            our_next_strand_nonce.len() +
            contact_next_strand_nonce.len()
        ));

        inner_payload.extend_from_slice(&our_next_strand_key);
        inner_payload.extend_from_slice(&signing_pk);
        inner_payload.extend_from_slice(&our_smp_nonce);
        inner_payload.extend_from_slice(&our_next_strand_nonce);
        inner_payload.extend_from_slice(&contact_next_strand_nonce);


        let (ciphertext_blob, ciphertext_nonce) = crypto::encrypt_chacha20poly1305(&our_strand_key, &inner_payload, None, consts::CHACHA20POLY1305_MAX_RANDOM_PAD)?;


        self.our_next_strand_key = Some(our_next_strand_key);
        self.our_next_strand_nonce = Some(our_next_strand_nonce);

        self.contact_next_strand_key = Some(contact_next_strand_key);
        self.contact_next_strand_nonce = Some(contact_next_strand_nonce);

        self.our_smp_nonce = Some(our_smp_nonce);

        self.contact_smp_tmp_pub_key = Some(
            Zeroizing::new(
                data[1..1 + consts::ML_KEM_1024_PK_SIZE].to_vec()
            )
        );


        let mut out = Zeroizing::new(Vec::with_capacity(1 + key_ciphertexts.len() + ciphertext_blob.len() + ciphertext_nonce.len()));
        out.push(consts::SMP_TYPE_INIT_SMP);
        out.extend_from_slice(&key_ciphertexts);
        out.extend_from_slice(ciphertext_nonce.as_slice());
        out.extend_from_slice(&ciphertext_blob);

        self.state = ContactState::SMPStep2;

        Ok(ContactOutput::Wire(vec![WireMessage(out)]))
    }

    pub(super) fn do_smp_step_3(&mut self, data: &[u8]) ->  Result<ContactOutput, Error> {
        let key_ciphertexts = &data.get(1 .. (consts::ML_KEM_1024_CT_SIZE * 2) + 1)
            .ok_or(Error::InvalidDataLength)?;

        let sk = self.our_smp_tmp_secret_key.as_ref().expect("our_smp_tmp_secret_key must be initialized before SMP step");

        let smp_answer = self.smp_answer.as_ref().unwrap().as_bytes();

        let shared_secrets = crypto::decrypt_shared_secrets(key_ciphertexts, sk, oqs::kem::Algorithm::MlKem1024, 64)?;

        let contact_strand_key = Zeroizing::new(shared_secrets[0..32].to_vec());
        let our_strand_key = Zeroizing::new(shared_secrets[32..64].to_vec());


        let smp_ciphertext = data.get(key_ciphertexts.len() + 1 + consts::CHACHA20POLY1305_NONCE_SIZE ..)
            .ok_or(Error::InvalidDataLength)?;

        let chacha_nonce = data.get(key_ciphertexts.len() + 1 .. key_ciphertexts.len() + 1 + consts::CHACHA20POLY1305_NONCE_SIZE)
            .ok_or(Error::InvalidDataLength)?;


        let plaintext = crypto::decrypt_chacha20poly1305(&contact_strand_key, chacha_nonce, smp_ciphertext)?;

        let contact_next_strand_key = plaintext.get(..32)
            .ok_or(Error::InvalidSmpPlaintextLength)?;

        let smp_plaintext = plaintext.get(32..)
            .ok_or(Error::InvalidSmpPlaintextLength)?;

        let contact_signing_pk = smp_plaintext.get(..consts::ML_DSA_87_PK_SIZE)
            .ok_or(Error::InvalidSmpPlaintextLength)?;

        let contact_smp_nonce = smp_plaintext.get(consts::ML_DSA_87_PK_SIZE .. consts::ML_DSA_87_PK_SIZE + consts::SMP_NONCE_SIZE)
            .ok_or(Error::InvalidSmpPlaintextLength)?;

        let contact_next_strand_nonce = smp_plaintext.get(consts::ML_DSA_87_PK_SIZE + consts::SMP_NONCE_SIZE .. consts::ML_DSA_87_PK_SIZE + consts::SMP_NONCE_SIZE + consts::CHACHA20POLY1305_NONCE_SIZE)
            .ok_or(Error::InvalidSmpPlaintextLength)?;

        let our_next_strand_nonce = smp_plaintext.get(consts::ML_DSA_87_PK_SIZE + consts::SMP_NONCE_SIZE + consts::CHACHA20POLY1305_NONCE_SIZE ..)
            .ok_or(Error::InvalidSmpPlaintextLength)?;

 
        let our_smp_nonce = crypto::generate_secure_random_bytes_whiten(consts::SMP_NONCE_SIZE)?;

        let contact_pk_fingerprint = crypto::hash_sha3_512(&Zeroizing::new(contact_signing_pk.to_vec()));

        let answer_secret = calculate_answer_secret(smp_answer, contact_smp_nonce.as_ref(), our_smp_nonce.as_slice())?;

        let our_proof = calculate_proof(&answer_secret, contact_smp_nonce.as_ref(), &our_smp_nonce, &contact_pk_fingerprint)?;

        let mut payload = Zeroizing::new(Vec::with_capacity(
                1 + 
                self.our_signing_pub_key.as_ref().unwrap().len() + 
                consts::SMP_NONCE_SIZE + 
                our_proof.len() + 
                self.smp_question.as_ref().unwrap().len()
            ));

        payload.push(consts::SMP_TYPE_INIT_SMP);
        payload.extend_from_slice(self.our_signing_pub_key.as_ref().unwrap());
        payload.extend_from_slice(&our_smp_nonce);
        payload.extend_from_slice(&our_proof);
        payload.extend_from_slice(self.smp_question.as_ref().unwrap().as_bytes());


        self.our_next_strand_key = Some(our_strand_key);
        self.our_next_strand_nonce = Some(Zeroizing::new(our_next_strand_nonce.to_vec()));


        self.contact_next_strand_key = Some(Zeroizing::new(contact_next_strand_key.to_vec()));
        self.contact_next_strand_nonce = Some(Zeroizing::new(contact_next_strand_nonce.to_vec()));


        self.our_smp_nonce = Some(Zeroizing::new(our_smp_nonce.to_vec()));
        self.contact_smp_nonce = Some(Zeroizing::new(contact_smp_nonce.to_vec()));

        self.contact_signing_pub_key = Some(Zeroizing::new(contact_signing_pk.to_vec()));

        let final_payload = self.prepare_payload(&payload)?;

        self.state = ContactState::SMPStep3;

        Ok(ContactOutput::Wire(vec![WireMessage(final_payload)]))
        
    }

    pub(super) fn do_smp_step_4_request_answer(&mut self, data: &[u8]) ->  Result<ContactOutput, Error> {
        let smp_plaintext = self.decrypt_incoming_data(data)?;

        // ensure first byte exists and is the expected type
        let type_byte = smp_plaintext.get(0).ok_or(Error::InvalidSmpPlaintextLength)?;
        if type_byte != &consts::SMP_TYPE_INIT_SMP {
            return Err(Error::InvalidSmpPlaintextLength);
        }

        // now shadow and skip the leading type byte
        let smp_plaintext = smp_plaintext.get(1..)
            .ok_or(Error::InvalidSmpPlaintextLength)?;


        let contact_signing_pk = smp_plaintext.get(..consts::ML_DSA_87_PK_SIZE)
            .ok_or(Error::InvalidSmpPlaintextLength)?;

        let contact_smp_nonce = smp_plaintext.get(consts::ML_DSA_87_PK_SIZE .. consts::ML_DSA_87_PK_SIZE + consts::SMP_NONCE_SIZE)
            .ok_or(Error::InvalidSmpPlaintextLength)?;

        let contact_smp_proof = smp_plaintext.get(consts::ML_DSA_87_PK_SIZE + consts::SMP_NONCE_SIZE .. consts::ML_DSA_87_PK_SIZE + consts::SMP_NONCE_SIZE + 64 )
            .ok_or(Error::InvalidSmpPlaintextLength)?;

        let smp_question = smp_plaintext.get(consts::ML_DSA_87_PK_SIZE + consts::SMP_NONCE_SIZE + 64 .. )
            .ok_or(Error::InvalidSmpPlaintextLength)?;


        if contact_smp_nonce == self.our_smp_nonce.as_ref().unwrap().as_slice() {
            return Err(Error::SMPnonceDuplicated)
        }


        self.contact_signing_pub_key = Some(Zeroizing::new(contact_signing_pk.to_vec()));

        self.contact_smp_nonce = Some(Zeroizing::new(contact_smp_nonce.to_vec()));

        self.contact_smp_proof = Some(Zeroizing::new(contact_smp_proof.to_vec()));


        let question = std::str::from_utf8(smp_question)
            .map_err(|_| Error::SmpQuestionInvalidUtf8)?
            .to_owned();

        self.smp_question = Some(question.clone());

        Ok(ContactOutput::Prompt(UserPrompt {
            question
        }))
    }

    pub fn provide_smp_answer(&mut self, answer_struct: UserAnswer) ->  Result<ContactOutput, Error> {
        let zeroized_str: &Zeroizing<String> = &answer_struct.0;
        let smp_answer = zeroized_str.deref().as_bytes();


        // Failsafe to protect retarded callers
        if self.state != ContactState::SMPStep2 {
            return Err(Error::InvalidState);
        }


        let our_signing_pk = self.our_signing_pub_key.as_ref().unwrap();
        let contact_signing_pk = self.contact_signing_pub_key.as_ref().unwrap();

        let contact_smp_tmp_pk = self.contact_smp_tmp_pub_key.as_ref().unwrap();

        let our_smp_nonce = self.our_smp_nonce.as_ref().unwrap();
        let contact_smp_nonce = self.contact_smp_nonce.as_ref().unwrap();


        let our_pk_fingerprint = crypto::hash_sha3_512(&Zeroizing::new(our_signing_pk.to_vec()));
        
        let answer_secret = calculate_answer_secret(smp_answer, our_smp_nonce.as_slice(), contact_smp_nonce.as_ref())?;

        let our_proof = calculate_proof(&answer_secret, &our_smp_nonce, contact_smp_nonce.as_ref(), &our_pk_fingerprint)?;

        let contact_proof = self.contact_smp_proof.as_ref().unwrap();

        // Verify Contact's version of our public-key fingerprint matches our actual public-key fingerprint.
        if !crypto::compare_secrets(&our_proof, &contact_proof)
        {
            return Err(Error::SMPInvalidContactProof);
        }

        // We now compute proof for our version of contact's public-key(s).
        let mut contact_fingerprint_plain = Zeroizing::new(Vec::with_capacity(consts::ML_DSA_87_PK_SIZE + consts::ML_KEM_1024_PK_SIZE));
        contact_fingerprint_plain.extend_from_slice(contact_signing_pk);
        contact_fingerprint_plain.extend_from_slice(contact_smp_tmp_pk);

        let contact_pks_fingerprint = crypto::hash_sha3_512(&contact_fingerprint_plain);
        
        let our_proof = calculate_proof(&answer_secret, contact_smp_nonce.as_ref(), &our_smp_nonce, &contact_pks_fingerprint)?;

        let mut payload = Zeroizing::new(Vec::with_capacity(1 + our_proof.len()));

        payload.push(consts::SMP_TYPE_INIT_SMP);
        payload.extend_from_slice(&our_proof);

        let final_payload = self.prepare_payload(&payload)?;

        self.state = ContactState::Verified;


        let (our_next_strand_key, _) = crypto::one_time_pad(&answer_secret[..32], self.our_next_strand_key.as_ref().unwrap())?;
        let (contact_next_strand_key, _) = crypto::one_time_pad(&answer_secret[..32], self.contact_next_strand_key.as_ref().unwrap())?;

        self.our_next_strand_key = Some(Zeroizing::new(our_next_strand_key));
        self.contact_next_strand_key = Some(Zeroizing::new(contact_next_strand_key));


        Ok(ContactOutput::Wire(vec![WireMessage(final_payload)]))
    }


    pub(super) fn do_smp_step_5(&mut self, data: &[u8]) ->  Result<ContactOutput, Error> {
        let smp_plaintext = self.decrypt_incoming_data(data)?;

        // ensure first byte exists and is the expected type
        let type_byte = smp_plaintext.get(0)
            .ok_or(Error::InvalidSmpPlaintextLength)?;

        if type_byte != &consts::SMP_TYPE_INIT_SMP {
            return Err(Error::InvalidSmpPlaintextLength);
        }

        // now shadow and skip the leading type byte
        let smp_plaintext = smp_plaintext.get(1..)
            .ok_or(Error::InvalidSmpPlaintextLength)?;

        let contact_proof = smp_plaintext.get(.. 64)
            .ok_or(Error::InvalidSmpPlaintextLength)?;
  
        let smp_answer = self.smp_answer.as_ref().unwrap();
        let smp_answer = smp_answer.deref().as_bytes();

        let our_smp_tmp_pk = self.our_smp_tmp_pub_key
            .as_ref().unwrap();
        
        let our_signing_pk = self.our_signing_pub_key
            .as_ref().unwrap();

        let our_smp_nonce = self.our_smp_nonce.as_ref().unwrap();
        let contact_smp_nonce = self.contact_smp_nonce.as_ref().unwrap();


        let mut our_fingerprint_plain = Zeroizing::new(Vec::with_capacity(consts::ML_DSA_87_PK_SIZE + consts::ML_KEM_1024_PK_SIZE));
        our_fingerprint_plain.extend_from_slice(our_signing_pk);
        our_fingerprint_plain.extend_from_slice(our_smp_tmp_pk);

        let our_pks_fingerprint = crypto::hash_sha3_512(&our_fingerprint_plain);

        let answer_secret = calculate_answer_secret(smp_answer, contact_smp_nonce.as_ref(), our_smp_nonce.as_slice())?;

        let our_proof = calculate_proof(&answer_secret, &our_smp_nonce, contact_smp_nonce.as_ref(), &our_pks_fingerprint)?;

        if !crypto::compare_secrets(&our_proof, contact_proof)
        {
            return Err(Error::SMPInvalidContactProof);
        }

        self.state = ContactState::Verified;

        let (our_next_strand_key, _) = crypto::one_time_pad(&answer_secret[..32], self.our_next_strand_key.as_ref().unwrap())?;
        let (contact_next_strand_key, _) = crypto::one_time_pad(&answer_secret[..32], self.contact_next_strand_key.as_ref().unwrap())?;

        self.our_next_strand_key = Some(Zeroizing::new(our_next_strand_key));
        self.contact_next_strand_key = Some(Zeroizing::new(contact_next_strand_key));

        self.do_new_ephemeral_keys()
    }


    pub(super) fn do_smp_failure(&mut self) ->  Result<ContactOutput, Error> {
        self.state = ContactState::Uninitialized;

        let our_next_strand_key = crypto::generate_secure_random_bytes_whiten(32)?;
        let our_next_strand_nonce = crypto::generate_secure_random_bytes_whiten(consts::CHACHA20POLY1305_NONCE_SIZE)?;
        
        let our_strand_key = self.our_next_strand_key
            .as_ref()
            .unwrap_or(&our_next_strand_key);

        let our_strand_nonce = self.our_next_strand_nonce
            .as_ref()
            .unwrap_or(&our_next_strand_nonce);

 
        let mut out = Zeroizing::new(Vec::with_capacity(1 + 32 + consts::CHACHA20POLY1305_NONCE_SIZE + 7));
        out.extend_from_slice(&our_next_strand_key);
        out.extend_from_slice(&our_next_strand_nonce);
        out.push(consts::SMP_TYPE_INIT_SMP);
        out.extend_from_slice(b"failure");

        
        let (ciphertext_blob, _) = crypto::encrypt_chacha20poly1305(&our_strand_key, &out, Some(our_strand_nonce.as_slice()), consts::CHACHA20POLY1305_MAX_RANDOM_PAD)?;

        Ok(ContactOutput::Wire(vec![WireMessage(Zeroizing::new(ciphertext_blob))]))
    }
}
