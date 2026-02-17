use zeroize::{Zeroize, Zeroizing};
use std::ops::Deref;

use crate::consts;
use crate::crypto;
use crate::smp;
use crate::wire::{ContactOutput, WireMessage, UserPrompt, UserAnswer};
use crate::error::Error;

// Contact states for one contact
#[derive(Clone, Copy, Debug, PartialEq)]
enum ContactState {
    Uninitialized,
    SMPInit,
    SMPStep2,
    SMPStep3,
    Verified
}

// Public contact struct (one per contact)
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct Contact {
    #[zeroize(skip)]
    state: ContactState,

    // stored key material

    our_signing_pub_key: Option<Zeroizing<Vec<u8>>>,
    our_signing_secret_key: Option<Zeroizing<Vec<u8>>>,
    contact_signing_pub_key: Option<Zeroizing<Vec<u8>>>,
    

    our_ml_kem_pub_key: Option<Zeroizing<Vec<u8>>>,
    our_ml_kem_secret_key: Option<Zeroizing<Vec<u8>>>,
    contact_ml_kem_pub_key: Option<Zeroizing<Vec<u8>>>,

    our_mceliece_pub_key: Option<Zeroizing<Vec<u8>>>,
    our_mceliece_secret_key: Option<Zeroizing<Vec<u8>>>,
    contact_mceliece_pub_key: Option<Zeroizing<Vec<u8>>>,

    our_staged_ml_kem_pub_key: Option<Zeroizing<Vec<u8>>>,
    our_staged_ml_kem_secret_key: Option<Zeroizing<Vec<u8>>>,

    our_staged_mceliece_pub_key: Option<Zeroizing<Vec<u8>>>,
    our_staged_mceliece_secret_key: Option<Zeroizing<Vec<u8>>>,

    our_smp_tmp_pub_key: Option<Zeroizing<Vec<u8>>>,
    our_smp_tmp_secret_key: Option<Zeroizing<Vec<u8>>>,
    contact_smp_tmp_pub_key: Option<Zeroizing<Vec<u8>>>,

    our_next_strand_key  : Option<Zeroizing<Vec<u8>>>,
    our_next_strand_nonce: Option<Zeroizing<Vec<u8>>>,

    contact_next_strand_key  : Option<Zeroizing<Vec<u8>>>,
    contact_next_strand_nonce: Option<Zeroizing<Vec<u8>>>,

    our_smp_nonce: Option<Zeroizing<Vec<u8>>>,
    contact_smp_nonce: Option<Zeroizing<Vec<u8>>>,
    contact_smp_proof: Option<Zeroizing<Vec<u8>>>,

    smp_answer: Option<Zeroizing<String>>,
    smp_question: Option<String>,


    our_hash_chain: Option<Zeroizing<Vec<u8>>>,
    contact_hash_chain: Option<Zeroizing<Vec<u8>>>,

    #[zeroize(skip)]
    backup: Option<Box<Contact>>
}

// Manual Clone implementation
impl Clone for Contact {
    fn clone(&self) -> Self {
        Contact {
            state: self.state.clone(), 
            our_signing_pub_key: self.our_signing_pub_key.clone(),
            our_signing_secret_key: self.our_signing_secret_key.clone(),
            contact_signing_pub_key: self.contact_signing_pub_key.clone(),

            our_ml_kem_pub_key: self.our_ml_kem_pub_key.clone(),
            our_ml_kem_secret_key: self.our_ml_kem_secret_key.clone(),
            contact_ml_kem_pub_key: self.contact_ml_kem_pub_key.clone(),

            our_mceliece_pub_key: self.our_mceliece_pub_key.clone(),
            our_mceliece_secret_key: self.our_mceliece_pub_key.clone(),
            contact_mceliece_pub_key: self.contact_mceliece_pub_key.clone(),


            our_staged_ml_kem_pub_key: self.our_staged_ml_kem_pub_key.clone(),
            our_staged_ml_kem_secret_key: self.our_staged_ml_kem_secret_key.clone(),

            our_staged_mceliece_pub_key: self.our_staged_mceliece_pub_key.clone(),
            our_staged_mceliece_secret_key: self.our_staged_mceliece_secret_key.clone(),


            our_smp_tmp_pub_key: self.our_smp_tmp_pub_key.clone(),
            our_smp_tmp_secret_key: self.our_smp_tmp_secret_key.clone(),
            contact_smp_tmp_pub_key: self.contact_smp_tmp_pub_key.clone(),

            our_next_strand_key: self.our_next_strand_key.clone(),
            our_next_strand_nonce: self.our_next_strand_nonce.clone(),

            contact_next_strand_key: self.contact_next_strand_key.clone(),
            contact_next_strand_nonce: self.contact_next_strand_nonce.clone(),

            our_smp_nonce: self.our_smp_nonce.clone(),
            contact_smp_nonce: self.contact_smp_nonce.clone(),
            contact_smp_proof: self.contact_smp_proof.clone(),

            smp_answer: self.smp_answer.clone(),
            smp_question: self.smp_question.clone(),

            our_hash_chain: self.our_hash_chain.clone(),
            contact_hash_chain: self.contact_hash_chain.clone(),

            backup: None, // Always reset backup in clones
        }
    }
}


impl Contact {
    /// Create new contact
    pub fn new() -> Result<Self, Error> {
        let mut contact = Contact {
            state: ContactState::Uninitialized,
            our_smp_tmp_pub_key: None,
            our_smp_tmp_secret_key: None,
            contact_smp_tmp_pub_key: None,

            our_ml_kem_pub_key: None, 
            our_ml_kem_secret_key: None, 
            contact_ml_kem_pub_key: None,

            our_mceliece_pub_key: None,
            our_mceliece_secret_key: None, 
            contact_mceliece_pub_key: None,


            our_staged_ml_kem_pub_key: None, 
            our_staged_ml_kem_secret_key: None, 
            
            our_staged_mceliece_pub_key: None, 
            our_staged_mceliece_secret_key: None, 
           

            our_signing_pub_key: None,
            our_signing_secret_key: None,

            contact_signing_pub_key: None,

            our_next_strand_key: None,
            our_next_strand_nonce: None,
            contact_next_strand_key: None,
            contact_next_strand_nonce: None,
            our_smp_nonce: None,
            contact_smp_nonce: None,
            contact_smp_proof: None,

            smp_answer: None,
            smp_question: None,

            our_hash_chain: None, 
            contact_hash_chain: None,

            backup: None,
        };

        contact.init_lt_sign_keypair()?;
        Ok(contact)
    }


    pub fn save_backup(&mut self) {
        // Store a clone of self in backup
        self.backup = Some(Box::new(self.clone()));
    }

    pub fn restore_backup(&mut self) {
        // TODO: Prevent restore if backup OTPs and current OTPs differ.
        if let Some(b) = self.backup.take() {
            // Overwrite self fields from backup
            *self = *b;
        }
    }


    /// Process an incoming blob, returning optional outgoing blob
    pub fn process(&mut self, data: &[u8]) -> Result<ContactOutput, Error> {
        self.save_backup();
        let result = match self.state {
            ContactState::Uninitialized => self.do_smp_step_2(data),
            ContactState::SMPInit       => self.do_smp_step_3(data),
            ContactState::SMPStep2      => self.do_smp_step_4_request_answer(data),

            ContactState::SMPStep3      => self.do_smp_step_5(data),
            ContactState::Verified      => self.process_verified(data)
        };
        
        if self.state != ContactState::Verified {
            // If we are not verified, we must still be in SMP.
            if result.is_ok() {
                return result;
            } else {
                return self.do_smp_failure();
            }
        }

        result
    }
    
    pub fn process_verified(&mut self, data: &[u8]) -> Result<ContactOutput, Error> {
        let data_plaintext = self.decrypt_incoming_data(data)?;

        let type_byte = data_plaintext.get(0)
            .ok_or(Error::InvalidDataPlaintextLength)?;

        if type_byte == &consts::PFS_TYPE_PFS_NEW {
            let pfs_plaintext = data_plaintext.get(1..).ok_or(Error::InvalidPfsPlaintextLength).unwrap();
            return self.do_pfs_new(pfs_plaintext);
        
        } else if type_byte == &consts::PFS_TYPE_PFS_ACK {
            let pfs_plaintext = data_plaintext.get(1..).ok_or(Error::InvalidPfsPlaintextLength).unwrap();
            return self.do_pfs_ack(pfs_plaintext);
        }



        Err(Error::InvalidDataType)
    }

    pub fn init_smp(&mut self, question: String, answer: String) -> Result<ContactOutput, Error> {
        // Normalize and store SMP answer
        let normalized = smp::normalize_smp_answer(Zeroizing::new(answer))?;
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
     
    fn do_smp_step_2(&mut self, data: &[u8]) -> Result<ContactOutput, Error> {
        if data.len() != 1 + consts::ML_KEM_1024_PK_SIZE {
            return Err(Error::InvalidKemPublicKeyLength);
        }

        let signing_pk = self.our_signing_pub_key.as_ref().expect("our_signing_pub_key must be initialized");
        

        let (key_ciphertexts, shared_secrets) = crypto::generate_shared_secrets(&data[1..], oqs::kem::Algorithm::MlKem1024, 64)?;

        let our_strand_key = Zeroizing::new(shared_secrets[0..32].to_vec());
        let contact_next_strand_key = Zeroizing::new(shared_secrets[32..64].to_vec());

        let our_next_strand_key = crypto::generate_secure_random_bytes_whiten(32)?;

        let our_next_strand_nonce = crypto::generate_secure_random_bytes_whiten(consts::STRAND_NONCE_SIZE)?;

        let contact_next_strand_nonce = crypto::generate_secure_random_bytes_whiten(consts::STRAND_NONCE_SIZE)?;

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

    fn do_smp_step_3(&mut self, data: &[u8]) ->  Result<ContactOutput, Error> {
        let key_ciphertexts = &data.get(1 .. (consts::ML_KEM_1024_CT_SIZE * 2) + 1)
            .ok_or(Error::InvalidDataLength)?;

        let sk = self.our_smp_tmp_secret_key.as_ref().expect("our_smp_tmp_secret_key must be initialized before SMP step");

        let smp_answer = self.smp_answer.as_ref().unwrap().as_bytes();

        let shared_secrets = crypto::decrypt_shared_secrets(key_ciphertexts, sk, oqs::kem::Algorithm::MlKem1024, 64)?;

        let contact_strand_key = Zeroizing::new(shared_secrets[0..32].to_vec());
        let our_strand_key = Zeroizing::new(shared_secrets[32..64].to_vec());


        let smp_ciphertext = data.get(key_ciphertexts.len() + 1 + consts::CHACHA20POLY1305_NONCE_LEN ..)
            .ok_or(Error::InvalidDataLength)?;

        let chacha_nonce = data.get(key_ciphertexts.len() + 1 .. key_ciphertexts.len() + 1 + consts::CHACHA20POLY1305_NONCE_LEN)
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

        let contact_next_strand_nonce = smp_plaintext.get(consts::ML_DSA_87_PK_SIZE + consts::SMP_NONCE_SIZE .. consts::ML_DSA_87_PK_SIZE + consts::SMP_NONCE_SIZE + consts::CHACHA20POLY1305_NONCE_LEN)
            .ok_or(Error::InvalidSmpPlaintextLength)?;

        let our_next_strand_nonce = smp_plaintext.get(consts::ML_DSA_87_PK_SIZE + consts::SMP_NONCE_SIZE + consts::CHACHA20POLY1305_NONCE_LEN ..)
            .ok_or(Error::InvalidSmpPlaintextLength)?;

 
        let our_smp_nonce = crypto::generate_secure_random_bytes_whiten(consts::SMP_NONCE_SIZE)?;

        let contact_pk_fingerprint = crypto::hash_sha3_512(&Zeroizing::new(contact_signing_pk.to_vec()));

        let answer_secret = smp::calculate_answer_secret(smp_answer, contact_smp_nonce.as_ref(), our_smp_nonce.as_slice())?;

        let our_proof = smp::calculate_proof(&answer_secret, contact_smp_nonce.as_ref(), &our_smp_nonce, &contact_pk_fingerprint)?;

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

    fn do_smp_step_4_request_answer(&mut self, data: &[u8]) ->  Result<ContactOutput, Error> {
        let smp_plaintext = self.decrypt_incoming_data(data)?;

        // ensure first byte exists and is the expected type
        let type_byte = smp_plaintext.get(0).ok_or(Error::InvalidSmpPlaintextLength)?;
        if type_byte != &consts::SMP_TYPE_INIT_SMP {
            return Err(Error::InvalidSmpPlaintextLength);
        }

        // now shadow and skip the leading type byte
        let smp_plaintext = smp_plaintext.get(1..).ok_or(Error::InvalidSmpPlaintextLength).unwrap();


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


        let our_signing_pk = self.our_signing_pub_key.as_ref().unwrap();
        let contact_signing_pk = self.contact_signing_pub_key.as_ref().unwrap();

        let contact_smp_tmp_pk = self.contact_smp_tmp_pub_key.as_ref().unwrap();

        let our_smp_nonce = self.our_smp_nonce.as_ref().unwrap();
        let contact_smp_nonce = self.contact_smp_nonce.as_ref().unwrap();


        let our_pk_fingerprint = crypto::hash_sha3_512(&Zeroizing::new(our_signing_pk.to_vec()));
        
        let answer_secret = smp::calculate_answer_secret(smp_answer, our_smp_nonce.as_slice(), contact_smp_nonce.as_ref())?;

        let our_proof = smp::calculate_proof(&answer_secret, &our_smp_nonce, contact_smp_nonce.as_ref(), &our_pk_fingerprint)?;

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
        
        let our_proof = smp::calculate_proof(&answer_secret, contact_smp_nonce.as_ref(), &our_smp_nonce, &contact_pks_fingerprint)?;

        let mut payload = Zeroizing::new(Vec::with_capacity(1 + our_proof.len()));

        payload.push(consts::SMP_TYPE_INIT_SMP);
        payload.extend_from_slice(&our_proof);

        let final_payload = self.prepare_payload(&payload)?;

        self.state = ContactState::Verified;

        Ok(ContactOutput::Wire(vec![WireMessage(final_payload)]))
    }


    fn do_smp_step_5(&mut self, data: &[u8]) ->  Result<ContactOutput, Error> {
        let smp_plaintext = self.decrypt_incoming_data(data)?;

        // ensure first byte exists and is the expected type
        let type_byte = smp_plaintext.get(0)
            .ok_or(Error::InvalidSmpPlaintextLength)?;

        if type_byte != &consts::SMP_TYPE_INIT_SMP {
            return Err(Error::InvalidSmpPlaintextLength);
        }

        // now shadow and skip the leading type byte
        let smp_plaintext = smp_plaintext.get(1..)
            .ok_or(Error::InvalidSmpPlaintextLength).unwrap();

        let contact_proof = smp_plaintext.get(.. 64)
            .ok_or(Error::InvalidSmpPlaintextLength).unwrap();
  
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

        let answer_secret = smp::calculate_answer_secret(smp_answer, contact_smp_nonce.as_ref(), our_smp_nonce.as_slice())?;

        let our_proof = smp::calculate_proof(&answer_secret, &our_smp_nonce, contact_smp_nonce.as_ref(), &our_pks_fingerprint)?;

        if !crypto::compare_secrets(&our_proof, contact_proof)
        {
            return Err(Error::SMPInvalidContactProof);
        }

        self.state = ContactState::Verified;

        self.do_new_ephemeral_keys()
    }


    fn do_smp_failure(&mut self) ->  Result<ContactOutput, Error> {
        self.state = ContactState::Uninitialized;

        let our_next_strand_key = crypto::generate_secure_random_bytes_whiten(32)?;
        let our_next_strand_nonce = crypto::generate_secure_random_bytes_whiten(consts::STRAND_NONCE_SIZE)?;
        
        let our_strand_key = self.our_next_strand_key
            .as_ref()
            .unwrap_or(&our_next_strand_key);

        let our_strand_nonce = self.our_next_strand_nonce
            .as_ref()
            .unwrap_or(&our_next_strand_nonce);

 
        let mut out = Zeroizing::new(Vec::with_capacity(1 + 32 + consts::STRAND_NONCE_SIZE + 7));
        out.extend_from_slice(&our_next_strand_key);
        out.extend_from_slice(&our_next_strand_nonce);
        out.push(consts::SMP_TYPE_INIT_SMP);
        out.extend_from_slice(b"failure");


        Ok(ContactOutput::Wire(vec![WireMessage(out)]))
    }

  
    fn do_pfs_new(&mut self, pfs_plaintext: &[u8]) ->  Result<ContactOutput, Error> {
        if pfs_plaintext.len() != 64 + consts::ML_KEM_1024_PK_SIZE + consts::CLASSIC_MCELIECE_8_PK_SIZE {
            return Err(Error::InvalidPfsPlaintextLength);
        }


        let contact_signing_pk = self.contact_signing_pub_key
            .as_ref().unwrap();

        let contact_hash_chain = self.contact_hash_chain
            .as_ref();


        let signature = pfs_plaintext.get(.. consts::ML_DSA_87_SIGN_SIZE)
            .ok_or(Error::InvalidPfsPlaintextLength).unwrap();

        let signature_data = pfs_plaintext.get(consts::ML_DSA_87_SIGN_SIZE + 64 ..)
            .ok_or(Error::InvalidPfsPlaintextLength).unwrap();

        // Verify the signature of the public-keys and the hash-chain.
        crypto::verify_signature(oqs::sig::Algorithm::MlDsa87, contact_signing_pk, signature_data, signature)?;

        let contact_next_hash_chain = pfs_plaintext.get(consts::ML_DSA_87_SIGN_SIZE .. consts::ML_DSA_87_SIGN_SIZE + 64)
            .ok_or(Error::InvalidPfsPlaintextLength).unwrap();


        let contact_ml_kem_pk = pfs_plaintext.get(64 + consts::ML_DSA_87_SIGN_SIZE .. 64 + consts::ML_DSA_87_SIGN_SIZE + consts::ML_KEM_1024_PK_SIZE)
            .ok_or(Error::InvalidPfsPlaintextLength).unwrap();

        let contact_mceliece_pk = pfs_plaintext.get(64 + consts::ML_DSA_87_SIGN_SIZE + consts::ML_KEM_1024_PK_SIZE + consts::CLASSIC_MCELIECE_8_PK_SIZE ..)
            .ok_or(Error::InvalidPfsPlaintextLength).unwrap();


        if contact_hash_chain.is_some() {
            let computed_hash_chain = crypto::hash_sha3_512(&contact_hash_chain.unwrap());
            if computed_hash_chain.as_slice() != contact_next_hash_chain {
                return Err(Error::InvalidHashChain);
            }

        } else {
            // If we do not have a hashchain for the contact, we don't need to compute the chain, just save.
            self.contact_hash_chain = Some(Zeroizing::new(contact_next_hash_chain.to_vec()));
        }

        self.contact_ml_kem_pub_key = Some(Zeroizing::new(contact_ml_kem_pk.to_vec()));
        self.contact_mceliece_pub_key = Some(Zeroizing::new(contact_mceliece_pk.to_vec()));

        let mut payload = Zeroizing::new(Vec::with_capacity(1));
        payload.push(consts::PFS_TYPE_PFS_ACK);

        let final_payload = self.prepare_payload(&payload)?;


        if (!self.our_ml_kem_secret_key.is_some() || !self.our_mceliece_secret_key.is_some()) && (!self.our_staged_ml_kem_secret_key.is_some() || !self.our_staged_mceliece_secret_key.is_some()) {
            let ephemeral = self.do_new_ephemeral_keys()?; // ephemeral: ContactOutput

            let mut messages = vec![WireMessage(final_payload)];

            if let ContactOutput::Wire(mut ws) = ephemeral {
                messages.append(&mut ws); 
            } else {
                return Err(Error::InvalidState);
            }
            return Ok(ContactOutput::Wire(messages));

        }

        Ok(ContactOutput::Wire(vec![WireMessage(final_payload)]))
    }

    fn do_pfs_ack(&mut self, pfs_plaintext: &[u8]) ->  Result<ContactOutput, Error> {
        self.our_ml_kem_secret_key = self.our_staged_ml_kem_secret_key.take();
        self.our_ml_kem_pub_key = self.our_staged_ml_kem_pub_key.take();

        self.our_mceliece_secret_key = self.our_staged_mceliece_secret_key.take();
        self.our_mceliece_pub_key = self.our_staged_mceliece_pub_key.take();

        Ok(ContactOutput::None)
    }


    fn do_new_ephemeral_keys(&mut self) ->  Result<ContactOutput, Error> {
        let ml_dsa_sk = self.our_signing_secret_key
            .as_ref()
            .ok_or(Error::InvalidState)?;

        let (ml_kem_pk, ml_kem_sk) = crypto::generate_kem_keypair(oqs::kem::Algorithm::MlKem1024)
            .map_err(|_| Error::CryptoFail)?;
 
        let (mceliece_pk, mceliece_sk) = crypto::generate_kem_keypair(oqs::kem::Algorithm::ClassicMcEliece8192128)
            .map_err(|_| Error::CryptoFail)?;

        let our_hash_chain: Zeroizing<Vec<u8>> = match self.our_hash_chain.take() {
            Some(v) => v,
            None => crypto::generate_secure_random_bytes_whiten(64)?,
        };

        let our_next_hash_chain = crypto::hash_sha3_512(&our_hash_chain);

        let mut pks_hash_chain = Zeroizing::new(Vec::with_capacity(64 + consts::ML_KEM_1024_PK_SIZE + consts::CLASSIC_MCELIECE_8_PK_SIZE ));
        pks_hash_chain.extend_from_slice(our_next_hash_chain.as_slice());
        pks_hash_chain.extend_from_slice(ml_kem_pk.as_slice());
        pks_hash_chain.extend_from_slice(mceliece_pk.as_slice());

        let signature_pks_hash_chain = crypto::generate_signature(oqs::sig::Algorithm::MlDsa87, ml_dsa_sk, &pks_hash_chain)?;

        let mut payload = Zeroizing::new(Vec::with_capacity(
                1 + 
                signature_pks_hash_chain.len() +
                pks_hash_chain.len()

            ));

        payload.push(consts::PFS_TYPE_PFS_NEW);
        payload.extend_from_slice(&signature_pks_hash_chain);
        payload.extend_from_slice(&pks_hash_chain);


        let final_payload = self.prepare_payload(&payload)?;

        self.our_hash_chain = Some(our_next_hash_chain);

        self.our_ml_kem_pub_key = Some(ml_kem_pk);
        self.our_ml_kem_secret_key = Some(ml_kem_sk);

        self.our_mceliece_pub_key = Some(mceliece_pk);
        self.our_mceliece_secret_key = Some(mceliece_sk);

        Ok(ContactOutput::Wire(vec![WireMessage(final_payload)]))
    
    }


    pub fn send_message(&mut self, _plaintext: &[u8]) -> Result<Vec<u8>, Error> { Ok(vec![]) }

    fn decrypt_incoming_data(&mut self, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        let contact_strand_key = self.contact_next_strand_key.as_ref().unwrap();
        let contact_strand_nonce = self.contact_next_strand_nonce.as_ref().unwrap();

        let plaintext = crypto::decrypt_chacha20poly1305(contact_strand_key, contact_strand_nonce, blob)?;

        let next_key = plaintext
            .get(..32)
            .ok_or(Error::InvalidDataLength)?;

        let next_nonce = plaintext
            .get(32..32 + consts::CHACHA20POLY1305_NONCE_LEN)
            .ok_or(Error::InvalidDataLength)?;

        self.contact_next_strand_key = Some(Zeroizing::new(next_key.to_vec()));

        self.contact_next_strand_nonce = Some(Zeroizing::new(next_nonce.to_vec()));

        let message = plaintext
            .get(32 + consts::CHACHA20POLY1305_NONCE_LEN..)
            .ok_or(Error::InvalidDataLength)?;

        Ok(Zeroizing::new(message.to_vec()))
    }

    /// Prepapre the payload by wrap encrypting it and also continues the ratchet.
    fn prepare_payload(&mut self, payload: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        let our_next_strand_key = crypto::generate_secure_random_bytes_whiten(32)?;

        let our_next_strand_nonce = crypto::generate_secure_random_bytes_whiten(consts::STRAND_NONCE_SIZE)?;

        let our_strand_key = self.our_next_strand_key.as_ref().unwrap();
        let our_strand_nonce = self.our_next_strand_nonce.as_ref().unwrap();

       
        let mut prepared_payload = Zeroizing::new(Vec::with_capacity(32 + consts::STRAND_NONCE_SIZE + payload.len()));
        prepared_payload.extend_from_slice(&our_next_strand_key);
        prepared_payload.extend_from_slice(&our_next_strand_nonce);
        prepared_payload.extend_from_slice(payload);

        let (ciphertext_blob, _) = crypto::encrypt_chacha20poly1305(&our_strand_key, &prepared_payload, Some(our_strand_nonce.as_slice()), consts::CHACHA20POLY1305_MAX_RANDOM_PAD)?;

        self.our_next_strand_key = Some(our_next_strand_key);
        self.our_next_strand_nonce = Some(our_next_strand_nonce);

        // Ok(ContactOutput::Wire(WireMessage(Zeroizing::new(ciphertext_blob))))
        Ok(Zeroizing::new(ciphertext_blob))

    }

    fn init_lt_sign_keypair(&mut self) -> Result<(), Error> {
        let (pk, sk) = crypto::generate_signing_keypair(oqs::sig::Algorithm::MlDsa87)
            .map_err(|_| Error::CryptoFail)?;


        self.our_signing_pub_key = Some(pk);
        self.our_signing_secret_key = Some(sk);

        Ok(())
    }


    fn init_tmp_kem_keypair(&mut self) -> Result<(), Error> {
        let (pk, sk) = crypto::generate_kem_keypair(oqs::kem::Algorithm::MlKem1024)
            .map_err(|_| Error::CryptoFail)?;


        self.our_smp_tmp_pub_key = Some(pk);
        self.our_smp_tmp_secret_key = Some(sk);

        Ok(())
    }

}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_smp_session() {

        // Alice initiates a new SMP session
        let alice_question = String::from("This is a question");
        let alice_answer = String::from("This is an answer");

        let mut alice = Contact::new().expect("Failed to create new contact instance");

        let result = alice.init_smp(
            alice_question.clone(),
            alice_answer.clone()
        );

        println!("Alice result: {:?}", result);
        assert!(result.is_ok());

        let result = match result.unwrap() {
            ContactOutput::Wire(w) => w,
            _ => panic!("Expected Wire output"),
        };

        assert_eq!(result.len(), 1, "Expected exactly one wire message");
        assert_eq!(result[0].len(), 1 + consts::ML_KEM_1024_PK_SIZE, "SMP init output length mismatch");
        assert_eq!(result[0][0], consts::SMP_TYPE_INIT_SMP, "SMP type byte mismatch");


        // Bob processes Alice's result.
        let mut bob = Contact::new().expect("Failed to create new contact instance");

        let result = bob.process(result[0].as_ref());
        println!("Bob result: {:?}", result);
        assert!(result.is_ok());

        let result = match result.unwrap() {
            ContactOutput::Wire(w) => w,
            _ => panic!("Expected Wire output"),
        };

        assert_eq!(result.len(), 1, "Expected exactly one wire message");

        assert!(
            result[0].len() >= 
            1 + (consts::ML_KEM_1024_CT_SIZE * 2) + 16 + (consts::CHACHA20POLY1305_NONCE_LEN * 3) + 32 + consts::SMP_NONCE_SIZE + consts::ML_DSA_87_PK_SIZE, 
            "SMP step 2 output length mismatch"
        );
        assert_eq!(result[0][0], consts::SMP_TYPE_INIT_SMP, "SMP type byte mismatch");



        // Alice processes Bob's result.
        let result = alice.process(result[0].as_ref());
        println!("Alice result: {:?}", result);
        assert!(result.is_ok());

        let result = match result.unwrap() {
            ContactOutput::Wire(w) => w,
            _ => panic!("Expected Wire output"),
        };

        assert_eq!(result.len(), 1, "Expected exactly one wire message");


        // Bob processes Alice's result.
        let result = bob.process(result[0].as_ref());
        println!("Bob result: {:?}", result);
        assert!(result.is_ok());

        let result = match result.unwrap() {
            ContactOutput::Prompt(p) => p,
            _ => panic!("Expected Prompt output"),
        };


        let bob_question = result.question;

        assert_eq!(bob_question, alice_question, "Bob question and Alice question do not match");

        let bob_answer = String::from("This is an answer");

        let bob_user_answer = UserAnswer::new(bob_answer).expect("Failed to create new UserAnswer instance");
        
        let result = bob.provide_smp_answer(bob_user_answer);
        println!("Bob provide_smp_answer: result: {:?}", result);
        assert!(result.is_ok());

        let result = match result.unwrap() {
            ContactOutput::Wire(w) => w,
            _ => panic!("Expected Wire output"),
        };


        assert_eq!(result.len(), 1, "Expected exactly one wire message");


        let result = alice.process(result[0].as_ref());
        println!("Alice result: {:?}", result);
        assert!(result.is_ok());

        let result = match result.unwrap() {
            ContactOutput::Wire(w) => w,
            _ => panic!("Expected Wire output"),
        };

        assert_eq!(result.len(), 1, "Expected exactly one wire message");

    }
}
