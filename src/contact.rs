use zeroize::{Zeroize, Zeroizing};
use std::ops::Deref;

use crate::consts;
use crate::crypto;
use crate::wire::{ContactOutput, WireMessage, UserPrompt, UserAnswer, NewMessage};
use crate::error::Error;

mod smp;
mod pfs;
mod msgs;
mod ratchet;
pub(crate) use smp::normalize_smp_answer;


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

    message_locked: bool,

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

    our_pads: Option<Zeroizing<Vec<u8>>>,
    contact_pads: Option<Zeroizing<Vec<u8>>>,

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

            message_locked: self.message_locked.clone(),

            our_signing_pub_key: self.our_signing_pub_key.clone(),
            our_signing_secret_key: self.our_signing_secret_key.clone(),
            contact_signing_pub_key: self.contact_signing_pub_key.clone(),

            our_ml_kem_pub_key: self.our_ml_kem_pub_key.clone(),
            our_ml_kem_secret_key: self.our_ml_kem_secret_key.clone(),
            contact_ml_kem_pub_key: self.contact_ml_kem_pub_key.clone(),

            our_mceliece_pub_key: self.our_mceliece_pub_key.clone(),
            our_mceliece_secret_key: self.our_mceliece_secret_key.clone(),
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

            our_pads: self.our_pads.clone(),
            contact_pads: self.contact_pads.clone(),

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

            message_locked: false,

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

            our_pads: None,
            contact_pads: None,

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
            // If we are not verified, we must still be in SMP, therefore if we encounter any
            // error, we send failure.
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
            let pfs_plaintext = data_plaintext.get(1..)
                .ok_or(Error::InvalidPfsPlaintextLength)?;
            return self.do_pfs_new(pfs_plaintext);
        
        } else if type_byte == &consts::PFS_TYPE_PFS_ACK {
            let pfs_plaintext = data_plaintext.get(1..)
                .ok_or(Error::InvalidPfsPlaintextLength)?;
            return self.do_pfs_ack(pfs_plaintext);
        
        } else if type_byte == &consts::MSG_TYPE_MSG_BATCH {
            let msgs_plaintext = data_plaintext.get(1..)
                .ok_or(Error::InvalidMsgsPlaintextLength)?;

            return self.do_process_otp_batch(msgs_plaintext);

        } else if type_byte == &consts::MSG_TYPE_MSG_NEW {
            let msgs_plaintext = data_plaintext.get(1..)
                .ok_or(Error::InvalidMsgsPlaintextLength)?;

            return self.do_process_new_msg(msgs_plaintext);
        }

        Err(Error::InvalidDataType)
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
    fn test_full_two_sessions() {

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
            1 + (consts::ML_KEM_1024_CT_SIZE * 2) + 16 + (consts::CHACHA20POLY1305_NONCE_SIZE * 3) + 32 + consts::SMP_NONCE_SIZE + consts::ML_DSA_87_PK_SIZE, 
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

        // PFS

        let result = bob.process(result[0].as_ref());
        println!("Bob result: {:?}", result);
        assert!(result.is_ok());

        let result = match result.unwrap() {
            ContactOutput::Wire(w) => w,
            _ => panic!("Expected Wire output"),
        };

        assert_eq!(result.len(), 2, "Expected exactly 2 wire messages");


        let result_1 = alice.process(result[0].as_ref());
        println!("Alice result 1: {:?}", result_1);
        assert!(result_1.is_ok());

        match result_1.unwrap() {
            ContactOutput::None => {},
            _ => panic!("Expected None output"),
        };
        

        let result_2 = alice.process(result[1].as_ref());
        println!("Alice result 2: {:?}", result_2);
        assert!(result_2.is_ok());

        let result_2 = match result_2.unwrap() {
            ContactOutput::Wire(w) => w,
            _ => panic!("Expected Wire output"),
        };


        assert_eq!(result_2.len(), 1, "Expected exactly one wire message");

        let result = bob.process(result_2[0].as_ref());
        println!("Bob result: {:?}", result);
        assert!(result.is_ok());

        let result = match result.unwrap() {
            ContactOutput::None => {},
            _ => panic!("Expected None output"),
        };


        // MSGS:
        
        let alice_message_1 = Zeroizing::new(String::from("Hello, World!"));

        let result = alice.send_message(&alice_message_1);
        println!("Alice result: {:?}", result);
        assert!(result.is_ok());

        let result = match result.unwrap() {
            ContactOutput::Wire(w) => w,
            _ => panic!("Expected Wire output"),
        };

  
        // 2 because we never sent pads to Bob yet.
        assert_eq!(result.len(), 2, "Expected exactly 2 wire message");


        let r = alice.i_confirm_message_has_been_sent();
        assert!(r.is_ok());


        let result_1 = bob.process(result[0].as_ref());
        println!("Bob result 1: {:?}", result_1);
        assert!(result_1.is_ok());

        match result_1.unwrap() {
            ContactOutput::Wire(w) => w,
            _ => panic!("Expected Wire output"),
        };
        

        let result_2 = bob.process(result[1].as_ref());
        println!("Bob result 2: {:?}", result_2);
        assert!(result_2.is_ok());

        let result_2 = match result_2.unwrap() {
            ContactOutput::Message(m) => m,
            _ => panic!("Expected Message output"),
        };

        assert_eq!(alice_message_1, result_2.message, "Decrypted message not equal to original message");


        let alice_message_2 = Zeroizing::new(String::from("Hi Bob!!"));

        let result = alice.send_message(&alice_message_2);
        println!("Alice result: {:?}", result);
        assert!(result.is_ok());

        let result = match result.unwrap() {
            ContactOutput::Wire(w) => w,
            _ => panic!("Expected Wire output"),
        };

  
        // 1 because we should've at this point sent Bob enough pads
        assert_eq!(result.len(), 1, "Expected exactly one wire message");

        let r = alice.i_confirm_message_has_been_sent();
        assert!(r.is_ok());


        let result = bob.process(result[0].as_ref());
        println!("Bob result: {:?}", result);
        assert!(result.is_ok());

        let result = match result.unwrap() {
            ContactOutput::Message(m) => m,
            _ => panic!("Expected Message output"),
        };

        assert_eq!(alice_message_2, result.message, "Decrypted message not equal to original message");



        // This should error
        let r = alice.i_confirm_message_has_been_sent();
        assert!(r.is_err(), "Confirmation over use did not cause an error");


    }
}


