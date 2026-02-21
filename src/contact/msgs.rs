use super::*;

impl Contact {
    pub(super) fn do_generate_otpads(&mut self) ->  Result<ContactOutput, Error>  {
        let ml_dsa_sk = self.our_signing_secret_key
            .as_ref().unwrap();

        let contact_ml_kem_pk = self.contact_ml_kem_pub_key
            .as_ref().unwrap();

        let contact_mceliece_pk = self.contact_mceliece_pub_key
            .as_ref().unwrap();

        
        let (ml_kem_ciphertexts, ml_kem_secrets) = crypto::generate_shared_secrets(&contact_ml_kem_pk, oqs::kem::Algorithm::MlKem1024, consts::OTP_PAD_SIZE)?;
        let (mceliece_ciphertexts, mceliece_secrets) = crypto::generate_shared_secrets(&contact_mceliece_pk, oqs::kem::Algorithm::ClassicMcEliece8192128, consts::OTP_PAD_SIZE)?;

        let mut chacha_shared_secrets = Vec::new();

        while chacha_shared_secrets.len() < consts::OTP_PAD_SIZE {
            let random_bytes = crypto::generate_secure_random_bytes_whiten(64)?;
            chacha_shared_secrets.extend_from_slice(&random_bytes);
        }

        let mut otp_batch_plain = Zeroizing::new(Vec::with_capacity(consts::ML_KEM_1024_CT_SIZE + consts::CLASSIC_MCELIECE_8_CT_SIZE ));
        otp_batch_plain.extend_from_slice(ml_kem_ciphertexts.as_slice());
        otp_batch_plain.extend_from_slice(mceliece_ciphertexts.as_slice());

        let otp_batch_signature = crypto::generate_signature(oqs::sig::Algorithm::MlDsa87, ml_dsa_sk, &otp_batch_plain)?;

        otp_batch_plain.extend_from_slice(chacha_shared_secrets.as_slice());

        let mut payload = Zeroizing::new(Vec::with_capacity(
                1 + 
                otp_batch_signature.len() +
                otp_batch_plain.len()

            ));

        payload.push(consts::MSG_TYPE_MSG_BATCH);
        payload.extend_from_slice(&otp_batch_signature);
        payload.extend_from_slice(&otp_batch_plain);

        let final_payload = self.prepare_payload(&payload)?;

        let (our_pads, _) = crypto::one_time_pad(&ml_kem_secrets, &mceliece_secrets)?;
        let (our_pads, _) = crypto::one_time_pad(our_pads.as_slice(), &chacha_shared_secrets)?;

        self.our_next_strand_key = Some(Zeroizing::new(our_pads.get(..32).unwrap().to_vec()));

        self.our_pads = Some(Zeroizing::new(our_pads.get(32..).unwrap().to_vec()));

        Ok(ContactOutput::Wire(vec![WireMessage(final_payload)]))
    }


    pub fn i_confirm_message_has_been_sent(&mut self) ->  Result<(), Error> {
        if self.message_locked == false {
            return Err(Error::MessageLockAlreadyDisabled);
        }

        self.message_locked = false;
        
        Ok(())
    }
    
    pub fn send_message(&mut self, message: &Zeroizing<String>) ->  Result<ContactOutput, Error> {
        // Failsafe to protect retarded callers
        if self.state != ContactState::Verified {
            return Err(Error::InvalidState);
        }

        if self.message_locked == true {
            return Err(Error::MessagesLockedUntilConfirm);
        }
        // Ensures we cannot send messages until the caller confirms they have successfully sent
        // the message
        self.message_locked = true;

        let mut messages = vec![];
            
        // We have no pads (Either None or Empty vec).
        if self.our_pads.as_ref().map_or(true, |v| v.is_empty()) {
            let ephemeral = self.do_generate_otpads()?;

            if let ContactOutput::Wire(mut ws) = ephemeral {
                messages.append(&mut ws); 
            }
        }

        let mut our_pads = self.our_pads.as_ref().unwrap();

        // We do this to ensure if our pads are not enough for the padded message, we simply
        // generate new pads.
        let (message_encrypted, new_pads) = match crypto::otp_encrypt_with_padding(message.as_bytes(), our_pads) {
            Ok((ct, np)) => (ct, np),
            Err(_) => {
                let ephemeral = self.do_generate_otpads()?;
                if let ContactOutput::Wire(mut ws) = ephemeral {
                    messages.append(&mut ws);
                }
                our_pads = self.our_pads.as_ref().unwrap();
                crypto::otp_encrypt_with_padding(message.as_bytes(), our_pads)?
            }
        };

        // Truncate pads
        self.our_pads = Some(Zeroizing::new(new_pads));

        let mut payload = Zeroizing::new(Vec::with_capacity(
                1 + 
                message_encrypted.len()
            ));

        payload.push(consts::MSG_TYPE_MSG_NEW);
        payload.extend_from_slice(&message_encrypted);

        let final_payload = self.prepare_payload(&payload)?;

        messages.push(WireMessage(final_payload));

        Ok(ContactOutput::Wire(messages))
    }


    pub(super) fn do_process_otp_batch(&mut self, msgs_plaintext: &[u8]) ->  Result<ContactOutput, Error> {
        // NOTE: Rust / floors. So if it errors, u know why. 

        if msgs_plaintext.len() != ( (consts::ML_KEM_1024_CT_SIZE + consts::CLASSIC_MCELIECE_8_CT_SIZE) * (consts::OTP_PAD_SIZE / 32)) + (64 * (consts::OTP_PAD_SIZE / 64)) + consts::ML_DSA_87_SIGN_SIZE {
            return Err(Error::InvalidMsgsPlaintextLength);
        }

        let contact_signing_pk = self.contact_signing_pub_key
            .as_ref().unwrap();


        let our_ml_kem_sk = self.our_ml_kem_secret_key
            .as_ref().ok_or(Error::UninitializedContactKeys)?;

        let our_mceliece_sk = self.our_mceliece_secret_key
            .as_ref().ok_or(Error::UninitializedContactKeys)?;



        let batch_signature = msgs_plaintext
            .get(.. consts::ML_DSA_87_SIGN_SIZE)
            .ok_or(Error::InvalidMsgsPlaintextLength)?;

        let batch_ciphertext = msgs_plaintext
            .get(consts::ML_DSA_87_SIGN_SIZE .. consts::ML_DSA_87_SIGN_SIZE + ((consts::ML_KEM_1024_CT_SIZE + consts::CLASSIC_MCELIECE_8_CT_SIZE) * (consts::OTP_PAD_SIZE / 32)))
            .ok_or(Error::InvalidMsgsPlaintextLength)?;

        let chacha_shared_secrets = msgs_plaintext
            .get(consts::ML_DSA_87_SIGN_SIZE + ((consts::ML_KEM_1024_CT_SIZE + consts::CLASSIC_MCELIECE_8_CT_SIZE) * (consts::OTP_PAD_SIZE / 32)) ..)
            .ok_or(Error::InvalidMsgsPlaintextLength)?;


        crypto::verify_signature(oqs::sig::Algorithm::MlDsa87, contact_signing_pk, batch_ciphertext, batch_signature)?;


        let batch_ml_kem_ciphertext = batch_ciphertext
            .get(..consts::ML_KEM_1024_CT_SIZE * (consts::OTP_PAD_SIZE / 32))
            .ok_or(Error::InvalidMsgsPlaintextLength)?;

        let batch_mceliece_ciphertext = batch_ciphertext
            .get(consts::ML_KEM_1024_CT_SIZE * (consts::OTP_PAD_SIZE / 32) .. )
            .ok_or(Error::InvalidMsgsPlaintextLength)?;


        let ml_kem_secrets = crypto::decrypt_shared_secrets(batch_ml_kem_ciphertext, our_ml_kem_sk, oqs::kem::Algorithm::MlKem1024, consts::OTP_PAD_SIZE)?;
        let mceliece_secrets = crypto::decrypt_shared_secrets(batch_mceliece_ciphertext, our_mceliece_sk, oqs::kem::Algorithm::ClassicMcEliece8192128, consts::OTP_PAD_SIZE)?;


        let (contact_pads, _) = crypto::one_time_pad(&ml_kem_secrets, &mceliece_secrets)?;
        let (contact_pads, _) = crypto::one_time_pad(contact_pads.as_slice(), chacha_shared_secrets)?;


        let contact_next_strand_key = contact_pads
            .get(..32)
            .ok_or(Error::InvalidMsgsPlaintextLength)?;

        let contact_pads = contact_pads
            .get(32..)
            .ok_or(Error::InvalidMsgsPlaintextLength)?;


        self.contact_next_strand_key = Some(Zeroizing::new(contact_next_strand_key.to_vec()));
        self.contact_pads = Some(Zeroizing::new(contact_pads.to_vec()));

        // PFS.
        let final_payload = self.do_new_ephemeral_keys()?;

        Ok(final_payload)

    }

    pub(super) fn do_process_new_msg(&mut self, msgs_plaintext: &[u8]) ->  Result<ContactOutput, Error> {
        let mut contact_pads = self.contact_pads
            .take()
            .ok_or(Error::UninitializedContactKeys)?;


        if msgs_plaintext.len() > contact_pads.len() {
            // If this happens, contact has corrupted OTP state and forgot to send us a message.
            return Err(Error::CorruptedOTPState);
        }


        let pads_to_be_consumed = &contact_pads[..msgs_plaintext.len()];

        let message_decrypted = crypto::otp_decrypt_with_padding(msgs_plaintext, pads_to_be_consumed)?;

        let message_utf_8 = Zeroizing::new(String::from_utf8(message_decrypted)
            .map_err(|_| Error::MessageInvalidUtf8)?);


        // Consume the used pads.
        let remaining_pads = contact_pads.split_off(msgs_plaintext.len());
        self.contact_pads = Some(Zeroizing::new(remaining_pads));

        Ok(ContactOutput::Message(
                NewMessage{
                    message: message_utf_8
                }
            ))
    }


}
