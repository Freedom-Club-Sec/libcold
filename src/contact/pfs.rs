use super::*;


impl Contact {
    pub(super) fn do_pfs_new(&mut self, pfs_plaintext: &[u8]) ->  Result<ContactOutput, Error> {
        if pfs_plaintext.len() != 64 + consts::ML_DSA_87_SIGN_SIZE + consts::ML_KEM_1024_PK_SIZE + consts::CLASSIC_MCELIECE_8_PK_SIZE {
            return Err(Error::InvalidPfsPlaintextLength);
        }

        let contact_signing_pk = self.contact_signing_pub_key
            .as_ref().unwrap();

        let contact_hash_chain = self.contact_hash_chain
            .as_ref();


        let signature = pfs_plaintext.get(.. consts::ML_DSA_87_SIGN_SIZE)
            .ok_or(Error::InvalidPfsPlaintextLength)?;

        let signature_data = pfs_plaintext.get(consts::ML_DSA_87_SIGN_SIZE ..)
            .ok_or(Error::InvalidPfsPlaintextLength)?;

        // Verify the signature of the public-keys and the hash-chain.
        crypto::verify_signature(oqs::sig::Algorithm::MlDsa87, contact_signing_pk, signature_data, signature)?;

        let contact_next_hash_chain = pfs_plaintext.get(consts::ML_DSA_87_SIGN_SIZE .. consts::ML_DSA_87_SIGN_SIZE + 64)
            .ok_or(Error::InvalidPfsPlaintextLength)?;


        let contact_ml_kem_pk = pfs_plaintext.get(64 + consts::ML_DSA_87_SIGN_SIZE .. 64 + consts::ML_DSA_87_SIGN_SIZE + consts::ML_KEM_1024_PK_SIZE)
            .ok_or(Error::InvalidPfsPlaintextLength)?;

        let contact_mceliece_pk = pfs_plaintext.get(64 + consts::ML_DSA_87_SIGN_SIZE + consts::ML_KEM_1024_PK_SIZE ..)
            .ok_or(Error::InvalidPfsPlaintextLength)?;


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
            let ephemeral = self.do_new_ephemeral_keys()?;

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

    pub(super) fn do_pfs_ack(&mut self, pfs_plaintext: &[u8]) ->  Result<ContactOutput, Error> {
        self.our_ml_kem_secret_key = self.our_staged_ml_kem_secret_key.take();
        self.our_ml_kem_pub_key = self.our_staged_ml_kem_pub_key.take();

        self.our_mceliece_secret_key = self.our_staged_mceliece_secret_key.take();
        self.our_mceliece_pub_key = self.our_staged_mceliece_pub_key.take();

        Ok(ContactOutput::None)
    }

    pub(super) fn do_new_ephemeral_keys(&mut self) ->  Result<ContactOutput, Error> {
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

        self.our_staged_ml_kem_pub_key = Some(ml_kem_pk);
        self.our_staged_ml_kem_secret_key = Some(ml_kem_sk);

        self.our_staged_mceliece_pub_key = Some(mceliece_pk);
        self.our_staged_mceliece_secret_key = Some(mceliece_sk);

        Ok(ContactOutput::Wire(vec![WireMessage(final_payload)]))
    
    }

}
