use super::*;



impl Contact {
    pub(super) fn decrypt_incoming_data(&mut self, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        let contact_strand_key = self.contact_next_strand_key.as_ref().unwrap();
        let contact_strand_nonce = self.contact_next_strand_nonce.as_ref().unwrap();

        let plaintext = crypto::decrypt_chacha20poly1305(contact_strand_key, contact_strand_nonce, blob)?;

        let next_key = plaintext
            .get(..32)
            .ok_or(Error::InvalidDataLength)?;

        let next_nonce = plaintext
            .get(32..32 + consts::CHACHA20POLY1305_NONCE_SIZE)
            .ok_or(Error::InvalidDataLength)?;

        self.contact_next_strand_key = Some(Zeroizing::new(next_key.to_vec()));

        self.contact_next_strand_nonce = Some(Zeroizing::new(next_nonce.to_vec()));

        let message = plaintext
            .get(32 + consts::CHACHA20POLY1305_NONCE_SIZE..)
            .ok_or(Error::InvalidDataLength)?;

        Ok(Zeroizing::new(message.to_vec()))
    }

    /// Prepapre the payload by wrap encrypting it and also continues the ratchet.
    pub(super) fn prepare_payload(&mut self, payload: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        let our_next_strand_key = crypto::generate_secure_random_bytes_whiten(32)?;

        let our_next_strand_nonce = crypto::generate_secure_random_bytes_whiten(consts::CHACHA20POLY1305_NONCE_SIZE)?;

        let our_strand_key = self.our_next_strand_key.as_ref().unwrap();
        let our_strand_nonce = self.our_next_strand_nonce.as_ref().unwrap();

       
        let mut prepared_payload = Zeroizing::new(Vec::with_capacity(32 + consts::CHACHA20POLY1305_NONCE_SIZE + payload.len()));
        prepared_payload.extend_from_slice(&our_next_strand_key);
        prepared_payload.extend_from_slice(&our_next_strand_nonce);
        prepared_payload.extend_from_slice(payload);

        let (ciphertext_blob, _) = crypto::encrypt_chacha20poly1305(&our_strand_key, &prepared_payload, Some(our_strand_nonce.as_slice()), consts::CHACHA20POLY1305_MAX_RANDOM_PAD)?;

        self.our_next_strand_key = Some(our_next_strand_key);
        self.our_next_strand_nonce = Some(our_next_strand_nonce);

        Ok(Zeroizing::new(ciphertext_blob))

    }
}
