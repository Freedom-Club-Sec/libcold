use super::*;

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


}
