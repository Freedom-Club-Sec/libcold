use super::*;
use std::io::{Cursor, Read};
use std::convert::TryFrom;

// safety limit
const MAX_FIELD_LEN: usize = 2 * 1024 * 1024; // 2 MiB max per field 

// The Magic byte
const MAGIC: &[u8] = b"COLDWIREMESSENGER\0";


impl Contact {
    /// Export the contact into a versioned, explicit plaintext blob.
    /// Caller MUST encrypt this blob before storing/transmitting it.
    /// Returns Zeroizing<Vec<u8>> so the plaintext will be zeroed on drop.
    pub fn export_plain(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        let mut out = Vec::with_capacity(1024);

        out.extend_from_slice(MAGIC);

        out.push(1u8); // format version 1

        // state
        let state_byte = match self.state {
            ContactState::Uninitialized => 0u8,
            ContactState::SMPInit       => 1u8,
            ContactState::SMPStep2      => 2u8,
            ContactState::SMPStep3      => 3u8,
            ContactState::Verified      => 4u8,
        };
        out.push(state_byte);

        // message_locked
        out.push(if self.message_locked { 1u8 } else { 0u8 });

        // now write each Option<Zeroizing<Vec<u8>>> in a deterministic order:
        write_opt_bytes(&mut out, &self.our_signing_pub_key)?;
        write_opt_bytes(&mut out, &self.our_signing_secret_key)?;
        write_opt_bytes(&mut out, &self.contact_signing_pub_key)?;

        write_opt_bytes(&mut out, &self.our_ml_kem_pub_key)?;
        write_opt_bytes(&mut out, &self.our_ml_kem_secret_key)?;
        write_opt_bytes(&mut out, &self.contact_ml_kem_pub_key)?;

        write_opt_bytes(&mut out, &self.our_mceliece_pub_key)?;
        write_opt_bytes(&mut out, &self.our_mceliece_secret_key)?;
        write_opt_bytes(&mut out, &self.contact_mceliece_pub_key)?;

        write_opt_bytes(&mut out, &self.our_staged_ml_kem_pub_key)?;
        write_opt_bytes(&mut out, &self.our_staged_ml_kem_secret_key)?;
        write_opt_bytes(&mut out, &self.our_staged_mceliece_pub_key)?;
        write_opt_bytes(&mut out, &self.our_staged_mceliece_secret_key)?;

        write_opt_bytes(&mut out, &self.our_smp_tmp_pub_key)?;
        write_opt_bytes(&mut out, &self.our_smp_tmp_secret_key)?;
        write_opt_bytes(&mut out, &self.contact_smp_tmp_pub_key)?;

        write_opt_bytes(&mut out, &self.our_next_strand_key)?;
        write_opt_bytes(&mut out, &self.our_next_strand_nonce)?;
        write_opt_bytes(&mut out, &self.contact_next_strand_key)?;
        write_opt_bytes(&mut out, &self.contact_next_strand_nonce)?;

        write_opt_bytes(&mut out, &self.our_smp_nonce)?;
        write_opt_bytes(&mut out, &self.contact_smp_nonce)?;
        write_opt_bytes(&mut out, &self.contact_smp_proof)?;

        write_opt_zeroize_string(&mut out, &self.smp_answer)?;
        write_opt_string(&mut out, &self.smp_question)?;

        write_opt_bytes(&mut out, &self.our_pads)?;
        write_opt_bytes(&mut out, &self.contact_pads)?;

        write_opt_bytes(&mut out, &self.our_hash_chain)?;
        write_opt_bytes(&mut out, &self.contact_hash_chain)?;
        
        write_opt_bytes(&mut out, &self.additional_data)?;

        // Note: backup is intentionally skipped (#[zeroize(skip)]).
        Ok(Zeroizing::new(out))
    }

    /// Import a plaintext blob created by export_plain.
    /// The blob MUST have been authenticated and decrypted by the caller before calling this.
    pub fn import_plain(blob: &[u8]) -> Result<Self, Error> {
        let mut cur = Cursor::new(blob);

        let mut magic_buf = [0u8; MAGIC.len()];
        cur.read_exact(&mut magic_buf).map_err(|_| Error::InvalidMagic)?;
        if &magic_buf != MAGIC {
            return Err(Error::InvalidMagic);
        }

        // parse header
        let version = read_u8(&mut cur)?;
        if version != 1 {
            return Err(Error::IncompatibleBlobVersion);
        }

        let state = match read_u8(&mut cur)? {
            0 => ContactState::Uninitialized,
            1 => ContactState::SMPInit,
            2 => ContactState::SMPStep2,
            3 => ContactState::SMPStep3,
            4 => ContactState::Verified,
            _ => return Err(Error::InvalidImportBlob),
        };

        let message_locked = match read_u8(&mut cur)? {
            0 => false,
            1 => true,
            _ => return Err(Error::InvalidImportBlob),
        };

        // Now read fields in the exact same order used in export_plain
        let our_signing_pub_key = read_opt_bytes(&mut cur, MAX_FIELD_LEN)?;
        let our_signing_secret_key = read_opt_bytes(&mut cur, MAX_FIELD_LEN)?;
        let contact_signing_pub_key = read_opt_bytes(&mut cur, MAX_FIELD_LEN)?;

        let our_ml_kem_pub_key = read_opt_bytes(&mut cur, MAX_FIELD_LEN)?;
        let our_ml_kem_secret_key = read_opt_bytes(&mut cur, MAX_FIELD_LEN)?;
        let contact_ml_kem_pub_key = read_opt_bytes(&mut cur, MAX_FIELD_LEN)?;

        let our_mceliece_pub_key = read_opt_bytes(&mut cur, MAX_FIELD_LEN)?;
        let our_mceliece_secret_key = read_opt_bytes(&mut cur, MAX_FIELD_LEN)?;
        let contact_mceliece_pub_key = read_opt_bytes(&mut cur, MAX_FIELD_LEN)?;

        let our_staged_ml_kem_pub_key = read_opt_bytes(&mut cur, MAX_FIELD_LEN)?;
        let our_staged_ml_kem_secret_key = read_opt_bytes(&mut cur, MAX_FIELD_LEN)?;
        let our_staged_mceliece_pub_key = read_opt_bytes(&mut cur, MAX_FIELD_LEN)?;
        let our_staged_mceliece_secret_key = read_opt_bytes(&mut cur, MAX_FIELD_LEN)?;

        let our_smp_tmp_pub_key = read_opt_bytes(&mut cur, MAX_FIELD_LEN)?;
        let our_smp_tmp_secret_key = read_opt_bytes(&mut cur, MAX_FIELD_LEN)?;
        let contact_smp_tmp_pub_key = read_opt_bytes(&mut cur, MAX_FIELD_LEN)?;

        let our_next_strand_key = read_opt_bytes(&mut cur, MAX_FIELD_LEN)?;
        let our_next_strand_nonce = read_opt_bytes(&mut cur, MAX_FIELD_LEN)?;
        let contact_next_strand_key = read_opt_bytes(&mut cur, MAX_FIELD_LEN)?;
        let contact_next_strand_nonce = read_opt_bytes(&mut cur, MAX_FIELD_LEN)?;

        let our_smp_nonce = read_opt_bytes(&mut cur, MAX_FIELD_LEN)?;
        let contact_smp_nonce = read_opt_bytes(&mut cur, MAX_FIELD_LEN)?;
        let contact_smp_proof = read_opt_bytes(&mut cur, MAX_FIELD_LEN)?;

        let smp_answer = read_opt_zeroize_string(&mut cur, MAX_FIELD_LEN)?;
        let smp_question = read_opt_string(&mut cur, MAX_FIELD_LEN)?;

        let our_pads = read_opt_bytes(&mut cur, MAX_FIELD_LEN)?;
        let contact_pads = read_opt_bytes(&mut cur, MAX_FIELD_LEN)?;

        let our_hash_chain = read_opt_bytes(&mut cur, MAX_FIELD_LEN)?;
        let contact_hash_chain = read_opt_bytes(&mut cur, MAX_FIELD_LEN)?;
        
        let additional_data = read_opt_bytes(&mut cur, MAX_FIELD_LEN)?;

        if cur.position() != blob.len() as u64 {
            return Err(Error::InvalidDataPlaintextLength);
        }


        // Construct Contact - match the field ordering in the struct initializer
        let contact = Contact {
            state: state,
            message_locked: message_locked,

            our_signing_pub_key: our_signing_pub_key,
            our_signing_secret_key: our_signing_secret_key,
            contact_signing_pub_key: contact_signing_pub_key,

            our_ml_kem_pub_key: our_ml_kem_pub_key,
            our_ml_kem_secret_key: our_ml_kem_secret_key,
            contact_ml_kem_pub_key: contact_ml_kem_pub_key,

            our_mceliece_pub_key: our_mceliece_pub_key,
            our_mceliece_secret_key: our_mceliece_secret_key,
            contact_mceliece_pub_key: contact_mceliece_pub_key,

            our_staged_ml_kem_pub_key: our_staged_ml_kem_pub_key,
            our_staged_ml_kem_secret_key: our_staged_ml_kem_secret_key,

            our_staged_mceliece_pub_key: our_staged_mceliece_pub_key,
            our_staged_mceliece_secret_key: our_staged_mceliece_secret_key,

            our_smp_tmp_pub_key: our_smp_tmp_pub_key,
            our_smp_tmp_secret_key: our_smp_tmp_secret_key,
            contact_smp_tmp_pub_key: contact_smp_tmp_pub_key,

            our_next_strand_key: our_next_strand_key,
            our_next_strand_nonce: our_next_strand_nonce,

            contact_next_strand_key: contact_next_strand_key,
            contact_next_strand_nonce: contact_next_strand_nonce,

            our_smp_nonce: our_smp_nonce,
            contact_smp_nonce: contact_smp_nonce,
            contact_smp_proof: contact_smp_proof,

            smp_answer: smp_answer,
            smp_question: smp_question,

            our_pads: our_pads,
            contact_pads: contact_pads,

            our_hash_chain: our_hash_chain,
            contact_hash_chain: contact_hash_chain,

            additional_data: additional_data,

            backup: None,
        };

        Ok(contact)
    }
}

fn write_opt_bytes(buf: &mut Vec<u8>, opt: &Option<Zeroizing<Vec<u8>>>) -> Result<(), Error> {
    match opt {
        None => { buf.push(0); Ok(()) },
        Some(z) => {
            buf.push(1);
            let len = z.len();
            if len > MAX_FIELD_LEN { return Err(Error::FieldTooLarge); }
            let len_u32 = u32::try_from(len).map_err(|_| Error::FieldTooLarge)?;
            buf.extend_from_slice(&len_u32.to_be_bytes());
            buf.extend_from_slice(&z);
            Ok(())
        }
    }
}

fn write_opt_string(buf: &mut Vec<u8>, opt: &Option<String>) -> Result<(), Error> {
    match opt {
        None => { buf.push(0); Ok(()) },
        Some(s) => {
            buf.push(1);
            let bytes = s.as_bytes();
            let len = bytes.len();
            if len > MAX_FIELD_LEN { return Err(Error::FieldTooLarge); }
            let len_u32 = u32::try_from(len).map_err(|_| Error::FieldTooLarge)?;
            buf.extend_from_slice(&len_u32.to_be_bytes());
            buf.extend_from_slice(bytes);
            Ok(())
        }
    }
}

fn write_opt_zeroize_string(buf: &mut Vec<u8>, opt: &Option<Zeroizing<String>>) -> Result<(), Error> {
    match opt {
        None => { buf.push(0); Ok(()) },
        Some(zs) => {
            buf.push(1);
            let bytes = zs.as_bytes();
            let len = bytes.len();
            if len > MAX_FIELD_LEN { return Err(Error::FieldTooLarge); }
            let len_u32 = u32::try_from(len).map_err(|_| Error::FieldTooLarge)?;
            buf.extend_from_slice(&len_u32.to_be_bytes());
            buf.extend_from_slice(bytes);
            Ok(())
        }
    }
}


// Import helpers
fn read_u8(cur: &mut Cursor<&[u8]>) -> Result<u8, Error> {
    let mut b = [0u8; 1];
    cur.read_exact(&mut b).map_err(|_| Error::InvalidImportBlob)?;
    Ok(b[0])
}
fn read_u32(cur: &mut Cursor<&[u8]>) -> Result<u32, Error> {
    let mut b = [0u8; 4];
    cur.read_exact(&mut b).map_err(|_| Error::InvalidImportBlob)?;
    Ok(u32::from_be_bytes(b))
}
fn read_bytes(cur: &mut Cursor<&[u8]>, len: usize) -> Result<Vec<u8>, Error> {
    let mut v = vec![0u8; len];
    cur.read_exact(&mut v).map_err(|_| Error::InvalidImportBlob)?;
    Ok(v)
}

fn read_opt_bytes(cur: &mut Cursor<&[u8]>, max_len: usize) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
    let present = read_u8(cur)?;
    if present == 0 { return Ok(None); }
    if present != 1 { return Err(Error::InvalidImportBlob); }
    let len = read_u32(cur)? as usize;
    if len > max_len { return Err(Error::FieldTooLarge); }
    let bytes = read_bytes(cur, len)?;
    Ok(Some(Zeroizing::new(bytes)))
}


fn read_opt_string(cur: &mut Cursor<&[u8]>, max_len: usize) -> Result<Option<String>, Error> {
    let present = read_u8(cur)?;
    if present == 0 { return Ok(None); }
    if present != 1 { return Err(Error::InvalidImportBlob); }
    let len = read_u32(cur)? as usize;
    if len > max_len { return Err(Error::FieldTooLarge); }
    let bytes = read_bytes(cur, len)?;
    let s = String::from_utf8(bytes).map_err(|_| Error::InvalidUtf8)?;
    Ok(Some(s))
}

fn read_opt_zeroize_string(cur: &mut Cursor<&[u8]>, max_len: usize) -> Result<Option<Zeroizing<String>>, Error> {
    if let Some(s) = read_opt_string(cur, max_len)? {
        Ok(Some(Zeroizing::new(s)))
    } else {
        Ok(None)
    }
}


