use std::ops::Deref;
use zeroize::Zeroizing;

use crate::smp;
use crate::error::Error;


#[derive(Debug)]
pub struct WireMessage(pub Zeroizing<Vec<u8>>);

impl Deref for WireMessage {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[u8]> for WireMessage {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}


#[derive(Debug)]
pub struct UserPrompt {
    pub question: String,
    // TODO: Maybe add contact and our public key fingerprints here too to pass to caller ?
}

pub struct UserAnswer(pub Zeroizing<String>);

impl UserAnswer {
    pub fn new(s: String) -> Result<Self, Error> {
        Ok(Self(smp::normalize_smp_answer(Zeroizing::new(s))?))
    }
}


#[derive(Debug)]
pub struct NewMessage{
    pub message: Zeroizing<String>
}

#[derive(Debug)]
pub enum ContactOutput {
    None,
    Wire(Vec<WireMessage>),
    Prompt(UserPrompt),
    Message(NewMessage)
}


