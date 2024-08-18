use bitcoin::blockdata::{block::{Block}, transaction::{Transaction}};
use bitcoin::script::Script;
use crate::index_pointer::{IndexPointer};
use crate::envelope::{RawEnvelope};
use anyhow;
use hex;
use std::sync::Arc;

pub fn index_block(block: Block) -> Result<(), anyhow::Error> {
  for transaction in &block.txdata {
    index_transaction(&transaction)?;
  }
  Ok(())
}

pub fn index_transaction(transaction: &Transaction) -> Result<(), anyhow::Error> {
  for envelope in RawEnvelope::from_transaction(transaction) {
  let payload: Arc<Vec<u8>> = Arc::new(envelope.payload.clone().into_iter().flatten().collect());
  IndexPointer::from_keyword("/programs").append(payload.clone());
  println!("{}", hex::encode(&envelope.payload[0]));
  }
  Ok(())
}
