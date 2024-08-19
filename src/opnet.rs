use crate::envelope::RawEnvelope;
use crate::index_pointer::IndexPointer;
use anyhow;
use bitcoin::blockdata::{block::Block, transaction::Transaction};
use bitcoin::script::Script;
use bitcoin::Amount;
use hex;
use libflate::zlib::{Decoder, Encoder};
use std::io::Read;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use wasmi::*;

pub fn index_block(block: Block) -> Result<(), anyhow::Error> {
    for transaction in &block.txdata {
        index_transaction(&transaction)?;
    }
    Ok(())
}

pub fn try_read_arraybuffer_as_vec(data: &[u8], data_start: i32) -> Result<Vec<u8>, anyhow::Error> {
    if data_start < 4 {
        return Err(anyhow::anyhow!("memory error"));
    }
    let len = u32::from_le_bytes(
        (data[((data_start - 4) as usize)..(data_start as usize)])
            .try_into()
            .unwrap(),
    );
    return Ok(Vec::<u8>::from(
        &data[(data_start as usize)..(((data_start as u32) + len) as usize)],
    ));
}

pub fn read_arraybuffer_as_vec(data: &[u8], data_start: i32) -> Vec<u8> {
    match try_read_arraybuffer_as_vec(data, data_start) {
        Ok(v) => v,
        Err(_) => Vec::<u8>::new(),
    }
}

struct OpnetContract {
    instance: InstancePre,
    store: Store<State>,
    storage: Arc<Mutex<StorageView>>,
}

struct State {
    address: Vec<u8>,
    had_failure: bool,
    storage: Arc<Mutex<StorageView>>,
}

impl OpnetContract {
    pub fn load(address: &Vec<u8>, program: &Vec<u8>) -> Result<Self, anyhow::Error> {
        let engine = Engine::default();
        let storage = Arc::new(Mutex::new(StorageView::at(
            IndexPointer::from_keyword("/contracts/")
                .select(&address)
                .keyword("/storage/"),
        )));
        let mut store = Store::<State>::new(
            &engine,
            State {
                address: address.clone(),
                had_failure: false,
                storage: storage.clone(),
            },
        );
        let cloned = program.clone();
        let module = Module::new(&engine, &mut &cloned[..])?;
        let mut linker: Linker<State> = Linker::<State>::new(&engine);
        linker.func_wrap(
            "env",
            "abort",
            |mut caller: Caller<'_, State>, _: i32, _: i32, _: i32, _: i32| {
                caller.data_mut().had_failure = true;
            },
        )?;
        linker.func_wrap(
            "env",
            "sha256",
            |mut caller: Caller<'_, State>, v: i32| -> i32 {
                // handle sha256
                0
            },
        )?;
        linker.func_wrap(
            "env",
            "load",
            |mut caller: Caller<'_, State>, v: i32| -> i32 {
                let mem = caller.get_export("memory").unwrap().into_memory().unwrap();
                let key = {
                 let data = mem.data(&caller);
                 read_arraybuffer_as_vec(data, v)
                };
                let value = caller.data_mut().storage.lock().unwrap().get(&key);
                // TODO: return value from storage
                0
            },
        )?;
        linker.func_wrap(
            "env",
            "store",
            |mut caller: Caller<'_, State>, k: i32, v: i32| {
                let mem = caller.get_export("memory").unwrap().into_memory().unwrap();
                let (key, value) = {
                  let data = mem.data(&caller);
                  (read_arraybuffer_as_vec(data, k), read_arraybuffer_as_vec(data, v))
                };
                caller.data_mut().storage.lock().unwrap().set(&key, &value);
            },
        )?;
        linker.func_wrap(
            "env",
            "defineSelectors",
            |mut caller: Caller<'_, State>, v: i32| {},
        )?;
        linker.func_wrap(
            "env",
            "readMethod",
            |mut caller: Caller<'_, State>, v: i32| {},
        )?;
        linker.func_wrap(
            "env",
            "readView",
            |mut caller: Caller<'_, State>, v: i32| {},
        )?;
        linker.func_wrap(
            "env",
            "getEvents",
            |mut caller: Caller<'_, State>, v: i32| {},
        )?;
        linker.func_wrap(
            "env",
            "getViewABI",
            |mut caller: Caller<'_, State>, v: i32| {},
        )?;
        linker.func_wrap(
            "env",
            "getMethodABI",
            |mut caller: Caller<'_, State>, v: i32| {},
        )?;
        linker.func_wrap(
            "env",
            "getWriteMethods",
            |mut caller: Caller<'_, State>, v: i32| {},
        )?;
        linker.func_wrap(
            "env",
            "setEnvironment",
            |mut caller: Caller<'_, State>, v: i32| {},
        )?;
        Ok(OpnetContract {
          instance: linker.instantiate(&mut store, &module)?,
          store,
          storage: storage.clone()
        })
    }
    pub fn reset(&mut self) {
      self.store.data_mut().had_failure = false;
    }
    pub fn run(&mut self, calldata: Vec<u8>) -> Result<(), anyhow::Error> {
        // TODO: supply calldata, determine the entrypoint of WASM files for OP_NET contracts, write
        // code here to invoke it
        let had_failure = self.store.data().had_failure;
        self.reset();
        if had_failure {
          return Err(anyhow::anyhow!("OP_NET: revert"));
        } else {
          return Ok(())
        }
    }
}

pub struct StorageView {
    cache: HashMap<Vec<u8>, Vec<u8>>,
    table: IndexPointer,
}

impl StorageView {
    pub fn at(table: IndexPointer) -> Self {
        StorageView {
            cache: HashMap::<Vec<u8>, Vec<u8>>::new(),
            table,
        }
    }
    pub fn get(&self, k: &Vec<u8>) -> Vec<u8> {
        if let Some(value) = self.cache.get(k) {
          value.clone()
        } else {
            (*self.table.select(k).get()).clone()
        }
    }
    pub fn set(&mut self, k: &Vec<u8>, v: &Vec<u8>) {
        self.cache.insert(k.clone(), v.clone());
    }
    pub fn flush(&mut self) {
        self.cache.clone().iter().for_each(|(k, v)| {
          self.table.select(k).set(Arc::new(v.clone()));
          self.cache.remove(k);
        });
    }
}

pub fn index_transaction(transaction: &Transaction) -> Result<(), anyhow::Error> {
    for envelope in RawEnvelope::from_transaction(transaction) {
        let payload: Arc<Vec<u8>> = Arc::new(
            envelope
                .payload
                .clone()
                .into_iter()
                .skip(1)
                .flatten()
                .collect(),
        );
        if payload.len() > 0 && transaction.output[0].value > Amount::from_sat(330) {
            //            println!("{}", hex::encode(&envelope.payload[0]));
            let script_pubkey: Vec<u8> = transaction.output[0].script_pubkey.clone().into(); //transaction.output[0].into_address();
            let table_entry = IndexPointer::from_keyword("/contracts/").select(&script_pubkey);
            let program = table_entry.get();
            if (program.len() == 0) {
                let mut buf = Vec::new();
                let cloned = payload.clone();
                let mut decoder: Decoder<&[u8]> = Decoder::new(&cloned[..])?;
                decoder.read_to_end(&mut buf)?;
                table_entry.set(Arc::new(buf));
            } else {
                if let Ok(mut vm) = OpnetContract::load(&script_pubkey, &program) {
                    match vm.run((*payload).clone()) {
                      Ok(_) => {
                        println!("OP_NET: transaction success");
                        vm.storage.lock().unwrap().flush(); // transaction success -- save updated storage slots
                      },
                      Err(e) => println!("{}", e)
                    };
                }
            }
        }
    }
    Ok(())
}
