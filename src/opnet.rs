use crate::envelope::RawEnvelope;
use crate::index_pointer::IndexPointer;
use anyhow;
use bitcoin::blockdata::{block::Block, transaction::Transaction};
use bitcoin::script::Script;
use bitcoin::Amount;
use hex;
use libflate::zlib::{Decoder, Encoder};
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;
use std::io::Read;
use std::sync::{Arc, Mutex};
use wasmi::*;
//use wasmi::module::utils::WasmiValueType;

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
    let len =
        u32::from_le_bytes((data[((data_start - 4) as usize)..(data_start as usize)]).try_into()?);
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
    limiter: StoreLimits,
}

const MEMORY_LIMIT: usize = 33554432;

pub struct OpnetHostFunctionsImpl(());

pub fn get_memory<'a>(caller: &mut Caller<'_, State>) -> Result<Memory, anyhow::Error> {
    caller
        .get_export("memory")
        .ok_or(anyhow::anyhow!("export was not memory region"))?
        .into_memory()
        .ok_or(anyhow::anyhow!("export was not memory region"))
}

impl OpnetHostFunctionsImpl {
    fn _abort<'a>(mut caller: Caller<'_, State>) {
        OpnetHostFunctionsImpl::abort(caller, 0, 0, 0, 0);
    }
    fn abort<'a>(mut caller: Caller<'_, State>, _: i32, _: i32, _: i32, _: i32) {
        caller.data_mut().had_failure = true;
    }
    fn sha256<'a>(caller: &mut Caller<'_, State>, v: i32) -> Result<i32, anyhow::Error> {
        // handle sha256
        let mut hasher = Sha3_256::new();
        let mem = get_memory(caller)?;
        hasher.update(read_arraybuffer_as_vec(mem.data(&caller), v));
        send_to_arraybuffer(caller, &hasher.finalize().to_vec())
    }
    fn load<'a>(caller: &mut Caller<'_, State>, k: i32) -> Result<i32, anyhow::Error> {
        let mem = get_memory(caller)?;
        let key = {
            let data = mem.data(&caller);
            try_read_arraybuffer_as_vec(data, k)?
        };
        let value = caller.data_mut().storage.lock().unwrap().get(&key);
        send_to_arraybuffer(caller, &value)
    }
    fn store<'a>(caller: &mut Caller<'_, State>, k: i32, v: i32) -> Result<(), anyhow::Error> {
        let mem = get_memory(caller)?;
        let (key, value) = {
            let data = mem.data(&caller);
            (
                try_read_arraybuffer_as_vec(data, k)?,
                try_read_arraybuffer_as_vec(data, v)?,
            )
        };
        caller.data_mut().storage.lock().unwrap().set(&key, &value);
        Ok(())
    }
    fn log<'a>(caller: &mut Caller<'_, State>, v: i32) -> Result<(), anyhow::Error> {
        crate::stdio::log({
            let mem = get_memory(caller)?;
            Arc::new(try_read_arraybuffer_as_vec(mem.data(&caller), v)?)
        });
        Ok(())
    }
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
                limiter: StoreLimitsBuilder::new().memory_size(MEMORY_LIMIT).build(),
                storage: storage.clone(),
            },
        );
        store.limiter(|state| &mut state.limiter);
        let cloned = program.clone();
        let module = Module::new(&engine, &mut &cloned[..])?;
        let mut linker: Linker<State> = Linker::<State>::new(&engine);
        linker.func_wrap("env", "abort", OpnetHostFunctionsImpl::abort)?;
        linker.func_wrap("env", "sha256", |mut caller: Caller<'_, State>, v: i32| {
            match OpnetHostFunctionsImpl::sha256(&mut caller, v) {
                Ok(v) => v,
                Err(e) => {
                    OpnetHostFunctionsImpl::_abort(caller);
                    return -1;
                }
            }
        })?;
        linker.func_wrap("env", "load", |mut caller: Caller<'_, State>, k: i32| {
            match OpnetHostFunctionsImpl::load(&mut caller, k) {
                Ok(v) => v,
                Err(e) => {
                    OpnetHostFunctionsImpl::_abort(caller);
                    return -1;
                }
            }
        })?;
        linker.func_wrap(
            "env",
            "store",
            |mut caller: Caller<'_, State>, k: i32, v: i32| {
                if let Err(e) = OpnetHostFunctionsImpl::store(&mut caller, k, v) {
                    OpnetHostFunctionsImpl::_abort(caller);
                }
            },
        )?;
        linker.func_wrap("env", "deploy", |mut caller: Caller<'_, State>, v: i32| {})?;
        linker.func_wrap(
            "env",
            "deployFromAddress",
            |mut caller: Caller<'_, State>, v: i32| {},
        )?;
        linker.func_wrap("env", "call", |mut caller: Caller<'_, State>, v: i32| {})?;
        linker.func_wrap("env", "log", |mut caller: Caller<'_, State>, v: i32| {
            if let Err(e) = OpnetHostFunctionsImpl::log(&mut caller, v) {
                OpnetHostFunctionsImpl::_abort(caller);
            }
        })?;
        linker.func_wrap(
            "env",
            "encodeAddress",
            |mut caller: Caller<'_, State>, v: i32| {},
        )?;
        Ok(OpnetContract {
            instance: linker.instantiate(&mut store, &module)?,
            store,
            storage: storage.clone(),
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
            return Ok(());
        }
    }
}

pub struct StorageView {
    cache: HashMap<Vec<u8>, Vec<u8>>,
    table: IndexPointer,
}

pub fn send_to_arraybuffer<'a>(
    caller: &mut Caller<'_, State>,
    v: &Vec<u8>,
) -> Result<i32, anyhow::Error> {
    let mut result = [Value::I32(0)];
    caller
        .get_export("__new")
        .ok_or(anyhow::anyhow!(
            "__new export not found -- is this WASM built with --exportRuntime?"
        ))?
        .into_func()
        .ok_or(anyhow::anyhow!("__new export not a Func"))?
        .call(
            &mut *caller,
            &[Value::I32(v.len().try_into()?)],
            &mut result,
        )?;
    let mem = caller
        .get_export("memory")
        .ok_or(anyhow::anyhow!("memory export not found"))?
        .into_memory()
        .ok_or(anyhow::anyhow!("memory export not a Memory"))?;
    mem.write(&mut *caller, 4, &v.len().to_le_bytes())
        .map_err(|_| anyhow::anyhow!("failed to write ArrayBuffer"))?;
    mem.write(&mut *caller, v.len() + 4, v.as_slice())
        .map_err(|_| anyhow::anyhow!("failed to write ArrayBuffer"))?;
    return Ok(result[0]
        .i32()
        .ok_or(anyhow::anyhow!("result was not an i32"))?
        + 4);
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
                        }
                        Err(e) => println!("{}", e),
                    };
                }
            }
        }
    }
    Ok(())
}
