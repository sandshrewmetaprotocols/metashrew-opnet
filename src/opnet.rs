use crate::envelope::RawEnvelope;
use crate::index_pointer::IndexPointer;
use anyhow;
use bitcoin::blockdata::{block::Block, transaction::Transaction};
use bitcoin::script::Script;
use hex;
use std::sync::Arc;
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

struct OpnetContract(wasmi::InstancePre);

struct State {
    address: Vec<u8>,
}

impl OpnetContract {
    pub fn load(address: Vec<u8>, program: &Vec<u8>) -> Result<Self, anyhow::Error> {
        let engine = Engine::default();
        let mut store = Store::<State>::new(
            &engine,
            State {
                address: address.clone(),
            },
        );
        let cloned = program.clone();
        let module = Module::new(&engine, &mut &cloned[..])?;
        let mut linker: Linker<State> = Linker::<State>::new(&engine);
        let address_ref1 = Arc::new(address.clone());
        let address_ref2 = address_ref1.clone();
        linker.func_wrap(
            "env",
            "abort",
            |mut caller: Caller<'_, State>, _: i32, _: i32, _: i32, _: i32| {
                // handle abort
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
                let data = mem.data(&caller);
                IndexPointer::from_keyword("/storage/")
                    .select(&vec![0x01]) // use state.address
                    .keyword("/")
                    .select(&read_arraybuffer_as_vec(data, v))
                    .get();
                // TODO: return value from storage
                0
            },
        )?;
        linker.func_wrap(
            "env",
            "store",
            |mut caller: Caller<'_, State>, k: i32, v: i32| {
                let mem = caller.get_export("memory").unwrap().into_memory().unwrap();
                let data = mem.data(&caller);
                IndexPointer::from_keyword("/storage/")
                    .select(&vec![0x01]) // use state.address
                    .keyword("/")
                    .select(&read_arraybuffer_as_vec(data, k))
                    .set(Arc::new(read_arraybuffer_as_vec(data, v)));
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
        Ok(OpnetContract(linker.instantiate(&mut store, &module)?))
    }
}

pub fn index_transaction(transaction: &Transaction) -> Result<(), anyhow::Error> {
    for envelope in RawEnvelope::from_transaction(transaction) {
        let payload: Arc<Vec<u8>> =
            Arc::new(envelope.payload.clone().into_iter().flatten().collect());
        if payload.len() > 0 {
            println!("{}", hex::encode(&envelope.payload[0]));
            let address: Vec<u8> = vec![]; //transaction.output[0].into_address();
            IndexPointer::from_keyword("/programs/")
                .select(&address)
                .set(payload.clone());
        }
    }
    Ok(())
}
