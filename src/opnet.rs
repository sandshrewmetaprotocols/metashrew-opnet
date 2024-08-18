use crate::envelope::RawEnvelope;
use crate::index_pointer::IndexPointer;
use anyhow;
use bitcoin::blockdata::{block::Block, transaction::Transaction};
use bitcoin::script::Script;
use hex;
use metashrew_runtime::runtime::read_arraybuffer_as_vec;
use std::sync::Arc;

pub fn index_block(block: Block) -> Result<(), anyhow::Error> {
    for transaction in &block.txdata {
        index_transaction(&transaction)?;
    }
    Ok(())
}

struct OpnetContract(wasmi::Instance);

type HostState = u32;

/*
impl OpnetContract {
    pub fn load(address: Vec<u8>, program: &Vec<u8>) -> Result<Self, anyhow::Error> {
        let engine = wasmi::Engine::default();
        let store = Store::<HostState>::new(&engine, 0);
        let linker: Linker<HostState> = Linker::<HostState>::new(&engine);
        linker.func_wrap(
            "abort",
            |mut caller: Caller<'_, State>, _: i32, _: i32, _: i32, _: i32| {
                // handle abort
            },
        );
        linker.func_wrap("sha256", |mut caller: Caller<'_, State>, v: i32| -> i32 {
            // handle sha256
        });
        linker.func_wrap("load", |mut caller: Caller<'_, State>, v: i32| -> i32 {
            let mem = caller.get_export("memory").unwrap().into_memory().unwrap();
            let data = mem.data(&caller);
            IndexPointer::from_keyword("/storage/")
                .select(Arc::new(address.clone()))
                .keyword("/")
                .select(read_arraybuffer_as_vec(data, v))
                .get();
            // TODO: return value from storage
        });
        linker.func_wrap("store", |mut caller: Caller<'_, State>, k: i32, v: i32| {
            let mem = caller.get_export("memory").unwrap().into_memory().unwrap();
            let data = mem.data(&caller);
            IndexPointer::from_keyword("/storage/")
                .select(Arc::new(address.clone()))
                .keyword("/")
                .select(read_arraybuffer_as_vec(data, k))
                .set(read_arraybuffer_as_vec(data, v));
        });
        linker.func_wrap(
            "defineSelectors",
            |mut caller: Caller<'_, State>, v: i32| {},
        );
        linker.func_wrap("readMethod", |mut caller: Caller<'_, State>, v: i32| {});
        linker.func_wrap("readView", |mut caller: Caller<'_, State>, v: i32| {});
        linker.func_wrap("getEvents", |mut caller: Caller<'_, State>, v: i32| {});
        linker.func_wrap("getViewABI", |mut caller: Caller<'_, State>, v: i32| {});
        linker.func_wrap("getMethodABI", |mut caller: Caller<'_, State>, v: i32| {});
        linker.func_wrap(
            "getWriteMethods",
            |mut caller: Caller<'_, State>, v: i32| {},
        );
        linker.func_wrap("setEnvironment", |mut caller: Caller<'_, State>, v: i32| {});
        Ok(linker.instantiate(&mut store, &module)?)
    }
}
*/

pub fn index_transaction(transaction: &Transaction) -> Result<(), anyhow::Error> {
    for envelope in RawEnvelope::from_transaction(transaction) {
        let payload: Arc<Vec<u8>> =
            Arc::new(envelope.payload.clone().into_iter().flatten().collect());
        if payload.len() > 0 {
            println!("{}", hex::encode(&envelope.payload[0]));
            let address: Vec<u8> = vec![];//transaction.output[0].into_address();
            IndexPointer::from_keyword("/programs/")
                .select(&address)
                .set(payload.clone());
        }
    }
    Ok(())
}
