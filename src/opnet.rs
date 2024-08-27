use crate::envelope::RawEnvelope;
use crate::index_pointer::IndexPointer;
use bech32::{hrp, segwit};
use bitcoin::blockdata::{block::Block, transaction::Transaction};

use bitcoin::Amount;

use crate::serialization::{BytesReader, BytesWriter, U256};
use anyhow::{anyhow, Result};
use libflate::zlib::Decoder;
use ripemd::Ripemd160;
use sha3::{Digest, Sha3_256};
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::sync::{Arc, Mutex};
use wasmi::*;
//use wasmi::module::utils::WasmiValueType;
//
const MAX_EVENT_DATA_SIZE: u32 = 352; // 352 bytes max per event.
const MAX_EVENTS: u16 = 1000; // 1000 events max per transactions.

pub fn index_block(height: u32, block: Block) -> Result<()> {
    for transaction in &block.txdata {
        index_transaction(height, block.header.time as u64, &transaction)?;
    }
    Ok(())
}

pub fn read_arraybuffer(data: &[u8], data_start: i32) -> Result<Vec<u8>> {
    if data_start < 4 {
        return Err(anyhow::anyhow!("memory error"));
    }
    let len =
        u32::from_le_bytes((data[((data_start - 4) as usize)..(data_start as usize)]).try_into()?);
    return Ok(Vec::<u8>::from(
        &data[(data_start as usize)..(((data_start as u32) + len) as usize)],
    ));
}

#[derive(Default, Clone)]
struct OpnetEnvironment {
    pub current_block: u64,
    pub timestamp: u64,
    pub caller: Vec<u8>,
    pub callee: Vec<u8>,
    pub owner: Vec<u8>,
    pub contract_address: Vec<u8>,
}

impl Into<Vec<u8>> for OpnetEnvironment {
    fn into(self) -> Vec<u8> {
        let mut writer = BytesWriter::default();
        writer.write_address(&self.caller);
        writer.write_address(&self.callee);
        writer.write_u64(self.current_block);
        writer.write_address(&self.owner);
        writer.write_address(&self.contract_address);
        writer.write_u64(self.timestamp);
        writer.0
    }
}

impl OpnetEnvironment {
    pub fn from<'a>(reader: &mut BytesReader<'a>) -> Result<OpnetEnvironment> {
        let caller: Vec<u8> = reader.read_address()?.into();
        let callee: Vec<u8> = reader.read_address()?.into();
        let current_block: u64 = reader.read_u64()?;
        let owner: Vec<u8> = reader.read_address()?.into();
        let contract_address: Vec<u8> = reader.read_address()?.into();
        let timestamp: u64 = reader.read_u64()?;
        Ok(OpnetEnvironment {
            current_block,
            timestamp,
            caller,
            callee,
            owner,
            contract_address,
        })
    }
    pub fn set_callee(&mut self, v: &Vec<u8>) {
        self.callee = v.clone();
    }
    pub fn set_caller(&mut self, v: &Vec<u8>) {
        self.caller = v.clone();
    }
    pub fn set_owner(&mut self, v: &Vec<u8>) {
        self.owner = v.clone();
    }
    pub fn set_contract_address(&mut self, v: &Vec<u8>) {
        self.contract_address = v.clone();
    }
    pub fn set_timestamp(&mut self, v: u64) {
        self.timestamp = v;
    }
    pub fn set_current_block(&mut self, v: u64) {
        self.current_block = v;
    }
}

struct OpnetContract {
    instance: Instance,
    store: Store<State>,
    storage: Arc<Mutex<StorageView>>,
}

struct State {
    had_failure: bool,
    storage: Arc<Mutex<StorageView>>,
    events: Vec<OpnetEvent>,
    call_stack: HashSet<Vec<u8>>,
    environment: OpnetEnvironment,
    limiter: StoreLimits,
}

const MEMORY_LIMIT: usize = 33554432;

pub struct OpnetHostFunctionsImpl(());

pub fn get_memory<'a>(caller: &mut Caller<'_, State>) -> Result<Memory> {
    caller
        .get_export("memory")
        .ok_or(anyhow!("export was not memory region"))?
        .into_memory()
        .ok_or(anyhow!("export was not memory region"))
}

fn to_segwit_address(v: &[u8]) -> Result<Vec<u8>> {
    segwit::encode(hrp::BC, segwit::VERSION_1, v)
        .map(|v| v.as_str().as_bytes().to_vec())
        .map_err(|_| anyhow!("segwit address encode failed"))
}

#[derive(Default, Clone)]
pub struct StorageView {
    pub global: GlobalStorageView,
    pub contract: ContractStorageView,
}

pub fn get_contract_seed(deployer_pubkey: &Vec<u8>, bytecode: &Vec<u8>, salt_hash: &Vec<u8>) -> Vec<u8> {
  let mut hasher = Sha3_256::new();
  hasher.update(bytecode);
  let hash: Vec<u8> = hasher.finalize().to_vec();
  hasher = Sha3_256::new();
  let mut buffer = deployer_pubkey.clone();
  buffer.extend(salt_hash);
  buffer.extend(&hash);
  hasher.update(&buffer);
  hasher.finalize().to_vec()
}

impl StorageView {
    pub fn commit(&mut self) {
        self.global.merge(&self.contract);
    }
}

impl OpnetHostFunctionsImpl {
    fn _abort<'a>(caller: Caller<'_, State>) {
        OpnetHostFunctionsImpl::abort(caller, 0, 0, 0, 0);
    }
    fn abort<'a>(mut caller: Caller<'_, State>, _: i32, _: i32, _: i32, _: i32) {
        caller.data_mut().had_failure = true;
    }
    fn sha256<'a>(caller: &mut Caller<'_, State>, v: i32) -> Result<i32> {
        // handle sha256
        let mut hasher = Sha3_256::new();
        let mem = get_memory(caller)?;
        hasher.update(read_arraybuffer(mem.data(&caller), v)?);
        send_to_arraybuffer(caller, &hasher.finalize().to_vec())
    }
    fn load<'a>(caller: &mut Caller<'_, State>, k: i32) -> Result<i32> {
        let mem = get_memory(caller)?;
        let key = {
            let data = mem.data(&caller);
            BytesReader::from(&read_arraybuffer(data, k)?).read_u256()?
        };
        let value = caller
            .data_mut()
            .storage
            .lock()
            .unwrap()
            .contract
            .get(&(&key.to_be_bytes::<32>()).try_into()?);
        send_to_arraybuffer(caller, &value)
    }
    fn store<'a>(caller: &mut Caller<'_, State>, k: i32) -> Result<()> {
        let mem = get_memory(caller)?;
        let (key, value) = {
            let buffer = read_arraybuffer(mem.data(&caller), k)?;
            let mut reader = BytesReader::from(&buffer);
            (reader.read_u256()?, reader.read_u256()?)
        };
        caller.data_mut().storage.lock().unwrap().contract.set(
            &(&key.to_be_bytes::<32>()).try_into()?,
            &(&value.to_be_bytes::<32>()).try_into()?,
        );
        Ok(())
    }
    fn call<'a>(caller: &mut Caller<'_, State>, data: i32) -> Result<i32> {
        let buffer = read_arraybuffer(get_memory(caller)?.data(&caller), data)?;
        let mut reader = BytesReader::from(&buffer);
        let (contract_address, calldata): (Vec<u8>, Vec<u8>) = (
            reader.read_address()?.as_str().as_bytes().to_vec(),
            reader.read_bytes_with_length()?,
        );
        if let Some(_v) = caller.data().call_stack.get(&contract_address) {
            return Err(anyhow!("failure -- reentrancy guard"));
        }
        let mut vm = OpnetContract::get(
            &contract_address,
            Arc::new(Mutex::new(caller.data_mut().storage.lock().unwrap().clone()))
        )?.ok_or("").map_err(|_| {
            match String::from_utf8(contract_address.clone()) {
              Ok(v) => anyhow!(format!("failed to call non-existent contract at address {}", v)),
              Err(_) => anyhow!("failed to convert contract address from utf-8")
            }
        })?;
        {
          let mut environment = caller.data_mut().environment.clone();
          environment.set_contract_address(&contract_address.clone());
          vm.store.data_mut().environment = environment;
        }
        OpnetExportsImpl::set_environment(&mut vm)?;
        let call_response = vm.run(calldata)?;
        vm.store.data_mut().storage = call_response.storage.clone();
        vm.store.data_mut().events = call_response.events;
        vm.consume_fuel(call_response.gas_used)?;
        send_to_arraybuffer(caller, &call_response.response)
        // TODO: encode response
    }
    fn log<'a>(caller: &mut Caller<'_, State>, v: i32) -> Result<()> {
        crate::stdio::log({
            let mem = get_memory(caller)?;
            Arc::new(read_arraybuffer(mem.data(&caller), v)?)
        });
        Ok(())
    }
    fn encode_address(caller: &mut Caller<'_, State>, v: i32) -> Result<i32> {
        let mem = get_memory(caller)?;
        let input =
            BytesReader::from(&read_arraybuffer(mem.data(&caller), v)?).read_bytes_with_length()?;
        send_to_arraybuffer(caller, &script_pubkey_to_address(&input)?)
    }
    fn deploy_from_address<'a>(caller: &mut Caller<'_, State>, v: i32) -> Result<i32> {
        let mem = get_memory(caller)?;
        let (existing_address, salt) = {
          let input = read_arraybuffer(mem.data(&caller), v)?;
          let mut reader = BytesReader::from(&input);
          (reader.read_address()?.as_str().as_bytes().to_vec(), reader.read_bytes(32)?)
        };
        let saved = IndexPointer::from_keyword("/contracts/")
            .select(&existing_address)
            .get();
        if saved.len() == 0 {
          return Err(anyhow!(format!("no contract storedf at {}", hex::encode(existing_address))));
        }
        let virtual_address = get_contract_seed(&caller.data().environment.contract_address.clone(), &saved, &salt);
        let contract_address = script_pubkey_to_address(&virtual_address)?;
        let ptr = IndexPointer::from_keyword("/contracts/").select(&contract_address);
        let bytearray = ptr.get();
        if bytearray.len() != 0 {
          Err(anyhow!(format!("contract already deployed to {}", hex::encode(&contract_address))))
        } else {
          Ok(())
        }?;
        ptr.set(saved);
        let mut writer = BytesWriter::default();
        writer.write_u256(&U256::from_be_bytes::<32>(virtual_address.as_slice().try_into()?));
        writer.write_address(&contract_address);
        send_to_arraybuffer(caller, &writer.0)
    }
}

fn script_pubkey_to_address(input: &[u8]) -> Result<Vec<u8>> {
    let mut hasher = Ripemd160::new();
    hasher.update(&input);
    to_segwit_address(&hasher.finalize())
}

struct CallResponse {
    pub response: Vec<u8>,
    pub events: Vec<OpnetEvent>,
    pub storage: Arc<Mutex<StorageView>>,
    pub gas_used: u64
}

pub struct OpnetExportsImpl(());

#[derive(Clone)]
pub struct OpnetEvent {
    pub data: Vec<u8>,
    pub selector: u64,
    pub event_type: String,
}

impl OpnetExportsImpl {
    pub fn _get_sdk_export(vm: &mut OpnetContract, name: &str) -> Result<Func> {
        let instance: &mut Instance = &mut vm.instance;
        let store: &mut Store<State> = &mut vm.store;
        Ok(instance.get_func(store, name).ok_or("").map_err(|_| {
            anyhow!(format!(
                "{} not found -- is this WASM built with the OP_NET SDK?",
                name
            ))
        })?)
    }
    pub fn _get_sdk_result(vm: &mut OpnetContract, result: &[Val; 1]) -> Result<Vec<u8>> {
        vm.read_arraybuffer(
            result[0]
                .i32()
                .ok_or("")
                .map_err(|_| anyhow!("result is not an i32"))?,
        )
    }
    pub fn read_method(vm: &mut OpnetContract, method: u32, data: &Vec<u8>) -> Result<Vec<u8>> {
        let mut result = [Val::I32(0)];
        let func = Self::_get_sdk_export(vm, "readMethod")?;
        let arg2 = vm.send_to_arraybuffer(data)?;
        func.call(
            &mut vm.store,
            &[Val::I32(method as i32), Val::I32(arg2)],
            &mut result,
        )?;
        Self::_get_sdk_result(vm, &result)
    }
    pub fn read_view(vm: &mut OpnetContract, method: u32) -> Result<Vec<u8>> {
        let mut result = [Val::I32(0)];
        let func = Self::_get_sdk_export(vm, "readView")?;
        func.call(&mut vm.store, &[Val::I32(method as i32)], &mut result)?;
        Self::_get_sdk_result(vm, &result)
    }
    pub fn get_events(vm: &mut OpnetContract) -> Result<Vec<OpnetEvent>> {
        let mut result: [Val; 1] = [Val::I32(0)];

        let func = Self::_get_sdk_export(vm, "getEvents")?;
        func.call(&mut vm.store, &[], &mut result)?;
        let buffer = Self::_get_sdk_result(vm, &result)?;
        let mut reader = BytesReader::from(&buffer);
        let length = reader.read_u16()?;
        let mut events: Vec<OpnetEvent> = vec![];
        for i in (0..length) {
            let event_type: String = reader.read_string_with_length()?;
            let selector: u64 = reader.read_u64()?;
            let data: Vec<u8> = reader.read_bytes_with_length()?;
            if (data.len() > MAX_EVENT_DATA_SIZE as usize) {
                return Err(anyhow!("exceeded MAX_EVENT_DATA_SIZE"));
            }
            events.push(OpnetEvent {
                event_type,
                selector,
                data,
            });
        }
        Ok(events)
    }
    pub fn get_view_abi(vm: &mut OpnetContract) -> Result<Vec<u32>> {
        Self::_get_abi(vm, "getViewABI")
    }
    pub fn _get_abi(vm: &mut OpnetContract, name: &str) -> Result<Vec<u32>> {
        let mut result = [Val::I32(0)];

        let func = Self::_get_sdk_export(vm, name)?;
        func.call(&mut vm.store, &[], &mut result)?;
        let buffer = Self::_get_sdk_result(vm, &result)?;
        let mut reader = BytesReader::from(&buffer);
        let length = reader.read_u16()?;
        let mut result: Vec<u32> = vec![];
        for i in (0..length) {
            result.push(reader.read_u32()?);
        }
        Ok(result)
    }
    pub fn get_method_abi(vm: &mut OpnetContract) -> Result<Vec<u32>> {
        Self::_get_abi(vm, "getMethodABI")
    }
    pub fn get_write_methods(vm: &mut OpnetContract) -> Result<Vec<u32>> {
        Self::_get_abi(vm, "getWriteMethods")
    }
    pub fn set_environment(vm: &mut OpnetContract) -> Result<()> {
        let ptr: i32 = {
            let input: Vec<u8> = vm.store.data_mut().environment.clone().into();
            vm.send_to_arraybuffer(&input)?
        };
        Ok(Self::_get_sdk_export(vm, "setEnvironment")?.call(
            &mut vm.store,
            &[Val::I32(ptr)],
            &mut [],
        )?)
    }
}

impl OpnetContract {
    pub fn consume_fuel(&mut self, fuel: u64) -> Result<()> {
      let fuel_remaining = self.store.get_fuel().unwrap();
      if fuel_remaining < fuel {
          Err(anyhow!(format!("{} gas remaining but {} consumed by call", fuel_remaining, fuel)))
      } else {
          self.store.set_fuel(fuel_remaining - fuel).unwrap();
          Ok(())
      }
    }
    pub fn read_arraybuffer(&mut self, data_start: i32) -> anyhow::Result<Vec<u8>> {
        read_arraybuffer(self.get_memory()?.data(&self.store), data_start)
    }
    pub fn get_memory(&mut self) -> anyhow::Result<Memory> {
        self.instance
            .get_memory(&mut self.store, "memory")
            .ok_or("")
            .map_err(|_| anyhow!("memory segment not found"))
    }
    pub fn send_to_arraybuffer(&mut self, v: &Vec<u8>) -> anyhow::Result<i32> {
        let mut result = [Val::I32(0)];
        self.instance
            .get_func(&mut self.store, "__new")
            .ok_or("")
            .map_err(|_| {
                anyhow!("__new export not found -- is this WASM built with --exportRuntime?")
            })?
            .call(
                &mut self.store,
                &[Val::I32(v.len().try_into()?)],
                &mut result,
            )?;
        let ptr: usize = result[0]
            .i32()
            .ok_or("")
            .map_err(|_| anyhow!("result of __new is not an i32"))?
            as usize;
        let mem = self.get_memory()?;
        mem.write(&mut self.store, ptr, &v.len().to_le_bytes())
            .map_err(|_| anyhow!("failed to write ArrayBuffer"))?;
        mem.write(&mut self.store, ptr + 4, v.as_slice())
            .map_err(|_| anyhow!("failed to write ArrayBuffer"))?;
        Ok((ptr + 4).try_into()?)
    }
    pub fn get(address: &Vec<u8>, storage: Arc<Mutex<StorageView>>) -> Result<Option<Self>> {
        let saved = IndexPointer::from_keyword("/contracts/")
            .select(address)
            .get();
        if saved.len() == 0 {
            Ok(None)
        } else {
            Ok(Some(Self::load_from_address(address, &saved, storage)?))
        }
    }
    pub fn set_callee(&mut self, address: &Vec<u8>) {
        self.store.data_mut().environment.set_callee(address);
    }
    pub fn set_caller(&mut self, address: &Vec<u8>) {
        self.store.data_mut().environment.set_caller(address);
    }
    pub fn checkpoint(&mut self) -> Arc<Mutex<StorageView>> {
        Arc::new(Mutex::new(
            self.store.data_mut().storage.lock().unwrap().clone(),
        ))
    }
    pub fn load(address: &Vec<u8>, program: &Vec<u8>) -> Result<Self> {
        let mut storage = StorageView::default();
        storage.global.lazy_load(address);
        storage.contract = storage.global.0.get(address).clone().unwrap().clone();
        return Self::load_from_address(address, program, Arc::new(Mutex::new(storage)));
    }
    pub fn load_from_address(
        address: &Vec<u8>,
        program: &Vec<u8>,
        storage: Arc<Mutex<StorageView>>,
    ) -> Result<Self> {
        let mut config = Config::default();
        config.consume_fuel(true);
        let engine = Engine::new(&config);
        let mut store = Store::<State>::new(
            &engine,
            State {
                environment: OpnetEnvironment::default(),
                events: vec![],
                had_failure: false,
                limiter: StoreLimitsBuilder::new().memory_size(MEMORY_LIMIT).build(),
                call_stack: HashSet::<Vec<u8>>::new(),
                storage: storage.clone(),
            },
        );
        store.limiter(|state| &mut state.limiter);
        Store::<State>::set_fuel(&mut store, 100000)?; // TODO: implement gas limits
        let cloned = program.clone();
        let module = Module::new(&engine, &mut &cloned[..])?;
        let mut linker: Linker<State> = Linker::<State>::new(&engine);
        linker.func_wrap("env", "abort", OpnetHostFunctionsImpl::abort)?;
        linker.func_wrap("env", "sha256", |mut caller: Caller<'_, State>, v: i32| {
            match OpnetHostFunctionsImpl::sha256(&mut caller, v) {
                Ok(v) => v,
                Err(_e) => {
                    OpnetHostFunctionsImpl::_abort(caller);
                    -1
                }
            }
        })?;
        linker.func_wrap("env", "load", |mut caller: Caller<'_, State>, k: i32| {
            match OpnetHostFunctionsImpl::load(&mut caller, k) {
                Ok(v) => v,
                Err(_e) => {
                    OpnetHostFunctionsImpl::_abort(caller);
                    -1
                }
            }
        })?;
        linker.func_wrap(
            "env",
            "store",
            |mut caller: Caller<'_, State>, data: i32| {
                if let Err(_e) = OpnetHostFunctionsImpl::store(&mut caller, data) {
                    OpnetHostFunctionsImpl::_abort(caller);
                }
            },
        )?;
        linker.func_wrap("env", "log", |mut caller: Caller<'_, State>, v: i32| {
            if let Err(_e) = OpnetHostFunctionsImpl::log(&mut caller, v) {
                OpnetHostFunctionsImpl::_abort(caller);
            }
        })?;
        linker.func_wrap(
            "env",
            "deployFromAddress",
            |mut caller: Caller<'_, State>, v: i32| {
                if let Err(_) = OpnetHostFunctionsImpl::deploy_from_address(&mut caller, v) {
                    OpnetHostFunctionsImpl::_abort(caller);
                }
            },
        )?;
        linker.func_wrap("env", "call", |mut caller: Caller<'_, State>, v: i32| {
            if let Err(e) = OpnetHostFunctionsImpl::call(&mut caller, v) {
                OpnetHostFunctionsImpl::_abort(caller);
            }
        })?;
        linker.func_wrap(
            "env",
            "encodeAddress",
            |mut caller: Caller<'_, State>, v: i32| -> i32 {
                match OpnetHostFunctionsImpl::encode_address(&mut caller, v) {
                    Ok(v) => v,
                    Err(_) => {
                        OpnetHostFunctionsImpl::_abort(caller);
                        -1
                    }
                }
            },
        )?;
        Ok(OpnetContract {
            instance: linker
                .instantiate(&mut store, &module)?
                .ensure_no_start(&mut store)?,
            store,
            storage
        })
    }
    pub fn reset(&mut self) {
        self.store.data_mut().had_failure = false;
    }
    pub fn run(&mut self, payload: Vec<u8>) -> Result<CallResponse, anyhow::Error> {
        let start_fuel = self.store.get_fuel()?;
        let selector: u32 = u32::from_be_bytes((&payload[0..4]).try_into()?);
        let calldata: Vec<u8> = (&payload[4..]).try_into()?;
        let call_response: Vec<u8> =
            if HashSet::<u32>::from_iter(OpnetExportsImpl::get_view_abi(self)?.into_iter())
                .contains(&selector)
            {
                OpnetExportsImpl::read_view(self, selector)?
            } else if HashSet::<u32>::from_iter(
                OpnetExportsImpl::get_write_methods(self)?.into_iter(),
            )
            .contains(&selector)
            {
                OpnetExportsImpl::read_method(self, selector, &calldata)?
            } else {
                return Err(anyhow!("OP_NET: method is not exported by contract"));
            };
        let had_failure = self.store.data().had_failure;
        self.reset();
        if had_failure {
            Err(anyhow!("OP_NET: revert"))
        } else {
            let checkpoint = {
              self.checkpoint()
            };
            let events = OpnetExportsImpl::get_events(self)?;
            let mut state: &mut State = self.store.data_mut();
            state.storage.lock().unwrap().commit();
            state.events.extend(events.clone());
            state.storage = checkpoint.clone();
            Ok(CallResponse {
                storage: checkpoint.clone(),
                response: call_response,
                events: events,
                gas_used: start_fuel - self.store.get_fuel()?,
            })
        }
    }
}

pub type Address = Vec<u8>;
pub type StorageCache = HashMap<Vec<u8>, Vec<u8>>;

#[derive(Default, Clone)]
pub struct ContractStorageView {
    cache: StorageCache,
    table: IndexPointer,
    address: Vec<u8>,
}

pub fn send_to_arraybuffer<'a>(caller: &mut Caller<'_, State>, v: &Vec<u8>) -> Result<i32> {
    let mut result = [Val::I32(0)];
    caller
        .get_export("__new")
        .ok_or(anyhow!(
            "__new export not found -- is this WASM built with --exportRuntime?"
        ))?
        .into_func()
        .ok_or(anyhow!("__new export not a Func"))?
        .call(&mut *caller, &[Val::I32(v.len().try_into()?)], &mut result)?;
    let mem = get_memory(caller)?;
    mem.write(&mut *caller, 4, &v.len().to_le_bytes())
        .map_err(|_| anyhow!("failed to write ArrayBuffer"))?;
    mem.write(&mut *caller, v.len() + 4, v.as_slice())
        .map_err(|_| anyhow!("failed to write ArrayBuffer"))?;
    return Ok(result[0].i32().ok_or(anyhow!("result was not an i32"))? + 4);
}

#[derive(Default, Clone)]
pub struct GlobalStorageView(pub HashMap<Vec<u8>, ContractStorageView>);

impl GlobalStorageView {
    pub fn lazy_load(&mut self, address: &Vec<u8>) {
        if !self.0.contains_key(address) {
            self.0
                .insert(address.clone(), ContractStorageView::at(address));
        }
    }
    pub fn merge(&mut self, view: &ContractStorageView) {
        self.lazy_load(&view.address);
        view.cache.clone().into_iter().for_each(|(k, v)| {
            self.0.get_mut(&view.address).unwrap().cache.insert(k, v);
        });
    }
    pub fn flush(&mut self) {
        self.0.iter_mut().for_each(|(_, v)| {
            v.flush();
        });
    }
}

impl ContractStorageView {
    pub fn at(address: &Vec<u8>) -> Self {
        let table = IndexPointer::from_keyword("/contracts/")
            .select(&address)
            .keyword("/storage/");
        ContractStorageView {
            cache: HashMap::<Vec<u8>, Vec<u8>>::new(),
            table,
            address: address.clone(),
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

pub fn index_transaction(height: u32, timestamp: u64, transaction: &Transaction) -> Result<()> {
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
            let address = script_pubkey_to_address(&script_pubkey)?;
            let table_entry = IndexPointer::from_keyword("/contracts/").select(&address);
            let program = table_entry.get();
            if program.len() == 0 {
                let mut buf = Vec::new();
                let cloned = payload.clone();
                let mut decoder: Decoder<&[u8]> = Decoder::new(&cloned[..])?;
                decoder.read_to_end(&mut buf)?;
                table_entry.set(Arc::new(buf));
            } else {
                if let Ok(mut vm) = OpnetContract::load(&address, &program) {
                    {
                        let environment: &mut OpnetEnvironment =
                            &mut vm.store.data_mut().environment;
                        environment.set_contract_address(&address);
                        environment.set_timestamp(timestamp);
                        environment.set_current_block(height as u64);
                        environment.set_callee(&address);
                        environment.set_caller(&address);
                        environment.set_owner(&address);
                        OpnetExportsImpl::set_environment(&mut vm)?
                    }
                    match vm.run((*payload).clone()) {
                        Ok(_response) => {
                            println!("OP_NET: transaction success");
                            vm.storage.lock().unwrap().global.flush(); // transaction success -- save updated storage slots
                        }
                        Err(e) => println!("{}", e),
                    };
                }
            }
        }
    }
    Ok(())
}
