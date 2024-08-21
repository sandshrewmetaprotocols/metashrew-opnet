extern crate alloc;
use bitcoin::blockdata::block::Block;
use bitcoin::consensus::Decodable;
use bitcoin::hashes::Hash;
use std::collections::HashMap;
use std::fmt::Write;
use std::panic;
use std::sync::Arc;

mod bst;
mod byte_view;
mod compat;
mod envelope;
mod index_pointer;
mod opnet;
mod serialization;
mod stdio;
use crate::bst::BST;
use crate::compat::{panic_hook, to_arraybuffer_layout, to_ptr};
use crate::index_pointer::IndexPointer;
use crate::opnet::index_block;
use crate::stdio::stdout;

#[link(wasm_import_module = "env")]
extern "C" {
    fn __host_len() -> i32;
    fn __flush(ptr: i32);
    fn __get(ptr: i32, v: i32);
    fn __get_len(ptr: i32) -> i32;
    fn __load_input(ptr: i32);
}

static mut CACHE: Option<HashMap<Arc<Vec<u8>>, Arc<Vec<u8>>>> = None;
static mut TO_FLUSH: Option<Vec<Arc<Vec<u8>>>> = None;

pub fn get(v: Arc<Vec<u8>>) -> Arc<Vec<u8>> {
    unsafe {
        if CACHE.as_ref().unwrap().contains_key(&v.clone()) {
            return CACHE.as_ref().unwrap().get(&v.clone()).unwrap().clone();
        }
        let mut key = to_arraybuffer_layout(v.clone());
        let mut value = to_arraybuffer_layout(Arc::new(Vec::<u8>::with_capacity(__get_len(
            to_ptr(&mut key) + 4,
        )
            as usize)));
        __get(to_ptr(&mut key) + 4, to_ptr(&mut value) + 4);
        let result = Arc::<Vec<u8>>::new(value[4..].to_vec());
        CACHE.as_mut().unwrap().insert(v.clone(), result.clone());
        return result.clone();
    }
}

pub fn set(k: Arc<Vec<u8>>, v: Arc<Vec<u8>>) {
    unsafe {
        CACHE.as_mut().unwrap().insert(k.clone(), v.clone());
        TO_FLUSH.as_mut().unwrap().push(k.clone());
    }
}

pub fn flush() {
    unsafe {
        let mut to_encode: Vec<Vec<u8>> = Vec::<Vec<u8>>::new();
        for item in TO_FLUSH.as_ref().unwrap() {
            to_encode.push((*item.clone()).clone());
            to_encode.push((*(CACHE.as_ref().unwrap().get(item).unwrap().clone())).clone());
        }
        TO_FLUSH = Some(Vec::<Arc<Vec<u8>>>::new());
        let serialized = rlp::encode_list::<Vec<u8>, Vec<u8>>(to_encode.as_slice()).to_vec();
        __flush(to_ptr(&mut to_arraybuffer_layout(Arc::new(serialized.to_vec()))) + 4);
    }
}

pub fn input() -> Vec<u8> {
    unsafe {
        let length: i32 = __host_len().into();
        let mut buffer = Vec::<u8>::new();
        buffer.extend_from_slice(&length.to_le_bytes());
        buffer.resize((length as usize) + 4, 0);
        __load_input(to_ptr(&mut buffer) + 4);
        return buffer[4..].to_vec();
    }
}

fn initialize() -> () {
    unsafe {
        if CACHE.is_none() {
            CACHE = Some(HashMap::<Arc<Vec<u8>>, Arc<Vec<u8>>>::new());
            panic::set_hook(Box::new(panic_hook));
        }
        TO_FLUSH = Some(Vec::<Arc<Vec<u8>>>::new());
    }
}

#[no_mangle]
pub extern "C" fn _start() -> () {
    initialize();
    let data = input();
    let mut reader = &data[4..];
    index_block(Block::consensus_decode(&mut reader).unwrap()).unwrap();
    flush();
}

#[no_mangle]
pub extern "C" fn _test() -> () {
    initialize();
    let data = input();
    let mut reader = &data[4..];
    let _bst = BST::<u8>::new(IndexPointer::from_keyword("test"));
    let block = Block::consensus_decode(&mut reader).unwrap();
    set(
        Arc::new(block.block_hash().as_byte_array().to_vec()),
        Arc::new(data[4..].to_vec()),
    );
    println!(
        "{:x?}",
        get(Arc::new(block.block_hash().as_byte_array().to_vec()))
    );
    flush();
}
