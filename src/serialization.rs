use ruint::Uint;
use anyhow::{Result};
use std::ffi::CStr;

pub type U256 = Uint<256, 4>;

pub struct BytesWriter(pub Vec<u8>);

enum OpnetBufferDataType {
    U8 = 0,
    U16 = 1,
    U32 = 2,
    U64 = 3,
    U256 = 4,
    ADDRESS = 5,
    STRING = 6,
    BOOLEAN = 7,
}

pub type Selector = u32;
pub type Address = Vec<u8>;

impl BytesWriter {
    pub fn buffer_length(&self) -> usize {
        self.0.len()
    }
    pub fn write_u8(&mut self, v: u8) {
        self.0.push(OpnetBufferDataType::U8 as u8);
        self.0.extend(v.to_be_bytes());
    }
    pub fn write_u16(&mut self, v: u16) {
        self.0.push(OpnetBufferDataType::U16 as u8);
        self.0.extend(v.to_be_bytes());
    }
    pub fn write_u32(&mut self, v: u32) {
        self.0.push(OpnetBufferDataType::U32 as u8);
        self.0.extend(v.to_be_bytes());
    }
    pub fn write_u64(&mut self, v: u32) {
        self.0.push(OpnetBufferDataType::U64 as u8);
        self.0.extend(v.to_be_bytes());
    }
    pub fn write_u256(&mut self, v: &U256) {
        self.0.push(OpnetBufferDataType::U256 as u8);
        self.0.extend::<[u8; 32]>(v.to_be_bytes());
    }
    pub fn write_selector(&mut self, v: Selector) {
        self.write_u32(v.into());
    }
    pub fn write_boolean(&mut self, v: bool) {
        self.write_u8(if v { 1 } else { 0 });
    }
    pub fn write_tuple(&mut self, ary: &Vec<U256>) {
        self.write_u32(ary.len().try_into().unwrap());
        ary.iter().for_each(|v: &U256| {
            self.write_u256(v);
        });
    }
    pub fn write_bytes(&mut self, ary: &[u8]) {
        self.0.extend(ary);
    }
    pub fn write_bytes_with_length(&mut self, ary: &[u8]) {
        self.write_u32(ary.len().try_into().unwrap());
        self.write_bytes(ary);
    }
    pub fn write_string(&mut self, v: &String) {
        self.write_u8(OpnetBufferDataType::STRING as u8);
        self.write_bytes(v.as_str().as_bytes());
    }
    pub fn write_address(&mut self, v: &Address) {
        self.write_u8(OpnetBufferDataType::ADDRESS as u8);
        self.write_bytes(&self.from_address(v));
    }
    pub fn from_address(&self, _v: &Address) -> Vec<u8> {
        vec![]
    }
    pub fn write_string_with_length(&mut self, v: &String) {
        self.write_u16(v.len().try_into().unwrap());
        self.write_string(v);
    }
}

pub struct BytesReader<'a> {
  pub slice: &'a [u8],
  pub pos: usize
}

const ADDRESS_BYTE_LENGTH: usize = 66;

unsafe fn str_from_null_terminated_utf8(s: *const u8) -> Result<String, anyhow::Error> {
  Ok(CStr::from_ptr(s as *const i8).to_str()?.to_string())
}

impl<'a> BytesReader<'a> {
  pub fn from(slice: &'a [u8]) -> Self {
    Self {
      slice,
      pos: 0
    }
  }
  pub fn read_u8(&mut self) -> Result<u8> {
    let value = u8::from_be_bytes((&self.slice[(self.pos)..(self.pos + 1)]).try_into()?);
    self.pos = self.pos + 1;
    Ok(value)
  }
  pub fn read_u16(&mut self) -> Result<u16> {
    let value = u16::from_be_bytes((&self.slice[(self.pos)..(self.pos + 2)]).try_into()?);
    self.pos = self.pos + 2;
    Ok(value)
  }
  pub fn read_u32(&mut self) -> Result<u32> {
    let value = u32::from_be_bytes((&self.slice[(self.pos)..(self.pos + 4)]).try_into()?);
    self.pos = self.pos + 4;
    Ok(value)
  }
  pub fn read_u64(&mut self) -> Result<u64> {
    let value = u64::from_be_bytes((&self.slice[(self.pos)..(self.pos + 8)]).try_into()?);
    self.pos = self.pos + 8;
    Ok(value)
  }
  pub fn read_u256(&mut self) -> Result<U256> {
    let value = U256::from_be_bytes::<32>((&self.slice[(self.pos)..(self.pos + 32)]).try_into()?);
    self.pos = self.pos + 32;
    Ok(value)
  }
  pub fn read_string(&mut self, _len: usize) -> Result<String> {
    let value = unsafe { str_from_null_terminated_utf8((&self.slice[(self.pos)..]).as_ptr() as *const u8)? };
    self.pos = self.pos + value.as_str().as_bytes().to_vec().len();
    Ok(value)
  }
  pub fn read_address(&mut self) -> Result<String> {
    self.read_string(ADDRESS_BYTE_LENGTH)
  }
  pub fn read_bytes(&mut self, length: usize) -> Result<Vec<u8>> {
    let result = (&self.slice[(self.pos)..(self.pos + length)]).try_into()?;
    self.pos = self.pos + length;
    return Ok(result);
  }
  pub fn read_bytes_with_length(&mut self) -> Result<Vec<u8>> {
    let length = self.read_u32()?;
    self.read_bytes(length.try_into()?)
  }
}


