use ruint::Uint;

pub type U256 = Uint<256, 4>;

pub struct OpnetBytes(pub Vec<u8>);

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

impl OpnetBytes {
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
    pub fn from_address(&self, v: &Address) -> Vec<u8> {
        vec![]
    }
    pub fn write_string_with_length(&mut self, v: &String) {
        self.write_u16(v.len().try_into().unwrap());
        self.write_string(v);
    }
}
