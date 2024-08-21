pub trait ByteView {
    fn from_bytes(v: Vec<u8>) -> Self;
    fn to_bytes(v: Self) -> Vec<u8>;
    fn maximum() -> Self;
}

pub fn shrink_back(b: Vec<u8>, v: usize) -> Vec<u8> {
    let mut _vec = b.clone();
    if b.len() >= v {
        _vec.clear()
    }
    _vec.drain(0..v);
    _vec
}

impl ByteView for u8 {
    fn to_bytes(v: u8) -> Vec<u8> {
        Vec::<u8>::from(v.to_le_bytes())
    }
    fn from_bytes(v: Vec<u8>) -> u8 {
        u8::from_le_bytes(v.as_slice().try_into().expect("incorrect length"))
    }
    fn maximum() -> u8 {
        u8::MAX
    }
}

impl ByteView for u16 {
    fn to_bytes(v: u16) -> Vec<u8> {
        Vec::<u8>::from(v.to_le_bytes())
    }
    fn from_bytes(v: Vec<u8>) -> u16 {
        u16::from_le_bytes(v.as_slice().try_into().expect("incorrect length"))
    }
    fn maximum() -> u16 {
        u16::MAX
    }
}

impl ByteView for u32 {
    fn to_bytes(v: u32) -> Vec<u8> {
        Vec::<u8>::from(v.to_le_bytes())
    }
    fn from_bytes(v: Vec<u8>) -> u32 {
        u32::from_le_bytes(v.as_slice().try_into().expect("incorrect length"))
    }
    fn maximum() -> u32 {
        u32::MAX
    }
}

impl ByteView for u64 {
    fn to_bytes(v: u64) -> Vec<u8> {
        Vec::<u8>::from(v.to_le_bytes())
    }
    fn from_bytes(v: Vec<u8>) -> u64 {
        u64::from_le_bytes(v.as_slice().try_into().expect("incorrect length"))
    }
    fn maximum() -> u64 {
        u64::MAX
    }
}

impl ByteView for u128 {
    fn to_bytes(v: u128) -> Vec<u8> {
        let _x = v.to_le_bytes();
        Vec::<u8>::from(v.to_le_bytes())
    }
    fn from_bytes(v: Vec<u8>) -> u128 {
        u128::from_le_bytes(v.as_slice().try_into().expect("incorrect length"))
    }
    fn maximum() -> u128 {
        u128::MAX
    }
}

impl ByteView for usize {
    fn to_bytes(v: usize) -> Vec<u8> {
        Vec::<u8>::from(v.to_le_bytes())
    }
    fn from_bytes(v: Vec<u8>) -> usize {
        usize::from_le_bytes(v.as_slice().try_into().expect("incorrect length"))
    }

    fn maximum() -> usize {
        usize::MAX
    }
}
