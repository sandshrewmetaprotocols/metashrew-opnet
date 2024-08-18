use crate::stdio::log;
use std::panic;
use std::sync::Arc;
pub fn panic_hook(info: &panic::PanicInfo) {
    let _ = log(Arc::new(info.to_string().as_bytes().to_vec()));
}

pub fn to_ptr(v: &mut Vec<u8>) -> i32 {
    return v.as_mut_ptr() as usize as i32;
}
pub fn to_arraybuffer_layout(v: Arc<Vec<u8>>) -> Vec<u8> {
    let mut buffer = Vec::<u8>::new();
    buffer.extend_from_slice(&v.len().to_le_bytes());
    buffer.extend_from_slice(v.as_slice());
    return buffer;
}
