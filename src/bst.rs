use crate::byte_view::{shrink_back, ByteView};
use crate::IndexPointer;
use std::fmt::Debug;
use std::mem::size_of;
use std::sync::Arc;

//TODO: redo byteLen parts

#[derive(Debug, Clone)]
pub struct BST<K> {
    ptr: IndexPointer,
    _val: K,
}

pub fn mask_lower_than(v: Arc<Vec<u8>>, position: usize) -> Arc<Vec<u8>> {
    let mut ar: [u128; 2] = [0, 0];
    ar[0] = u128::from_le_bytes(v.clone().as_slice()[0..16].try_into().unwrap());
    ar[1] = u128::from_le_bytes(v.clone().as_slice()[16..32].try_into().unwrap());

    let bit_selected = u128::try_from(position % 128).unwrap();
    let byte_selected = position / 128;

    ar[byte_selected] = ar[byte_selected] & (((1 << bit_selected) - 1) << (128 - bit_selected));

    ar[!byte_selected] = 0;

    let _vec = ar
        .into_iter()
        .map(|v| v.to_le_bytes().to_vec())
        .flatten()
        .collect::<Vec<u8>>();
    Arc::from(_vec)
}

pub fn mask_greater_than(v: Arc<Vec<u8>>, position: usize) -> Arc<Vec<u8>> {
    let mut ar: [u128; 2] = [0, 0];
    ar[0] = u128::from_le_bytes(v.clone().as_slice()[0..16].try_into().unwrap());
    ar[1] = u128::from_le_bytes(v.clone().as_slice()[16..32].try_into().unwrap());

    let bit_selected = u128::try_from(position % 128).unwrap();
    let byte_selected = position / 128;

    ar[byte_selected] = ar[byte_selected] & ((1 << (bit_selected + 1)) - 1 << (127 - bit_selected));
    ar[!byte_selected] = 0;

    let _vec = ar
        .into_iter()
        .map(|v| v.to_le_bytes().to_vec())
        .flatten()
        .collect::<Vec<u8>>();
    Arc::from(_vec)
}

pub fn set_bit_u256(mut mask: Vec<u8>, position: usize) -> Arc<Vec<u8>> {
    let byte_position = position / 8;
    let bit_position = u8::try_from(position % 8).unwrap();

    let new_bit = u8::from(1) << (u8::from(7) - bit_position);

    mask[byte_position] = mask[byte_position] | new_bit;

    Arc::from(mask)
}

pub fn unset_bit_u256(mut mask: Vec<u8>, position: usize) -> Arc<Vec<u8>> {
    let byte_position = position / 8;
    let bit_position = u8::try_from(position % 8).unwrap();

    let new_bit = !(u8::from(1) << (u8::from(7) - bit_position));

    mask[byte_position] = mask[byte_position] & new_bit;

    Arc::from(mask)
}

pub fn is_set_u256(mask: &Vec<u8>, position: usize) -> bool {
    let byte_position: usize = position / 8;
    let bit_position: u8 = u8::try_from(position % 8).unwrap();

    let set_bit = u8::from(1) << (u8::from(7) - bit_position);

    mask[byte_position] == mask[byte_position] & set_bit
}

macro_rules! pass_down_bst {
    ($high: tt, $low: tt, $for_highest: tt, $next: tt, $shift: tt) => {
        if ($for_highest || $low == 0) && $high != 0 {
            binary_search::<$next>(ByteView::to_bytes($high), $for_highest)
        } else {
            $shift + binary_search::<$next>(ByteView::to_bytes($low), $for_highest)
        }
    };
}

pub fn binary_search<const N: usize>(_word: Vec<u8>, for_highest: bool) -> i32 {
    match N {
        256 => {
            let word_high: u128 = ByteView::from_bytes(_word.clone()[0..8].to_vec());
            let word_low: u128 = ByteView::from_bytes(_word.clone()[8..16].to_vec());
            let shift = (size_of::<u128>() * 8) as i32;
            pass_down_bst!(word_high, word_low, for_highest, 128, shift)
        }
        128 => {
            let word: u128 = ByteView::from_bytes(_word);
            let max = u64::MAX as u128;
            let low = (word & max) as u64;
            let high = ((word >> ((size_of::<u64>() as u128) * 8)) & max) as u64;
            let shift = (size_of::<u64>() * 8) as i32;
            pass_down_bst!(high, low, for_highest, 64, shift)
        }
        64 => {
            let word: u64 = ByteView::from_bytes(_word);
            let max = u32::MAX as u64;
            let low = (word & max) as u32;
            let high = ((word >> ((size_of::<u32>() as u64) * 8)) & max) as u32;
            let shift = (size_of::<u32>() * 8) as i32;
            pass_down_bst!(high, low, for_highest, 32, shift)
        }
        32 => {
            let word: u32 = ByteView::from_bytes(_word);
            let max = u16::MAX as u32;
            let low = (word & max) as u16;
            let high = ((word >> ((size_of::<u16>() as u32) * 8)) & max) as u16;
            let shift = (size_of::<u16>() * 8) as i32;
            pass_down_bst!(high, low, for_highest, 16, shift)
        }
        16 => {
            let word: u16 = ByteView::from_bytes(_word);
            let max = u8::MAX as u16;
            let low = (word & max) as u8;
            let high = ((word >> ((size_of::<u8>() as u16) * 8)) & max) as u8;
            let shift = (size_of::<u8>() * 8) as i32;
            pass_down_bst!(high, low, for_highest, 8, shift)
        }
        8 => {
            let word: u8 = ByteView::from_bytes(_word);
            let max: u8 = 0x0f;
            let high = (word >> 4) & max;
            let low = word & max;
            pass_down_bst!(high, low, for_highest, 4, 4)
        }
        4 => {
            let max: u8 = u8::try_from(N - 1).unwrap();
            let word: u8 = ByteView::from_bytes(_word);
            let high = (word >> 1) & max;
            let low = word & max;
            pass_down_bst!(high, low, for_highest, 2, 2)
        }
        2 => {
            let max: u8 = u8::try_from(N - 1).unwrap();
            let word: u8 = ByteView::from_bytes(_word);
            let high = (word >> 1) & max;
            let low = word & max;
            if (for_highest || low == 0) && high != 0 {
                0
            } else {
                1
            }
        }
        _ => 0,
    }
}

impl<K: ByteView + Sized + TryFrom<usize> + Clone> BST<K>
where
    <K as TryFrom<usize>>::Error: Debug,
{
    pub fn new(ptr: IndexPointer) -> Self {
        BST {
            ptr,
            _val: K::from_bytes(vec![0]),
        }
    }
    pub fn get_mask_pointer(&self, partial_key: Vec<u8>) -> IndexPointer {
        self.ptr.select(&partial_key).keyword("/mask")
    }
    pub fn mark_path(&self, key: K) {
        let key_bytes = ByteView::to_bytes(key);
        for i in 0..key_bytes.len() {
            let mut partial_key = ByteView::to_bytes(0 as usize);
            for j in 0..i {
                partial_key[j] = key_bytes[j];
            }
            let ptr = self.get_mask_pointer(partial_key.clone());
            let mut mask = Arc::try_unwrap(ptr.get()).unwrap();
            if mask.len() == 0 {
                mask = ByteView::to_bytes(0 as usize);
            }
            let byte = key_bytes[i];
            if !is_set_u256(&mask, byte as usize) {
                ptr.set(set_bit_u256(mask, byte as usize));
            }
        }
    }
    pub fn unmark_path(&self, key: K) {
        let key_bytes = ByteView::to_bytes(key);
        for i in 0..key_bytes.len() {
            let mut partial_key = ByteView::to_bytes(0 as usize);
            for j in 0..i {
                partial_key[j] = key_bytes[j];
            }
            let ptr = self.get_mask_pointer(partial_key.clone());
            let mut mask = Arc::try_unwrap(ptr.get()).unwrap();
            if mask.len() == 0 {
                mask = ByteView::to_bytes(0 as usize);
            }
            let byte = key_bytes[i];
            if is_set_u256(&mask, byte as usize) {
                ptr.set_or_nullify(unset_bit_u256(mask, byte as usize));
            }
        }
    }
    fn _find_boundary_from_partial(&self, _key_bytes: Vec<u8>, _seek_higher: bool) -> K {
        K::from_bytes(vec![0])
    }
    pub fn seek_lower(&self, start: K) -> K {
        let mut partial_key = ByteView::to_bytes(start);
        loop {
            let this_key = shrink_back(partial_key.clone(), 1);
            let mask = self.get_mask_pointer(this_key.clone()).get();
            if mask.len() > 0 {
                let derived_mask = mask_lower_than(mask, partial_key[this_key.len()].into());
                self.get_mask_pointer(this_key.clone())
                    .set(derived_mask.clone());
                let derived_mask_value = Arc::try_unwrap(derived_mask).unwrap();
                let symbol = binary_search::<256>(derived_mask_value, false);
                if symbol != -1 {
                    let mut new_key = this_key.clone();
                    new_key.push(symbol.try_into().unwrap());
                    return self._find_boundary_from_partial(new_key, false);
                }
            }

            partial_key = this_key;
            if partial_key.len() == 0 {
                break;
            }
        }
        K::from_bytes(vec![0])
    }
    pub fn seek_greater(&self, start: K) -> K {
        let mut partial_key = ByteView::to_bytes(start);
        loop {
            let this_key = shrink_back(partial_key.clone(), 1);
            let mask = self.get_mask_pointer(this_key.clone()).get();
            if mask.len() > 0 {
                let derived_mask = mask_greater_than(mask, partial_key[this_key.len()].into());
                self.get_mask_pointer(this_key.clone())
                    .set(derived_mask.clone());
                let derived_mask_value = Arc::try_unwrap(derived_mask).unwrap();
                let symbol = binary_search::<256>(derived_mask_value, false);
                if symbol != -1 {
                    let mut new_key = this_key.clone();
                    new_key.push(symbol.try_into().unwrap());
                    return self._find_boundary_from_partial(new_key, false);
                }
            }

            partial_key = this_key;
            if partial_key.len() == 0 {
                break;
            }
        }
        K::from_bytes(vec![0])
    }
    pub fn set(&self, k: K, v: Vec<u8>) {
        let key = ByteView::to_bytes(k.clone());
        let key_bytes = usize::from_bytes(key);
        if usize::from_bytes(v.clone()) == 0 {
            self.unmark_path(k);
        } else {
            self.mark_path(k);
        }
        self.ptr
            .select(&usize::to_bytes(key_bytes))
            .set(Arc::from(v));
    }
    pub fn get(&self, k: K) -> Vec<u8> {
        let key = ByteView::to_bytes(k.clone());
        let key_bytes = usize::from_bytes(key);
        Arc::try_unwrap(self.ptr.select(&usize::to_bytes(key_bytes)).get()).unwrap()
    }
    pub fn nullify(_key: K) {}
}
