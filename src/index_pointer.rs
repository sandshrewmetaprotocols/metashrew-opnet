use crate::byte_view::ByteView;
use crate::{flush, get, input, set};
use std::mem::{size_of, size_of_val};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct IndexPointer(Arc<Vec<u8>>);

impl IndexPointer {
    pub fn from_keyword(keyword: &str) -> IndexPointer {
        IndexPointer::wrap(&keyword.to_string().clone().into_bytes())
    }
    pub fn wrap(word: &Vec<u8>) -> IndexPointer {
        IndexPointer(Arc::<Vec<u8>>::new(word.clone()))
    }
    pub fn unwrap(&self) -> Arc<Vec<u8>> {
        self.0.clone()
    }
    pub fn set(&self, v: Arc<Vec<u8>>) {
        set(self.unwrap(), v)
    }
    pub fn get(&self) -> Arc<Vec<u8>> {
        get(self.unwrap())
    }
    /*
    pub fn length_key() -> Self {
        self.keyword("/length")
    }
    pub fn length() -> u32 {
      self.length_key().get_value::<u32>()
    }
    pub fn select_index(i: u32) -> Self {
      self.keyword("/").keyword(&i.to_string())
    }
    */
    pub fn append(&self, v: Arc<Vec<u8>>) {
      let length = self.length();
      self.select_index(length).set(v);
      self.length_key().set_value::<u32>(length + 1);
    }
    pub fn select(&self, word: &Vec<u8>) -> Self {
        let mut key = (*self.unwrap()).clone();
        key.extend(word);
        return IndexPointer::wrap(&key);
    }
    pub fn keyword(&self, word: &str) -> IndexPointer {
        let mut key = (*self.unwrap()).clone();
        key.extend(word.to_string().into_bytes());
        return IndexPointer::wrap(&key);
    }

    pub fn set_value<T: ByteView>(&self, v: T) {
        self.set(Arc::new(T::to_bytes(v)));
    }

    pub fn get_value<T: ByteView>(&self) -> T {
        T::from_bytes(self.get().as_ref().clone())
    }

    pub fn select_value<T: ByteView>(&self, key: T) -> Self {
        self.select(T::to_bytes(key).as_ref())
    }
    pub fn length_key(&self) -> Self {
        self.keyword(&"/length".to_string())
    }
    pub fn length<T: ByteView>(&self) -> T {
        self.length_key().get_value()
    }
    pub fn select_index(&self, index: u32) -> Self {
        self.keyword(&format!("/{}", index))
    }

    pub fn get_list(&self) -> Vec<Arc<Vec<u8>>> {
        Vec::<u8>::with_capacity(self.length::<usize>())
            .into_iter()
            .enumerate()
            .map(|(i, _x)| self.select_index(i as u32).get().clone())
            .collect::<Vec<Arc<Vec<u8>>>>()
    }
    pub fn get_list_values<T: ByteView>(&self) -> Vec<T> {
        Vec::<u8>::with_capacity(self.length::<usize>())
            .into_iter()
            .enumerate()
            .map(|(i, _x)| self.select_index(i as u32).get_value::<T>())
            .collect::<Vec<T>>()
    }
    pub fn nullify(&self) {
        self.set(Arc::from(vec![0]))
    }
    pub fn set_or_nullify(&self, v: Arc<Vec<u8>>) {
        let val = Arc::try_unwrap(v).unwrap();
        if <usize>::from_bytes(val.clone()) == 0 {
            self.nullify();
        } else {
            self.set(Arc::from(val));
        }
    }
}
