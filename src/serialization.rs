pub struct OpnetBytes(pub Vec<u8>);

impl OpnetBytes {
  pub fn buffer_length() -> u32 {
    self.0.len().into()
  }
  pub fn write_u8(v: u8) {
    self.0.push(v);
  }
  pub fn write_u16(v: u16) {
    self.0.extend(v.to_be_bytes());
  }
}
