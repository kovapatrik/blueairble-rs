pub mod protos {
  include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));
}

pub mod discovery;
pub mod service;
