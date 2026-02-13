//! SM2 协同签名客户端核心库
//!
//! 提供完整的 SM2 协同签名协议实现，包括：
//! - 密钥生成（D1/D2分片架构）
//! - 协同签名
//! - 协同解密

pub mod client;
pub mod error;
pub mod protocol;
pub mod types;

pub use client::{CoSignClient, ClientConfig};
pub use error::{Error, Result};
pub use protocol::CoSignProtocol;
pub use types::*;
