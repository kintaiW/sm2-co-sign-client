//! 错误类型定义

use thiserror::Error;

/// 错误类型
#[derive(Debug, Error)]
pub enum Error {
    /// 密码学错误
    #[error("Cryptographic error: {0}")]
    Crypto(String),

    /// 网络错误
    #[error("Network error: {0}")]
    Network(String),

    /// API 错误
    #[error("API error (code {code}): {message}")]
    Api { code: i32, message: String },

    /// 参数错误
    #[error("Invalid parameter: {0}")]
    InvalidParam(String),

    /// 状态错误
    #[error("Invalid state: {0}")]
    InvalidState(String),

    /// 编解码错误
    #[error("Encoding/Decoding error: {0}")]
    Encoding(String),

    /// 未认证错误
    #[error("Not authenticated")]
    NotAuthenticated,

    /// IO 错误
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// 结果类型
pub type Result<T> = std::result::Result<T, Error>;
