//! 数据类型定义

use serde::{Deserialize, Serialize};

/// 用户信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub id: String,
    pub username: String,
    #[serde(rename = "publicKey")]
    pub public_key: String,
    pub status: i32,
    #[serde(rename = "createdAt")]
    pub created_at: String,
}

/// 会话信息
#[derive(Debug, Clone)]
pub struct Session {
    pub token: String,
    pub user_id: String,
    pub expires_at: String,
}

/// 密钥对（客户端持有的 D1 分量）
#[derive(Debug, Clone)]
pub struct KeyPair {
    /// 客户端私钥分量 D1
    pub d1: Vec<u8>,
    /// 协同公钥 Pa
    pub public_key: Vec<u8>,
    /// 用户 ID
    pub user_id: String,
}

/// 签名结果
#[derive(Debug, Clone)]
pub struct Signature {
    pub r: Vec<u8>,
    pub s: Vec<u8>,
}

/// 统一 API 响应
#[derive(Debug, Clone, Deserialize)]
pub struct ApiResponse<T> {
    pub code: i32,
    pub message: String,
    pub data: Option<T>,
}

/// 注册响应数据
#[derive(Debug, Clone, Deserialize)]
pub struct RegisterResponse {
    #[serde(rename = "userId")]
    pub user_id: String,
    pub p2: String,
    #[serde(rename = "publicKey")]
    pub public_key: String,
}

/// 登录响应数据
#[derive(Debug, Clone, Deserialize)]
pub struct LoginResponse {
    pub token: String,
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: String,
}

/// 密钥初始化响应数据
#[derive(Debug, Clone, Deserialize)]
pub struct KeyInitResponse {
    pub p2: String,
    #[serde(rename = "publicKey")]
    pub public_key: String,
}

/// 签名响应数据
#[derive(Debug, Clone, Deserialize)]
pub struct SignResponse {
    pub r: String,
    pub s2: String,
    pub s3: String,
}

/// 解密响应数据
#[derive(Debug, Clone, Deserialize)]
pub struct DecryptResponse {
    pub t2: String,
}

/// 用户信息响应数据
#[derive(Debug, Clone, Deserialize)]
pub struct UserInfoResponse {
    pub id: String,
    pub username: String,
    #[serde(rename = "publicKey")]
    pub public_key: String,
    pub status: i32,
    #[serde(rename = "createdAt")]
    pub created_at: String,
}
