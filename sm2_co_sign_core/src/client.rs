//! SM2 协同签名客户端

use crate::error::{Error, Result};
use crate::protocol::{base64_decode, base64_encode, CoSignProtocol};
use crate::types::*;
use reqwest::Client;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// 客户端配置
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// 服务器 URL
    pub server_url: String,
    /// 请求超时（秒）
    pub timeout: u64,
    /// 是否验证 TLS 证书
    pub verify_tls: bool,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            server_url: "http://127.0.0.1:8080".to_string(),
            timeout: 30,
            verify_tls: true,
        }
    }
}

/// 协同签名客户端
pub struct CoSignClient {
    config: ClientConfig,
    http_client: Client,
    protocol: CoSignProtocol,
    /// 当前会话
    session: Arc<RwLock<Option<Session>>>,
    /// 当前密钥对
    key_pair: Arc<RwLock<Option<KeyPair>>>,
}

impl CoSignClient {
    /// 创建新的客户端实例
    pub fn new(config: ClientConfig) -> Result<Self> {
        let http_client = Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout))
            .danger_accept_invalid_certs(!config.verify_tls)
            .build()
            .map_err(|e| Error::Network(e.to_string()))?;

        Ok(Self {
            config,
            http_client,
            protocol: CoSignProtocol::new()?,
            session: Arc::new(RwLock::new(None)),
            key_pair: Arc::new(RwLock::new(None)),
        })
    }

    /// 使用默认配置创建客户端
    pub fn with_server_url(server_url: &str) -> Result<Self> {
        let mut config = ClientConfig::default();
        config.server_url = server_url.to_string();
        Self::new(config)
    }

    /// 用户注册
    pub async fn register(&self, username: &str, password: &str) -> Result<KeyPair> {
        info!("Registering user: {}", username);

        // 生成 D1
        let d1 = self.protocol.generate_d1()?;

        // 计算 P1
        let p1 = self.protocol.calculate_p1(&d1)?;
        let p1_base64 = base64_encode(&p1);

        // 发送注册请求
        let url = format!("{}/api/register", self.config.server_url);
        let response = self
            .http_client
            .post(&url)
            .json(&serde_json::json!({
                "username": username,
                "password": password,
                "p1": p1_base64,
            }))
            .send()
            .await
            .map_err(|e| Error::Network(format!("Failed to connect to {}: {}", url, e)))?;

        // 检查 HTTP 状态码
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_else(|_| "Unable to read response".to_string());
            return Err(Error::Network(format!("HTTP {} from {}: {}", status, url, body)));
        }

        let api_response: ApiResponse<RegisterResponse> = response
            .json()
            .await
            .map_err(|e| Error::Network(format!("Failed to parse response from {}: {}", url, e)))?;

        if api_response.code != 0 {
            return Err(Error::Api {
                code: api_response.code,
                message: api_response.message,
            });
        }

        let data = api_response.data.ok_or(Error::InvalidState("No data in response".to_string()))?;

        // 解码 P2 和公钥
        let _p2 = base64_decode(&data.p2)?;
        let public_key = base64_decode(&data.public_key)?;

        // 存储密钥对
        let key_pair = KeyPair {
            d1: d1.clone(),
            public_key: public_key.clone(),
            user_id: data.user_id.clone(),
        };

        *self.key_pair.write().await = Some(key_pair.clone());

        info!("User registered successfully: {}", data.user_id);
        Ok(key_pair)
    }

    /// 用户登录
    pub async fn login(&self, username: &str, password: &str) -> Result<Session> {
        info!("Logging in user: {}", username);

        let url = format!("{}/api/login", self.config.server_url);
        let response = self
            .http_client
            .post(&url)
            .json(&serde_json::json!({
                "username": username,
                "password": password,
            }))
            .send()
            .await
            .map_err(|e| Error::Network(e.to_string()))?;

        let api_response: ApiResponse<LoginResponse> = response
            .json()
            .await
            .map_err(|e| Error::Network(e.to_string()))?;

        if api_response.code != 0 {
            return Err(Error::Api {
                code: api_response.code,
                message: api_response.message,
            });
        }

        let data = api_response.data.ok_or(Error::InvalidState("No data in response".to_string()))?;

        let session = Session {
            token: data.token.clone(),
            user_id: data.user_id.clone(),
            expires_at: data.expires_at.clone(),
        };

        *self.session.write().await = Some(session.clone());

        info!("User logged in successfully");
        Ok(session)
    }

    /// 用户登出
    pub async fn logout(&self) -> Result<()> {
        let session = self.session.read().await.clone();
        let session = session.ok_or(Error::NotAuthenticated)?;

        let url = format!("{}/api/logout", self.config.server_url);
        let response = self
            .http_client
            .post(&url)
            .bearer_auth(&session.token)
            .send()
            .await
            .map_err(|e| Error::Network(e.to_string()))?;

        if !response.status().is_success() {
            warn!("Logout request failed, but continuing anyway");
        }

        *self.session.write().await = None;
        info!("User logged out successfully");
        Ok(())
    }

    /// 初始化密钥
    pub async fn init_key(&self) -> Result<KeyPair> {
        let session = self.session.read().await.clone();
        let session = session.ok_or(Error::NotAuthenticated)?;

        info!("Initializing key for user: {}", session.user_id);

        // 生成 D1
        let d1 = self.protocol.generate_d1()?;

        // 计算 P1
        let p1 = self.protocol.calculate_p1(&d1)?;
        let p1_base64 = base64_encode(&p1);

        let url = format!("{}/api/key/init", self.config.server_url);
        let response = self
            .http_client
            .post(&url)
            .bearer_auth(&session.token)
            .json(&serde_json::json!({
                "user_id": session.user_id,
                "p1": p1_base64,
            }))
            .send()
            .await
            .map_err(|e| Error::Network(e.to_string()))?;

        let api_response: ApiResponse<KeyInitResponse> = response
            .json()
            .await
            .map_err(|e| Error::Network(e.to_string()))?;

        if api_response.code != 0 {
            return Err(Error::Api {
                code: api_response.code,
                message: api_response.message,
            });
        }

        let data = api_response.data.ok_or(Error::InvalidState("No data in response".to_string()))?;

        let public_key = base64_decode(&data.public_key)?;

        let key_pair = KeyPair {
            d1,
            public_key,
            user_id: session.user_id,
        };

        *self.key_pair.write().await = Some(key_pair.clone());

        info!("Key initialized successfully");
        Ok(key_pair)
    }

    /// 协同签名
    pub async fn sign(&self, message: &[u8]) -> Result<Signature> {
        let session = self.session.read().await.clone();
        let session = session.ok_or(Error::NotAuthenticated)?;

        let key_pair = self.key_pair.read().await.clone();
        let key_pair = key_pair.ok_or(Error::InvalidState("No key pair available".to_string()))?;

        debug!("Signing message of {} bytes", message.len());

        // 计算消息哈希
        let e = self.protocol.calculate_message_hash(message, &key_pair.public_key)?;
        let e_base64 = base64_encode(&e);

        // 签名预处理：生成 k1, Q1
        let (k1, q1) = self.protocol.sign_prepare()?;
        let q1_base64 = base64_encode(&q1);

        // 发送签名请求
        let url = format!("{}/api/sign", self.config.server_url);
        let response = self
            .http_client
            .post(&url)
            .bearer_auth(&session.token)
            .json(&serde_json::json!({
                "user_id": key_pair.user_id,
                "q1": q1_base64,
                "e": e_base64,
            }))
            .send()
            .await
            .map_err(|e| Error::Network(e.to_string()))?;

        let api_response: ApiResponse<SignResponse> = response
            .json()
            .await
            .map_err(|e| Error::Network(e.to_string()))?;

        if api_response.code != 0 {
            return Err(Error::Api {
                code: api_response.code,
                message: api_response.message,
            });
        }

        let data = api_response.data.ok_or(Error::InvalidState("No data in response".to_string()))?;

        // 解码服务端返回的签名分量
        let r = base64_decode(&data.r)?;
        let s2 = base64_decode(&data.s2)?;
        let s3 = base64_decode(&data.s3)?;

        // 完成签名计算
        let (r_final, s_final) = self.protocol.complete_signature(&k1, &key_pair.d1, &r, &s2, &s3)?;

        debug!("Signature generated successfully");
        Ok(Signature {
            r: r_final,
            s: s_final,
        })
    }

    /// 协同解密
    pub async fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let session = self.session.read().await.clone();
        let session = session.ok_or(Error::NotAuthenticated)?;

        let key_pair = self.key_pair.read().await.clone();
        let key_pair = key_pair.ok_or(Error::InvalidState("No key pair available".to_string()))?;

        debug!("Decrypting ciphertext of {} bytes", ciphertext.len());

        // 解析密文 C1 || C3 || C2
        // C1: 65字节 (04 || x || y)
        // C3: 32字节
        // C2: 剩余字节
        if ciphertext.len() < 65 + 32 {
            return Err(Error::InvalidParam("Ciphertext too short".to_string()));
        }

        let c1 = &ciphertext[0..65];
        let c3 = &ciphertext[65..97];
        let c2 = &ciphertext[97..];

        // 计算预处理 T1
        let t1 = self.protocol.decrypt_prepare(&key_pair.d1, c1)?;
        let t1_base64 = base64_encode(&t1);

        // 发送解密请求
        let url = format!("{}/api/decrypt", self.config.server_url);
        let response = self
            .http_client
            .post(&url)
            .bearer_auth(&session.token)
            .json(&serde_json::json!({
                "user_id": key_pair.user_id,
                "t1": t1_base64,
            }))
            .send()
            .await
            .map_err(|e| Error::Network(e.to_string()))?;

        let api_response: ApiResponse<DecryptResponse> = response
            .json()
            .await
            .map_err(|e| Error::Network(e.to_string()))?;

        if api_response.code != 0 {
            return Err(Error::Api {
                code: api_response.code,
                message: api_response.message,
            });
        }

        let data = api_response.data.ok_or(Error::InvalidState("No data in response".to_string()))?;

        // 解码 T2
        let t2 = base64_decode(&data.t2)?;

        // 完成解密
        let plaintext = self.protocol.complete_decryption(&t2, c3, c2)?;

        debug!("Decryption completed successfully");
        Ok(plaintext)
    }

    /// 获取当前会话
    pub async fn get_session(&self) -> Option<Session> {
        self.session.read().await.clone()
    }

    /// 设置会话（从文件恢复）
    pub async fn set_session(&self, token: String, user_id: String) -> Result<()> {
        let session = Session {
            token,
            user_id,
            expires_at: String::new(),
        };
        *self.session.write().await = Some(session);
        Ok(())
    }

    /// 获取当前密钥对
    pub async fn get_key_pair(&self) -> Option<KeyPair> {
        self.key_pair.read().await.clone()
    }

    /// 设置密钥对（从文件恢复）
    pub async fn set_key_pair(&self, d1: Vec<u8>, public_key: Vec<u8>, user_id: String) -> Result<()> {
        let key_pair = KeyPair {
            d1,
            public_key,
            user_id,
        };
        *self.key_pair.write().await = Some(key_pair);
        Ok(())
    }

    /// 获取用户信息
    pub async fn get_user_info(&self) -> Result<UserInfo> {
        let session = self.session.read().await.clone();
        let session = session.ok_or(Error::NotAuthenticated)?;

        let url = format!("{}/api/user/info", self.config.server_url);
        let response = self
            .http_client
            .get(&url)
            .bearer_auth(&session.token)
            .send()
            .await
            .map_err(|e| Error::Network(e.to_string()))?;

        let api_response: ApiResponse<UserInfoResponse> = response
            .json()
            .await
            .map_err(|e| Error::Network(e.to_string()))?;

        if api_response.code != 0 {
            return Err(Error::Api {
                code: api_response.code,
                message: api_response.message,
            });
        }

        let data = api_response.data.ok_or(Error::InvalidState("No data in response".to_string()))?;

        Ok(UserInfo {
            id: data.id,
            username: data.username,
            public_key: data.public_key,
            status: data.status,
            created_at: data.created_at,
        })
    }

    /// 健康检查
    pub async fn health_check(&self) -> Result<bool> {
        let url = format!("{}/mapi/health", self.config.server_url);
        let response = self
            .http_client
            .get(&url)
            .send()
            .await
            .map_err(|e| Error::Network(e.to_string()))?;

        Ok(response.status().is_success())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_config_default() {
        let config = ClientConfig::default();
        assert_eq!(config.server_url, "http://127.0.0.1:8080");
        assert_eq!(config.timeout, 30);
        assert!(config.verify_tls);
    }

    #[tokio::test]
    async fn test_client_creation() {
        let client = CoSignClient::with_server_url("http://localhost:8080");
        assert!(client.is_ok());
    }
}
