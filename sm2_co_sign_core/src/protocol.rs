//! SM2 协同签名协议实现
//!
//! 协议流程：
//! 1. 密钥生成：客户端生成 d1，计算 P1 = d1 * G，服务端生成 d2，计算 P2, Pa
//! 2. 签名：客户端发送 Q1, E，服务端返回 r, s2, s3，客户端计算最终签名
//! 3. 解密：客户端发送 T1，服务端返回 T2，客户端计算共享密钥
//!
//! 依赖库说明：
//! - libsm: 用于协同签名特有的椭圆曲线操作（点乘、点加、点坐标转换等）
//! - gm-sdk-rs: 用于标准 SM2 签名验签、SM3 哈希（API 更简洁，开箱即用）

use crate::error::{Error, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use gm_sdk::sm2::{sm2_sign, sm2_verify};
use gm_sdk::sm3::sm3_hash as gm_sm3_hash;
use libsm::sm2::ecc::EccCtx;
use num_bigint::BigUint;
use rand::RngCore;

/// 协同签名协议
pub struct CoSignProtocol {
    ecc: EccCtx,
}

impl CoSignProtocol {
    /// 创建协议实例
    pub fn new() -> Result<Self> {
        let ecc = EccCtx::new();
        Ok(Self { ecc })
    }

    /// 生成随机数
    pub fn generate_random(bytes: usize) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let mut data = vec![0u8; bytes];
        rng.fill_bytes(&mut data);
        data
    }

    /// 计算 SM3 哈希
    /// 使用 gm-sdk-rs 提供的简洁 API
    pub fn sm3_hash(data: &[u8]) -> Vec<u8> {
        gm_sm3_hash(data).to_vec()
    }

    /// 生成客户端私钥分量 D1
    /// 注意：此功能需要 libsm 的椭圆曲线随机数生成，gm-sdk-rs 不支持
    pub fn generate_d1(&self) -> Result<Vec<u8>> {
        let d1 = self.ecc.random_uint();
        Ok(d1.to_bytes_be())
    }

    /// 计算 P1 = d1 * G
    /// 注意：此功能需要 libsm 的椭圆曲线点乘运算，gm-sdk-rs 不支持
    pub fn calculate_p1(&self, d1: &[u8]) -> Result<Vec<u8>> {
        let d1_big = BigUint::from_bytes_be(d1);
        
        let p1 = self.ecc.g_mul(&d1_big).map_err(|e| Error::Crypto(e.to_string()))?;
        
        let (x, y) = self.ecc.to_affine(&p1).map_err(|e| Error::Crypto(e.to_string()))?;
        let x_bytes = x.to_bytes();
        let y_bytes = y.to_bytes();
        
        let mut p1_bytes = vec![0u8; 64];
        let x_len = x_bytes.len();
        let y_len = y_bytes.len();
        p1_bytes[32 - x_len..32].copy_from_slice(&x_bytes);
        p1_bytes[64 - y_len..64].copy_from_slice(&y_bytes);
        
        Ok(p1_bytes)
    }

    /// 签名预处理：生成 k1，计算 Q1 = k1 * G
    /// 注意：此功能需要 libsm 的椭圆曲线点乘运算，gm-sdk-rs 不支持
    pub fn sign_prepare(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let k1 = self.ecc.random_uint();
        
        let q1 = self.ecc.g_mul(&k1).map_err(|e| Error::Crypto(e.to_string()))?;
        
        let (x, y) = self.ecc.to_affine(&q1).map_err(|e| Error::Crypto(e.to_string()))?;
        let x_bytes = x.to_bytes();
        let y_bytes = y.to_bytes();
        
        let mut q1_bytes = vec![0u8; 64];
        let x_len = x_bytes.len();
        let y_len = y_bytes.len();
        q1_bytes[32 - x_len..32].copy_from_slice(&x_bytes);
        q1_bytes[64 - y_len..64].copy_from_slice(&y_bytes);
        
        Ok((k1.to_bytes_be(), q1_bytes))
    }

    /// 计算消息哈希 E
    pub fn calculate_message_hash(&self, message: &[u8], _public_key: &[u8]) -> Result<Vec<u8>> {
        Ok(Self::sm3_hash(message))
    }

    /// 完成签名计算
    /// 注意：此功能是协同签名协议特有步骤，gm-sdk-rs 不支持
    pub fn complete_signature(
        &self,
        k1: &[u8],
        d1: &[u8],
        r: &[u8],
        s2: &[u8],
        s3: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let n = self.ecc.get_n();
        
        let k1_big = BigUint::from_bytes_be(k1);
        let d1_big = BigUint::from_bytes_be(d1);
        let r_big = BigUint::from_bytes_be(r);
        let s2_big = BigUint::from_bytes_be(s2);
        let s3_big = BigUint::from_bytes_be(s3);
        
        let r_d1 = (&r_big * &d1_big) % n;
        let k1_s3 = (&k1_big * &s3_big) % n;
        let s1 = if k1_s3 >= r_d1 {
            (&k1_s3 - &r_d1) % n
        } else {
            (&k1_s3 + n - &r_d1) % n
        };
        
        let s = (&s1 * &s2_big) % n;
        
        Ok((r.to_vec(), s.to_bytes_be()))
    }

    /// 解密预处理：计算 T1 = d1 * C1
    /// 注意：此功能需要 libsm 的椭圆曲线点乘运算，gm-sdk-rs 不支持
    pub fn decrypt_prepare(&self, d1: &[u8], c1: &[u8]) -> Result<Vec<u8>> {
        if c1.len() != 64 {
            return Err(Error::Crypto("Invalid C1 length, expected 64 bytes".to_string()));
        }
        
        let x_bytes = &c1[0..32];
        let y_bytes = &c1[32..64];
        
        let x = libsm::sm2::field::FieldElem::from_bytes(x_bytes)
            .map_err(|e| Error::Crypto(e.to_string()))?;
        let y = libsm::sm2::field::FieldElem::from_bytes(y_bytes)
            .map_err(|e| Error::Crypto(e.to_string()))?;
        
        let c1_point = self.ecc.new_point(&x, &y).map_err(|e| Error::Crypto(e.to_string()))?;
        
        let d1_big = BigUint::from_bytes_be(d1);
        let t1_point = self.ecc.mul(&d1_big, &c1_point).map_err(|e| Error::Crypto(e.to_string()))?;
        
        let (x, y) = self.ecc.to_affine(&t1_point).map_err(|e| Error::Crypto(e.to_string()))?;
        let x_bytes = x.to_bytes();
        let y_bytes = y.to_bytes();
        
        let mut t1_bytes = vec![0u8; 64];
        let x_len = x_bytes.len();
        let y_len = y_bytes.len();
        t1_bytes[32 - x_len..32].copy_from_slice(&x_bytes);
        t1_bytes[64 - y_len..64].copy_from_slice(&y_bytes);
        
        Ok(t1_bytes)
    }

    /// 完成解密计算
    pub fn complete_decryption(
        &self,
        t2: &[u8],
        _c3: &[u8],
        c2: &[u8],
    ) -> Result<Vec<u8>> {
        let k = Self::sm3_hash(t2);
        
        let plaintext: Vec<u8> = c2
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ k[i % k.len()])
            .collect();
        
        Ok(plaintext)
    }

    /// SM2 签名（标准签名，非协同）
    /// 使用 gm-sdk-rs 提供的简洁 API
    pub fn sign(private_key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        let sk: [u8; 32] = private_key.try_into()
            .map_err(|_| Error::Crypto("Invalid private key length, expected 32 bytes".to_string()))?;
        let signature = sm2_sign(&sk, message);
        Ok(signature.to_vec())
    }

    /// SM2 验签（标准验签，非协同）
    /// 使用 gm-sdk-rs 提供的简洁 API
    pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
        if public_key.len() != 64 || signature.len() != 64 {
            return Err(Error::Crypto("Invalid public key or signature length".to_string()));
        }
        
        let pk: [u8; 64] = public_key.try_into()
            .map_err(|_| Error::Crypto("Invalid public key length".to_string()))?;
        let sig: [u8; 64] = signature.try_into()
            .map_err(|_| Error::Crypto("Invalid signature length".to_string()))?;
        
        Ok(sm2_verify(&pk, message, &sig))
    }

    /// SM2 加密（标准加密，非协同）
    /// 注意：gm-sdk-rs 未提供加密功能，使用 libsm 实现
    pub fn encrypt(public_key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        if public_key.len() != 64 {
            return Err(Error::Crypto("Invalid public key length".to_string()));
        }
        
        let ecc = EccCtx::new();
        
        let x = libsm::sm2::field::FieldElem::from_bytes(&public_key[0..32])
            .map_err(|e| Error::Crypto(e.to_string()))?;
        let y = libsm::sm2::field::FieldElem::from_bytes(&public_key[32..64])
            .map_err(|e| Error::Crypto(e.to_string()))?;
        let pub_point = ecc.new_point(&x, &y).map_err(|e| Error::Crypto(e.to_string()))?;
        
        let k = ecc.random_uint();
        
        let c1 = ecc.g_mul(&k).map_err(|e| Error::Crypto(e.to_string()))?;
        let (c1_x, c1_y) = ecc.to_affine(&c1).map_err(|e| Error::Crypto(e.to_string()))?;
        
        let k_pa = ecc.mul(&k, &pub_point).map_err(|e| Error::Crypto(e.to_string()))?;
        let (k_pa_x, k_pa_y) = ecc.to_affine(&k_pa).map_err(|e| Error::Crypto(e.to_string()))?;
        
        let mut kdf_input = Vec::new();
        kdf_input.extend_from_slice(&k_pa_x.to_bytes());
        kdf_input.extend_from_slice(&k_pa_y.to_bytes());
        
        let kdf_output = Self::kdf(&kdf_input, message.len());
        let c2: Vec<u8> = message.iter().zip(kdf_output.iter()).map(|(m, k)| m ^ k).collect();
        
        let mut c3_input = Vec::new();
        c3_input.extend_from_slice(&k_pa_x.to_bytes());
        c3_input.extend_from_slice(&k_pa_y.to_bytes());
        c3_input.extend_from_slice(message);
        let c3 = Self::sm3_hash(&c3_input);
        
        let mut ciphertext = Vec::new();
        ciphertext.push(0x04);
        let c1_x_bytes = c1_x.to_bytes();
        let c1_y_bytes = c1_y.to_bytes();
        ciphertext.extend_from_slice(&vec![0u8; 32 - c1_x_bytes.len()]);
        ciphertext.extend_from_slice(&c1_x_bytes);
        ciphertext.extend_from_slice(&vec![0u8; 32 - c1_y_bytes.len()]);
        ciphertext.extend_from_slice(&c1_y_bytes);
        ciphertext.extend_from_slice(&c3);
        ciphertext.extend_from_slice(&c2);
        
        Ok(ciphertext)
    }

    /// SM2 解密（标准解密，非协同）
    /// 注意：gm-sdk-rs 未提供解密功能，使用 libsm 实现
    pub fn decrypt(private_key: &[u8], ciphertext: &[u8]) -> Result<Option<Vec<u8>>> {
        if ciphertext.len() < 97 {
            return Ok(None);
        }
        
        let ecc = EccCtx::new();
        
        if ciphertext[0] != 0x04 {
            return Ok(None);
        }
        
        let c1_x = libsm::sm2::field::FieldElem::from_bytes(&ciphertext[1..33])
            .map_err(|_| Error::Crypto("Invalid C1 x coordinate".to_string()))?;
        let c1_y = libsm::sm2::field::FieldElem::from_bytes(&ciphertext[33..65])
            .map_err(|_| Error::Crypto("Invalid C1 y coordinate".to_string()))?;
        let c1 = ecc.new_point(&c1_x, &c1_y).map_err(|e| Error::Crypto(e.to_string()))?;
        
        let c3 = &ciphertext[65..97];
        let c2 = &ciphertext[97..];
        
        let d = BigUint::from_bytes_be(private_key);
        let d_c1 = ecc.mul(&d, &c1).map_err(|e| Error::Crypto(e.to_string()))?;
        let (d_c1_x, d_c1_y) = ecc.to_affine(&d_c1).map_err(|e| Error::Crypto(e.to_string()))?;
        
        let mut kdf_input = Vec::new();
        kdf_input.extend_from_slice(&d_c1_x.to_bytes());
        kdf_input.extend_from_slice(&d_c1_y.to_bytes());
        
        let kdf_output = Self::kdf(&kdf_input, c2.len());
        let plaintext: Vec<u8> = c2.iter().zip(kdf_output.iter()).map(|(c, k)| c ^ k).collect();
        
        let mut c3_input = Vec::new();
        c3_input.extend_from_slice(&d_c1_x.to_bytes());
        c3_input.extend_from_slice(&d_c1_y.to_bytes());
        c3_input.extend_from_slice(&plaintext);
        let c3_check = Self::sm3_hash(&c3_input);
        
        if c3_check != c3 {
            return Ok(None);
        }
        
        Ok(Some(plaintext))
    }

    /// KDF 密钥派生函数
    /// 注意：gm-sdk-rs 未提供 KDF 功能
    fn kdf(z: &[u8], klen: usize) -> Vec<u8> {
        let mut result = Vec::new();
        let mut ct = 1u32;
        
        while result.len() < klen {
            let mut input = z.to_vec();
            input.extend_from_slice(&ct.to_be_bytes());
            let hash = Self::sm3_hash(&input);
            result.extend_from_slice(&hash);
            ct += 1;
        }
        
        result.truncate(klen);
        result
    }
}

impl Default for CoSignProtocol {
    fn default() -> Self {
        Self::new().expect("Failed to create protocol")
    }
}

/// Base64 编码
pub fn base64_encode(data: &[u8]) -> String {
    BASE64.encode(data)
}

/// Base64 解码
pub fn base64_decode(data: &str) -> Result<Vec<u8>> {
    BASE64.decode(data).map_err(|e| Error::Encoding(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_d1() {
        let protocol = CoSignProtocol::new().unwrap();
        let d1 = protocol.generate_d1().unwrap();
        assert!(!d1.is_empty());
        assert!(d1.len() <= 32);
    }

    #[test]
    fn test_calculate_p1() {
        let protocol = CoSignProtocol::new().unwrap();
        let d1 = protocol.generate_d1().unwrap();
        let p1 = protocol.calculate_p1(&d1).unwrap();
        assert_eq!(p1.len(), 64);
    }

    #[test]
    fn test_sm3_hash() {
        let data = b"hello world";
        let hash = CoSignProtocol::sm3_hash(data);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_sign_prepare() {
        let protocol = CoSignProtocol::new().unwrap();
        let (k1, q1) = protocol.sign_prepare().unwrap();
        assert!(!k1.is_empty());
        assert_eq!(q1.len(), 64);
    }

    #[test]
    fn test_complete_signature() {
        let protocol = CoSignProtocol::new().unwrap();
        let d1 = protocol.generate_d1().unwrap();
        let (k1, _q1) = protocol.sign_prepare().unwrap();
        
        let r = CoSignProtocol::generate_random(32);
        let s2 = CoSignProtocol::generate_random(32);
        let s3 = CoSignProtocol::generate_random(32);
        
        let (r_out, s) = protocol.complete_signature(&k1, &d1, &r, &s2, &s3).unwrap();
        assert_eq!(r_out.len(), 32);
        assert!(s.len() <= 32);
    }

    #[test]
    fn test_sm2_sign_verify() {
        use gm_sdk::sm2::sm2_generate_keypair;
        
        // 使用 gm-sdk-rs 生成密钥对进行测试
        let (private_key, public_key) = sm2_generate_keypair();
        let message = b"hello world";
        
        let signature = CoSignProtocol::sign(&private_key, message).unwrap();
        assert_eq!(signature.len(), 64);
        
        let valid = CoSignProtocol::verify(&public_key, message, &signature).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_sm2_encrypt_decrypt() {
        let protocol = CoSignProtocol::new().unwrap();
        let d1 = protocol.generate_d1().unwrap();
        let p1 = protocol.calculate_p1(&d1).unwrap();
        let message = b"hello world";
        
        let ciphertext = CoSignProtocol::encrypt(&p1, message).unwrap();
        assert!(!ciphertext.is_empty());
        
        // 补齐私钥到32字节
        let mut sk = vec![0u8; 32];
        let d1_len = d1.len();
        sk[32 - d1_len..].copy_from_slice(&d1);
        
        let plaintext = CoSignProtocol::decrypt(&sk, &ciphertext).unwrap();
        assert!(plaintext.is_some());
        assert_eq!(plaintext.unwrap().as_slice(), message);
    }

    #[test]
    fn test_base64() {
        let data = b"hello world";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(data.to_vec(), decoded);
    }
}
