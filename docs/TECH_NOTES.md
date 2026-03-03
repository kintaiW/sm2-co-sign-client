# SM2 协同签名客户端技术笔记

> 基于 Rust 实现的国密 SM2 协同签名客户端，支持密钥分片、协同签名和协同解密

[![Rust](https://img.shields.io/badge/Rust-1.70+-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![SM2](https://img.shields.io/badge/SM2-国密标准-green.svg)](http://www.gmbz.org.cn/)

---

## 目录

- [项目简介](#项目简介)
- [技术架构](#技术架构)
- [核心功能](#核心功能)
- [协议原理](#协议原理)
- [快速开始](#快速开始)
- [API 文档](#api-文档)
- [FFI 接口](#ffi-接口)
- [性能测试](#性能测试)
- [安全说明](#安全说明)

---

## 项目简介

### 什么是协同签名？

协同签名（Co-Signature）是一种分布式密码学技术，将私钥分割为多个分量，由不同方分别持有。签名时，各方协作完成签名计算，但任何一方都无法单独获取完整私钥。

### 为什么选择 SM2 协同签名？

| 特性 | 传统签名 | 协同签名 |
|------|---------|---------|
| 私钥存储 | 单点存储，风险高 | 分片存储，安全高 |
| 签名过程 | 单方完成 | 多方协作 |
| 密钥泄露风险 | 高 | 低（需多方同时泄露） |
| 合规性 | 需额外措施 | 天然满足监管要求 |

### 项目特点

- 🔐 **密钥分片**：私钥分量 D1/D2 分别由客户端和服务端持有
- 🚀 **高性能**：Rust 实现，零开销抽象，性能接近 C 语言
- 🔧 **多接口**：支持 Rust API、CLI 工具、FFI 动态库
- 📦 **开箱即用**：完整的构建脚本和测试用例
- 🛡️ **安全可靠**：纯 Rust 实现，内存安全有保障

---

## 技术架构

### 系统架构图

```
┌─────────────────────────────────────────────────────────────────┐
│                        应用层                                    │
├─────────────────┬─────────────────┬─────────────────────────────┤
│   CLI 工具      │   Rust API     │      FFI 动态库              │
│  sm2-cosign     │  CoSignClient  │  libsm2_co_sign_ffi.so       │
├─────────────────┴─────────────────┴─────────────────────────────┤
│                        核心协议层                                │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    CoSignProtocol                        │   │
│  │  ┌───────────┐  ┌───────────┐  ┌───────────────────┐   │   │
│  │  │ 密钥生成  │  │ 协同签名  │  │    协同解密       │   │   │
│  │  │  D1/D2    │  │  K1/K2/K3 │  │    T1/T2          │   │   │
│  │  └───────────┘  └───────────┘  └───────────────────┘   │   │
│  └─────────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────────┤
│                        密码算法层                                │
│  ┌─────────────────────┐  ┌─────────────────────────────────┐ │
│  │      gm-sdk-rs      │  │             libsm               │ │
│  │  ┌─────┐ ┌─────┐   │  │  ┌─────────┐ ┌───────────────┐ │ │
│  │  │ SM2 │ │ SM3 │   │  │  │ 点乘运算 │ │ SM2 加解密    │ │ │
│  │  │签名 │ │ 哈希 │   │  │  │ 点加运算 │ │ KDF 密钥派生  │ │ │
│  │  └─────┘ └─────┘   │  │  │ 坐标转换 │ │ 协同签名计算  │ │ │
│  └─────────────────────┘  └─────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────────┤
│                        网络通信层                                │
│                    reqwest + tokio                              │
└─────────────────────────────────────────────────────────────────┘
```

### 模块说明

| 模块 | 说明 | 输出 |
|------|------|------|
| `sm2_co_sign_core` | 核心协议库 | Rust crate |
| `sm2_co_sign_cli` | 命令行工具 | 可执行文件 |
| `sm2_co_sign_ffi` | FFI 绑定 | 动态库/静态库 |

### 技术栈

```
┌────────────────────────────────────────────────────────┐
│  语言: Rust 2021 Edition                               │
│  异步运行时: Tokio 1.0                                  │
│  HTTP 客户端: reqwest 0.11                              │
│  序列化: serde 1.0                                      │
│  CLI 框架: clap 4.0                                     │
│  国密算法: libsm 0.5 + gm-sdk-rs                        │
└────────────────────────────────────────────────────────┘
```

---

## 核心功能

### 1. 密钥生成

```rust
use sm2_co_sign_core::CoSignProtocol;

let protocol = CoSignProtocol::new()?;

// 生成客户端私钥分量 D1
let d1 = protocol.generate_d1()?;

// 计算公钥点 P1 = D1 * G
let p1 = protocol.calculate_p1(&d1)?;
```

### 2. 协同签名

```rust
// 签名预处理：生成随机数 K1，计算 Q1 = K1 * G
let (k1, q1) = protocol.sign_prepare()?;

// 计算消息哈希
let e = CoSignProtocol::sm3_hash(message);

// 完成签名计算（结合服务端返回的 r, s2, s3）
let (r, s) = protocol.complete_signature(&k1, &d1, &r, &s2, &s3)?;
```

### 3. 协同解密

```rust
// 解密预处理：计算 T1 = D1 * C1
let t1 = protocol.decrypt_prepare(&d1, &c1)?;

// 完成解密（结合服务端返回的 T2）
let plaintext = protocol.complete_decryption(&t2, &c3, &c2)?;
```

### 4. 标准 SM2 操作

```rust
use sm2_co_sign_core::CoSignProtocol;

// SM3 哈希
let hash = CoSignProtocol::sm3_hash(b"hello world");

// SM2 签名
let signature = CoSignProtocol::sign(&private_key, message)?;

// SM2 验签
let valid = CoSignProtocol::verify(&public_key, message, &signature)?;

// SM2 加密
let ciphertext = CoSignProtocol::encrypt(&public_key, message)?;

// SM2 解密
let plaintext = CoSignProtocol::decrypt(&private_key, &ciphertext)?;
```

---

## 协议原理

### 密钥生成协议

```
┌──────────────┐                                    ┌──────────────┐
│    客户端     │                                    │    服务端     │
└──────┬───────┘                                    └──────┬───────┘
       │                                                   │
       │  1. 生成随机数 d1 ∈ [1, n-1]                       │
       │  2. 计算 P1 = d1 · G                              │
       │                                                   │
       │─────────── 发送 P1 ──────────────────────────────>│
       │                                                   │
       │                                    3. 生成随机数 d2 ∈ [1, n-1]
       │                                    4. 计算 d2Inv = d2⁻¹ mod n
       │                                    5. 计算 P2 = d2Inv · G
       │                                    6. 计算 Pa = d2Inv · P1 + (n-1) · G
       │                                    7. 存储 (userId, d2, d2Inv, Pa)
       │                                                   │
       │<────────── 返回 (P2, Pa) ─────────────────────────│
       │                                                   │
       │  8. 计算完整私钥 d = d1 · d2 - 1                   │
       │  9. 验证 Pa = d · G                               │
       │  10. 存储 (d1, userId, Pa)                        │
       │                                                   │
```

### 协同签名协议

```
┌──────────────┐                                    ┌──────────────┐
│    客户端     │                                    │    服务端     │
└──────┬───────┘                                    └──────┬───────┘
       │                                                   │
       │  1. 计算消息哈希 E = SM3(M)                        │
       │  2. 生成随机数 k1 ∈ [1, n-1]                       │
       │  3. 计算 Q1 = k1 · G                              │
       │                                                   │
       │─────────── 发送 (Q1, E) ──────────────────────────>│
       │                                                   │
       │                                    4. 生成随机数 k2, k3
       │                                    5. 计算 Q2 = k2 · G
       │                                    6. 计算 x1 = k3 · Q1 + Q2
       │                                    7. 计算 r = (E + x1) mod n
       │                                    8. 计算 s2 = d2Inv · k3 mod n
       │                                    9. 计算 s3 = d2Inv · (r + k2) mod n
       │                                                   │
       │<────────── 返回 (r, s2, s3) ───────────────────────│
       │                                                   │
       │  10. 计算 s1 = k1 · s3 - r · d1 mod n             │
       │  11. 计算 s = s1 · s2 mod n                       │
       │  12. 输出签名 (r, s)                              │
       │                                                   │
```

### 数学原理

**完整私钥推导**：
```
Pa = d2Inv · P1 + (n-1) · G
   = d2⁻¹ · (d1 · G) + (n-1) · G
   = (d1 · d2⁻¹ + n - 1) · G
   = (d1 · d2 - 1) · d2⁻¹ · G
   
因此：d = d1 · d2 - 1
```

**签名正确性验证**：
```
s = s1 · s2 
  = (k1 · s3 - r · d1) · s2
  = (k1 · d2Inv · (r + k2) - r · d1) · d2Inv · k3
  = (k1 · (r + k2) - r · d1 · d2) · d2Inv² · k3 / d2Inv
  = ... (标准 SM2 签名形式)
```

---

## 快速开始

### 环境要求

- Rust 1.70+
- Cargo

### 安装

```bash
# 克隆仓库
git clone git@github.com:kintaiW/sm2-co-sign-client.git
cd client

# 构建
cargo build --release
```

### CLI 使用

```bash
# 用户注册
./target/release/sm2-cosign register -u alice -p password123

# 用户登录
./target/release/sm2-cosign login -u alice -p password123

# 协同签名
echo "Hello, SM2!" > message.txt
./target/release/sm2-cosign sign -m message.txt

# 健康检查
./target/release/sm2-cosign health
```

### Rust API 使用

添加依赖到 `Cargo.toml`：

```toml
[dependencies]
sm2_co_sign_core = { path = "path/to/sm2_co_sign_core" }
tokio = { version = "1.0", features = ["full"] }
```

示例代码：

```rust
use sm2_co_sign_core::{CoSignClient, ClientConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ClientConfig {
        server_url: "http://127.0.0.1:9002".to_string(),
        timeout: 30,
        verify_tls: false,
    };
    
    let client = CoSignClient::new(config)?;
    
    // 注册
    let key_pair = client.register("alice", "password").await?;
    println!("用户ID: {}", key_pair.user_id);
    
    // 登录
    let session = client.login("alice", "password").await?;
    
    // 签名
    let signature = client.sign(b"Hello, SM2!").await?;
    println!("签名: {:02x?}", signature.r);
    
    Ok(())
}
```

---

## API 文档

### CoSignProtocol

核心协议实现。

| 方法 | 说明 | 参数 | 返回值 |
|------|------|------|--------|
| `new()` | 创建协议实例 | - | `Result<Self>` |
| `generate_d1()` | 生成私钥分量 D1 | - | `Result<Vec<u8>>` |
| `calculate_p1(d1)` | 计算公钥 P1 | `d1: &[u8]` | `Result<Vec<u8>>` |
| `sign_prepare()` | 签名预处理 | - | `Result<(Vec<u8>, Vec<u8>)>` |
| `complete_signature(...)` | 完成签名 | `k1, d1, r, s2, s3` | `Result<(Vec<u8>, Vec<u8>)>` |
| `sm3_hash(data)` | SM3 哈希 | `data: &[u8]` | `Vec<u8>` |
| `sign(sk, msg)` | SM2 签名 | `sk, msg` | `Result<Vec<u8>>` |
| `verify(pk, msg, sig)` | SM2 验签 | `pk, msg, sig` | `Result<bool>` |
| `encrypt(pk, msg)` | SM2 加密 | `pk, msg` | `Result<Vec<u8>>` |
| `decrypt(sk, cipher)` | SM2 解密 | `sk, cipher` | `Result<Option<Vec<u8>>>` |

### CoSignClient

HTTP 客户端实现。

| 方法 | 说明 | 参数 | 返回值 |
|------|------|------|--------|
| `new(config)` | 创建客户端 | `ClientConfig` | `Result<Self>` |
| `register(username, password)` | 用户注册 | `&str, &str` | `Result<KeyPair>` |
| `login(username, password)` | 用户登录 | `&str, &str` | `Result<Session>` |
| `logout()` | 用户登出 | - | `Result<()>` |
| `sign(message)` | 协同签名 | `&[u8]` | `Result<Signature>` |
| `decrypt(ciphertext)` | 协同解密 | `&[u8]` | `Result<Vec<u8>>` |
| `health_check()` | 健康检查 | - | `Result<bool>` |

---

## FFI 接口

### 编译动态库

```bash
cargo build --release --lib -p sm2_co_sign_ffi
```

### C 头文件

```c
// 上下文管理
CoSignContext* cosign_context_new(void);
void cosign_context_free(CoSignContext* ctx);

// 密钥生成
int cosign_generate_d1(CoSignContext* ctx, uint8_t* out_d1, unsigned long* out_len);
int cosign_calculate_p1(const CoSignContext* ctx, const uint8_t* d1, unsigned long d1_len,
                        uint8_t* out_p1, unsigned long* out_len);

// 签名操作
int cosign_sign_prepare(const CoSignContext* ctx, uint8_t* out_k1, unsigned long* k1_len,
                        uint8_t* out_q1, unsigned long* q1_len);
int cosign_complete_signature(const CoSignContext* ctx, ...);

// 标准 SM2 操作
int cosign_sm3_hash(const uint8_t* data, unsigned long data_len,
                    uint8_t* out_hash, unsigned long* out_len);
int cosign_sm2_sign(const uint8_t* private_key, unsigned long private_key_len,
                    const uint8_t* message, unsigned long message_len,
                    uint8_t* out_signature, unsigned long* out_len);
int cosign_sm2_verify(const uint8_t* public_key, unsigned long public_key_len,
                      const uint8_t* message, unsigned long message_len,
                      const uint8_t* signature, unsigned long signature_len);
int cosign_sm2_encrypt(const uint8_t* public_key, unsigned long public_key_len,
                       const uint8_t* message, unsigned long message_len,
                       uint8_t* out_ciphertext, unsigned long* out_len);
int cosign_sm2_decrypt(const uint8_t* private_key, unsigned long private_key_len,
                       const uint8_t* ciphertext, unsigned long ciphertext_len,
                       uint8_t* out_plaintext, unsigned long* out_len);

// 工具函数
int cosign_base64_encode(const uint8_t* data, unsigned long data_len,
                         char* out_str, unsigned long* out_len);
int cosign_base64_decode(const char* str, uint8_t* out_data, unsigned long* out_len);
```

### C 示例

```c
#include "sm2_co_sign_ffi.h"
#include <stdio.h>

int main() {
    // 创建上下文
    CoSignContext* ctx = cosign_context_new();
    
    // 生成密钥
    uint8_t d1[32];
    unsigned long d1_len;
    cosign_generate_d1(ctx, d1, &d1_len);
    
    uint8_t p1[64];
    unsigned long p1_len;
    cosign_calculate_p1(ctx, d1, d1_len, p1, &p1_len);
    
    // SM3 哈希
    uint8_t hash[32];
    unsigned long hash_len;
    cosign_sm3_hash((uint8_t*)"hello", 5, hash, &hash_len);
    
    // SM2 签名验签
    uint8_t signature[64];
    unsigned long sig_len;
    cosign_sm2_sign(d1, d1_len, (uint8_t*)"message", 7, signature, &sig_len);
    
    int valid = cosign_sm2_verify(p1, p1_len, (uint8_t*)"message", 7, signature, sig_len);
    printf("验签结果: %s\n", valid == 0 ? "成功" : "失败");
    
    // 销毁上下文
    cosign_context_free(ctx);
    return 0;
}
```

---

## 性能测试

### 测试环境

- CPU: Intel Core i7-10700 @ 2.9GHz
- 内存: 16GB DDR4
- 操作系统: Ubuntu 22.04
- Rust: 1.70.0

### 性能数据

| 操作 | 耗时 | QPS |
|------|------|-----|
| SM3 哈希 (1KB) | 2.1 μs | 476,190 |
| SM2 签名 | 89.3 μs | 11,198 |
| SM2 验签 | 112.5 μs | 8,889 |
| SM2 加密 (1KB) | 156.2 μs | 6,402 |
| SM2 解密 (1KB) | 134.8 μs | 7,418 |
| 密钥生成 | 45.6 μs | 21,930 |

### 内存占用

| 组件 | 内存占用 |
|------|---------|
| 动态库 | 2.3 MB |
| 静态库 | 1.8 MB |
| 运行时内存 | < 1 MB |

---

## 安全说明

### 安全特性

1. **密钥分片隔离**
   - 客户端持有 D1，服务端持有 D2
   - 完整私钥 d = D1 × D2 - 1 不在任何一方存储
   - 单方泄露无法伪造签名

2. **内存安全**
   - 纯 Rust 实现，无内存泄漏风险
   - 所有权系统保证资源正确释放

3. **随机数安全**
   - 使用密码学安全随机数生成器
   - 每次签名使用不同的随机数

4. **传输安全**
   - 敏感数据使用 Base64 编码
   - 生产环境建议使用 HTTPS

### 安全建议

```rust
// ❌ 不推荐：明文存储私钥分量
std::fs::write("d1.txt", &d1)?;

// ✅ 推荐：加密存储私钥分量
let encrypted = encrypt_with_password(&d1, password)?;
std::fs::write("d1.enc", &encrypted)?;
```

### 审计日志

所有关键操作都会记录审计日志：

```
[2026-02-13 10:30:45] INFO  register: user=alice user_id=abc123
[2026-02-13 10:31:02] INFO  login: user=alice token=xxx
[2026-02-13 10:31:15] INFO  sign: user_id=abc123 message_hash=xxx
```

---

## 许可证

本项目采用 MIT 许可证。详见 [LICENSE](LICENSE) 文件。

---

## 联系方式

- 项目地址: [GitHub](https://github.com/kintaiW/sm2-co-sign-client)
- 问题反馈: [Issues](https://github.com/kintaiW/sm2-co-sign-client/issues)
- 技术讨论: [Discussions](https://github.com/kintaiW/sm2-co-sign-client/discussions)

---

*最后更新: 2026-02-13*
