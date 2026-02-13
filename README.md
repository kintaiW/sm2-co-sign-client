# SM2 协同签名客户端

基于 Rust 实现的 SM2 协同签名客户端，提供完整的协同签名协议实现，支持密钥分片、协同签名和协同解密功能。

## 项目概述

本项目实现了 SM2 协同签名协议的客户端部分，采用 D1/D2 密钥分片架构：
- **客户端**：持有私钥分量 D1
- **服务端**：持有私钥分量 D2

通过多轮交互完成签名和解密操作，确保私钥永不完整出现在任何一方。

### 核心功能

- **密钥生成**：生成客户端私钥分量 D1，计算 P1 = D1 * G
- **协同签名**：与服务端协作完成 SM2 签名
- **协同解密**：与服务端协作完成 SM2 解密
- **SM3 哈希**：支持 SM3 消息摘要算法
- **SM4 加密**：支持 SM4 对称加密算法

## 项目结构

```
client/
├── Cargo.toml                    # 工作空间配置
├── Cargo.lock                    # 依赖锁定文件
├── README.md                     # 本文档
│
├── sm2_co_sign_core/             # 核心库
│   ├── Cargo.toml
│   ├── src/
│   │   ├── lib.rs               # 库入口
│   │   ├── client.rs            # HTTP 客户端实现
│   │   ├── protocol.rs          # 协同签名协议实现
│   │   ├── types.rs             # 类型定义
│   │   └── error.rs             # 错误处理
│   └── tests/
│       └── integration_test.rs  # 集成测试
│
├── sm2_co_sign_cli/              # 命令行工具
│   ├── Cargo.toml
│   └── src/
│       └── main.rs              # CLI 入口
│
└── sm2_co_sign_ffi/              # FFI 绑定（动态库/静态库）
    ├── Cargo.toml
    └── src/
        └── lib.rs               # FFI 接口定义
```

## 依赖说明

### 国密算法库

本项目使用 [gm-sdk-rs](https://github.com/kintaiW/gm-sdk-rs.git) 作为国密算法实现：

- SM2：椭圆曲线公钥密码算法
- SM3：密码杂凑算法
- SM4：分组密码算法

### 主要依赖

| 依赖 | 版本 | 用途 |
|------|------|------|
| tokio | 1.0 | 异步运行时 |
| reqwest | 0.11 | HTTP 客户端 |
| serde | 1.0 | 序列化 |
| clap | 4.0 | CLI 框架 |
| thiserror | 1.0 | 错误处理 |

## 构建说明

### 环境要求

- Rust 1.70+
- Cargo

### 开发构建

```bash
# 进入项目目录
cd client

# 开发模式构建
cargo build

# 运行测试
cargo test

# 运行集成测试（需要后台服务运行在 127.0.0.1:8080）
cargo test --test integration_test
```

### 发布构建

```bash
# 发布模式构建（优化编译）
cargo build --release

# 构建产物位置
# - CLI: target/release/sm2-cosign
# - FFI: target/release/libsm2_co_sign_ffi.so (Linux)
#      或 target/release/libsm2_co_sign_ffi.dylib (macOS)
#      或 target/release/sm2_co_sign_ffi.dll (Windows)
```

## CLI 使用指南

### 编译 CLI 工具

```bash
# 开发构建
cargo build --bin sm2-cosign

# 发布构建
cargo build --release --bin sm2-cosign
```

### CLI 命令

#### 查看帮助

```bash
./target/release/sm2-cosign --help
```

#### 用户注册

```bash
# 注册新用户并生成密钥对
./target/release/sm2-cosign register -u <用户名> -p <密码>

# 示例
./target/release/sm2-cosign register -u alice -p password123
```

注册成功后会：
1. 生成客户端私钥分量 D1
2. 向服务端发送 P1 = D1 * G
3. 保存 D1 到 `.d1` 文件

#### 用户登录

```bash
# 用户登录获取 Token
./target/release/sm2-cosign login -u <用户名> -p <密码>

# 示例
./target/release/sm2-cosign login -u alice -p password123
```

登录成功后 Token 会保存到 `.token` 文件。

#### 用户登出

```bash
# 用户登出
./target/release/sm2-cosign logout
```

#### 协同签名

```bash
# 对文件进行签名
./target/release/sm2-cosign sign -m <消息文件> [-o <输出文件>]

# 示例：签名并输出到文件
./target/release/sm2-cosign sign -m message.txt -o signature.bin

# 示例：签名并输出到终端
./target/release/sm2-cosign sign -m message.txt
```

#### 协同解密

```bash
# 解密 SM2 密文
./target/release/sm2-cosign decrypt -c <密文文件> [-o <输出文件>]

# 示例
./target/release/sm2-cosign decrypt -c ciphertext.bin -o plaintext.txt
```

#### 健康检查

```bash
# 检查服务端状态
./target/release/sm2-cosign health
```

### 指定服务端地址

所有命令都支持 `-s` 或 `--server` 参数指定服务端地址：

```bash
./target/release/sm2-cosign -s http://192.168.1.100:8080 health
```

## FFI 动态库编译

### 编译动态库

```bash
# Linux/macOS
cargo build --release --lib -p sm2_co_sign_ffi

# 构建产物
# Linux:   target/release/libsm2_co_sign_ffi.so
# macOS:   target/release/libsm2_co_sign_ffi.dylib
# Windows: target/release/sm2_co_sign_ffi.dll
```

### 编译静态库

```bash
cargo build --release --lib -p sm2_co_sign_ffi

# 构建产物
# Linux/macOS: target/release/libsm2_co_sign_ffi.a
# Windows:     target/release/sm2_co_sign_ffi.lib
```

### 生成 C 头文件

```bash
# 安装 cbindgen（如果未安装）
cargo install cbindgen

# 生成头文件
cbindgen --crate sm2_co_sign_ffi -o sm2_co_sign_ffi.h
```

### FFI 接口说明

主要 C 接口函数：

```c
// 创建协议上下文
CoSignContext* cosign_context_new(void);

// 销毁协议上下文
void cosign_context_free(CoSignContext* ctx);

// 生成私钥分量 D1
int cosign_generate_d1(CoSignContext* ctx, uint8_t* out_d1, uint32_t* out_len);

// 计算 P1 = D1 * G
int cosign_calculate_p1(const CoSignContext* ctx, const uint8_t* d1, uint32_t d1_len,
                        uint8_t* out_p1, uint32_t* out_len);

// 签名预处理
int cosign_sign_prepare(const CoSignContext* ctx, uint8_t* out_k1, uint32_t* k1_len,
                        uint8_t* out_q1, uint32_t* q1_len);

// 完成签名计算
int cosign_complete_signature(const CoSignContext* ctx, const uint8_t* k1, uint32_t k1_len,
                              const uint8_t* d1, uint32_t d1_len,
                              const uint8_t* r, uint32_t r_len,
                              const uint8_t* s2, uint32_t s2_len,
                              const uint8_t* s3, uint32_t s3_len,
                              uint8_t* out_r, uint32_t* out_r_len,
                              uint8_t* out_s, uint32_t* out_s_len);

// SM3 哈希
int cosign_sm3_hash(const uint8_t* data, uint32_t data_len,
                    uint8_t* out_hash, uint32_t* out_len);

// Base64 编解码
int cosign_base64_encode(const uint8_t* data, uint32_t data_len,
                         char* out_str, uint32_t* out_len);
int cosign_base64_decode(const char* str, uint8_t* out_data, uint32_t* out_len);
```

### 错误码定义

| 错误码 | 说明 |
|--------|------|
| 0 | 成功 |
| -1 | 空指针错误 |
| -2 | 参数无效 |
| -3 | 密码算法错误 |
| -4 | 网络错误 |
| -5 | 编码错误 |

## 核心 API 使用示例

### Rust 代码示例

```rust
use sm2_co_sign_core::{CoSignClient, ClientConfig, CoSignProtocol};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 创建客户端配置
    let config = ClientConfig {
        server_url: "http://127.0.0.1:8080".to_string(),
        timeout: 30,
        verify_tls: false,
    };
    
    // 创建客户端
    let client = CoSignClient::new(config)?;
    
    // 用户注册
    let key_pair = client.register("alice", "password123").await?;
    println!("用户ID: {}", key_pair.user_id);
    println!("公钥: {:?}", key_pair.public_key);
    
    // 用户登录
    let session = client.login("alice", "password123").await?;
    println!("Token: {}", session.token);
    
    // 协同签名
    let message = b"Hello, SM2 Co-Sign!";
    let signature = client.sign(message).await?;
    println!("签名 R: {:?}", signature.r);
    println!("签名 S: {:?}", signature.s);
    
    // 用户登出
    client.logout().await?;
    
    Ok(())
}
```

### 协议直接使用

```rust
use sm2_co_sign_core::CoSignProtocol;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protocol = CoSignProtocol::new()?;
    
    // 生成 D1
    let d1 = protocol.generate_d1()?;
    println!("D1: {:?}", d1);
    
    // 计算 P1 = D1 * G
    let p1 = protocol.calculate_p1(&d1)?;
    println!("P1: {:?}", p1);
    
    // SM3 哈希
    let hash = CoSignProtocol::sm3_hash(b"hello world");
    println!("Hash: {:?}", hash);
    
    // 签名预处理
    let (k1, q1) = protocol.sign_prepare()?;
    println!("K1: {:?}", k1);
    println!("Q1: {:?}", q1);
    
    Ok(())
}
```

## 协同签名协议流程

### 密钥生成

```
客户端                                服务端
   |                                    |
   |--- 生成 D1 ----------------------->|
   |--- 计算 P1 = D1 * G -------------->|
   |                                    |--- 生成 D2
   |                                    |--- 计算 D2Inv = D2^(-1) mod n
   |                                    |--- 计算 P2 = D2Inv * G
   |                                    |--- 计算 Pa = D2Inv * P1 + (n-1) * G
   |<--- 返回 P2, Pa -------------------|
   |                                    |
   |--- 存储 D1                         |--- 存储 (D2, D2Inv, Pa)
   |--- 完整私钥 d = D1 * D2 - 1        |
```

### 协同签名

```
客户端                                服务端
   |                                    |
   |--- 生成 K1                         |
   |--- 计算 Q1 = K1 * G -------------->|
   |--- 计算 E = SM3(M) --------------->|
   |                                    |--- 生成 (K2, K3)
   |                                    |--- 计算 Q2 = K2 * G
   |                                    |--- 计算 x1 = K3 * Q1 + Q2
   |                                    |--- 计算 r = E + x1 mod n
   |                                    |--- 计算 s2 = D2 * K3 mod n
   |                                    |--- 计算 s3 = D2 * (r + K2) mod n
   |<--- 返回 (r, s2, s3) --------------|
   |                                    |
   |--- 计算 s1 = K1 * s3 - r * D1 mod n|
   |--- 计算 s = s1 * s2 mod n          |
   |--- 最终签名 (r, s)                 |
```

## 测试

### 单元测试

```bash
# 运行所有单元测试
cargo test

# 运行特定测试
cargo test test_sm2_sign_verify
```

### 集成测试

```bash
# 确保后台服务运行在 127.0.0.1:8080
cargo test --test integration_test
```

## 许可证

Apache License 2.0
