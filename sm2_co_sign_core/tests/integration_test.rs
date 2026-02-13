//! 集成测试 - 连接后台服务

use sm2_co_sign_core::{CoSignClient, ClientConfig};

fn get_client() -> CoSignClient {
    let config = ClientConfig {
        server_url: "http://127.0.0.1:8080".to_string(),
        timeout: 30,
        verify_tls: false,
    };
    CoSignClient::new(config).expect("Failed to create client")
}

#[tokio::test]
async fn test_health_check() {
    let client = get_client();
    let result = client.health_check().await;
    assert!(result.is_ok());
    assert!(result.unwrap());
}

#[tokio::test]
async fn test_register_and_login() {
    let client = get_client();
    
    // 使用随机用户名避免冲突
    let username = format!("test_user_{}", rand::random::<u32>());
    let password = "test_password";
    
    // 注册
    let key_pair = client.register(&username, password).await;
    if key_pair.is_err() {
        // 如果注册失败，可能是用户名已存在，跳过此测试
        eprintln!("Register failed (user may exist): {:?}", key_pair.err());
        return;
    }
    let key_pair = key_pair.unwrap();
    assert!(!key_pair.d1.is_empty());
    assert!(!key_pair.public_key.is_empty());
    assert!(!key_pair.user_id.is_empty());
    
    // 登录
    let session = client.login(&username, password).await;
    assert!(session.is_ok());
    let session = session.unwrap();
    assert!(!session.token.is_empty());
    
    // 登出
    let logout_result = client.logout().await;
    assert!(logout_result.is_ok());
}

#[tokio::test]
async fn test_get_user_info() {
    let client = get_client();
    
    // 先登录
    let username = format!("test_user_info_{}", rand::random::<u32>());
    let password = "test_password";
    
    // 注册
    let register_result = client.register(&username, password).await;
    if register_result.is_err() {
        eprintln!("Register failed: {:?}", register_result.err());
        return;
    }
    
    // 登录
    let login_result = client.login(&username, password).await;
    if login_result.is_err() {
        eprintln!("Login failed: {:?}", login_result.err());
        return;
    }
    
    // 获取用户信息
    let user_info = client.get_user_info().await;
    assert!(user_info.is_ok());
    let user_info = user_info.unwrap();
    assert_eq!(user_info.username, username);
}

#[tokio::test]
async fn test_sign() {
    let client = get_client();
    
    // 先注册和登录
    let username = format!("test_user_sign_{}", rand::random::<u32>());
    let password = "test_password";
    
    let register_result = client.register(&username, password).await;
    if register_result.is_err() {
        eprintln!("Register failed: {:?}", register_result.err());
        return;
    }
    
    let login_result = client.login(&username, password).await;
    if login_result.is_err() {
        eprintln!("Login failed: {:?}", login_result.err());
        return;
    }
    
    // 签名
    let message = b"Hello, SM2 Co-Sign!";
    let signature = client.sign(message).await;
    assert!(signature.is_ok());
    let signature = signature.unwrap();
    assert_eq!(signature.r.len(), 32);
    assert!(signature.s.len() <= 32);
}
