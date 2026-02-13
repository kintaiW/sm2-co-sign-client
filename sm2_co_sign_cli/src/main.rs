//! SM2 协同签名 CLI 工具

use clap::{Parser, Subcommand};
use sm2_co_sign_core::{CoSignClient, ClientConfig};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "sm2-co-sign")]
#[command(about = "SM2 协同签名客户端工具", long_about = None)]
struct Cli {
    /// 服务器地址
    #[arg(short, long, default_value = "http://127.0.0.1:9002")]
    server: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// 用户注册
    Register {
        /// 用户名
        #[arg(short, long)]
        username: String,
        /// 密码
        #[arg(short, long)]
        password: String,
    },
    /// 用户登录
    Login {
        /// 用户名
        #[arg(short, long)]
        username: String,
        /// 密码
        #[arg(short, long)]
        password: String,
    },
    /// 用户登出
    Logout {
        /// Token 文件路径
        #[arg(short, long, default_value = ".token")]
        token_file: PathBuf,
    },
    /// 协同签名
    Sign {
        /// Token 文件路径
        #[arg(short, long, default_value = ".token")]
        token_file: PathBuf,
        /// D1 文件路径
        #[arg(long, default_value = ".d1")]
        d1_file: PathBuf,
        /// 消息文件路径
        #[arg(short, long)]
        message: PathBuf,
        /// 输出签名文件路径
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// 协同解密
    Decrypt {
        /// Token 文件路径
        #[arg(short, long, default_value = ".token")]
        token_file: PathBuf,
        /// D1 文件路径
        #[arg(long, default_value = ".d1")]
        d1_file: PathBuf,
        /// 密文文件路径
        #[arg(short, long)]
        ciphertext: PathBuf,
        /// 输出明文文件路径
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// 健康检查
    Health,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    
    let config = ClientConfig {
        server_url: cli.server.clone(),
        timeout: 30,
        verify_tls: false,
    };
    
    match cli.command {
        Commands::Register { username, password } => {
            do_register(&config, &username, &password).await?;
        }
        Commands::Login { username, password } => {
            do_login(&config, &username, &password).await?;
        }
        Commands::Logout { token_file } => {
            do_logout(&config, &token_file).await?;
        }
        Commands::Sign { token_file, d1_file, message, output } => {
            do_sign(&config, &token_file, &d1_file, &message, output.as_ref()).await?;
        }
        Commands::Decrypt { token_file, d1_file, ciphertext, output } => {
            do_decrypt(&config, &token_file, &d1_file, &ciphertext, output.as_ref()).await?;
        }
        Commands::Health => {
            do_health(&config).await?;
        }
    }
    
    Ok(())
}

async fn do_register(config: &ClientConfig, username: &str, password: &str) -> anyhow::Result<()> {
    println!("正在注册用户: {}", username);
    
    let client = CoSignClient::new(config.clone())?;
    let key_pair = client.register(username, password).await?;
    
    println!("注册成功!");
    println!("用户ID: {}", key_pair.user_id);
    println!("请保存您的私钥分量 d1");
    
    // 保存 d1 到文件
    std::fs::write(".d1", &key_pair.d1)?;
    println!("私钥分量已保存到 .d1 文件");
    
    // 保存 user_id 到文件
    std::fs::write(".user_id", &key_pair.user_id)?;
    println!("用户ID已保存到 .user_id 文件");
    
    // 保存公钥到文件
    std::fs::write(".public_key", &key_pair.public_key)?;
    println!("公钥已保存到 .public_key 文件");
    
    Ok(())
}

async fn do_login(config: &ClientConfig, username: &str, password: &str) -> anyhow::Result<()> {
    println!("正在登录用户: {}", username);
    
    let client = CoSignClient::new(config.clone())?;
    let session = client.login(username, password).await?;
    
    println!("登录成功!");
    println!("Token: {}", session.token);
    
    // 保存 token 到文件
    std::fs::write(".token", &session.token)?;
    println!("Token 已保存到 .token 文件");
    
    // 保存 user_id 到文件
    std::fs::write(".user_id", &session.user_id)?;
    println!("用户ID已保存到 .user_id 文件");
    
    Ok(())
}

async fn do_logout(config: &ClientConfig, _token_file: &PathBuf) -> anyhow::Result<()> {
    println!("正在登出...");
    
    let client = CoSignClient::new(config.clone())?;
    client.logout().await?;
    
    // 删除 token 文件
    let _ = std::fs::remove_file(".token");
    
    println!("登出成功!");
    
    Ok(())
}

async fn do_sign(config: &ClientConfig, _token_file: &PathBuf, d1_file: &PathBuf, message_file: &PathBuf, output: Option<&PathBuf>) -> anyhow::Result<()> {
    // 读取必要的文件
    let token = std::fs::read_to_string(".token")
        .map_err(|_| anyhow::anyhow!("请先登录（.token 文件不存在）"))?;
    let d1 = std::fs::read(d1_file)
        .map_err(|_| anyhow::anyhow!("请先注册（.d1 文件不存在）"))?;
    let user_id = std::fs::read_to_string(".user_id")
        .map_err(|_| anyhow::anyhow!("请先注册（.user_id 文件不存在）"))?;
    let public_key = std::fs::read(".public_key")
        .map_err(|_| anyhow::anyhow!("请先注册（.public_key 文件不存在）"))?;
    let message = std::fs::read(message_file)?;
    
    println!("正在签名...");
    
    // 创建客户端并设置会话
    let client = CoSignClient::new(config.clone())?;
    
    // 手动设置会话和密钥对
    client.set_session(token, user_id.clone()).await?;
    client.set_key_pair(d1, public_key, user_id).await?;
    
    // 执行签名
    let signature = client.sign(&message).await?;
    
    // 组合签名 r || s
    let mut sig_bytes = Vec::with_capacity(64);
    sig_bytes.extend_from_slice(&signature.r);
    sig_bytes.extend_from_slice(&signature.s);
    
    if let Some(output_path) = output {
        std::fs::write(output_path, &sig_bytes)?;
        println!("签名已保存到: {:?}", output_path);
    } else {
        println!("签名: {}", hex::encode(&sig_bytes));
    }
    
    Ok(())
}

async fn do_decrypt(config: &ClientConfig, _token_file: &PathBuf, d1_file: &PathBuf, ciphertext_file: &PathBuf, output: Option<&PathBuf>) -> anyhow::Result<()> {
    // 读取必要的文件
    let token = std::fs::read_to_string(".token")
        .map_err(|_| anyhow::anyhow!("请先登录（.token 文件不存在）"))?;
    let d1 = std::fs::read(d1_file)
        .map_err(|_| anyhow::anyhow!("请先注册（.d1 文件不存在）"))?;
    let user_id = std::fs::read_to_string(".user_id")
        .map_err(|_| anyhow::anyhow!("请先注册（.user_id 文件不存在）"))?;
    let public_key = std::fs::read(".public_key")
        .map_err(|_| anyhow::anyhow!("请先注册（.public_key 文件不存在）"))?;
    let ciphertext = std::fs::read(ciphertext_file)?;
    
    println!("正在解密...");
    
    // 创建客户端并设置会话
    let client = CoSignClient::new(config.clone())?;
    
    // 手动设置会话和密钥对
    client.set_session(token, user_id.clone()).await?;
    client.set_key_pair(d1, public_key, user_id).await?;
    
    // 执行解密
    let plaintext = client.decrypt(&ciphertext).await?;
    
    if let Some(output_path) = output {
        std::fs::write(output_path, &plaintext)?;
        println!("明文已保存到: {:?}", output_path);
    } else {
        println!("明文: {}", String::from_utf8_lossy(&plaintext));
    }
    
    Ok(())
}

async fn do_health(config: &ClientConfig) -> anyhow::Result<()> {
    let client = CoSignClient::new(config.clone())?;
    let healthy = client.health_check().await?;
    
    if healthy {
        println!("服务状态: 正常");
    } else {
        println!("服务状态: 异常");
    }
    
    Ok(())
}
