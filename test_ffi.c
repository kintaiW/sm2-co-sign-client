/**
 * SM2 协同签名 FFI 测试程序
 * 
 * 测试内容：
 * 1. SM3 哈希计算
 * 2. SM2 签名和验签
 * 3. SM2 加密和解密
 * 4. Base64 编解码
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sm2_co_sign_ffi.h"

// 打印十六进制数据
void print_hex(const char *label, const unsigned char *data, unsigned long len) {
    printf("%s: ", label);
    for (unsigned long i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// 测试 SM3 哈希
int test_sm3_hash() {
    printf("\n=== 测试 SM3 哈希 ===\n");
    
    const char *data = "hello world";
    unsigned char hash[32];
    unsigned long hash_len = 0;
    
    int result = cosign_sm3_hash((const unsigned char *)data, strlen(data), hash, &hash_len);
    
    if (result != COSIGN_OK) {
        printf("SM3 哈希失败: %d\n", result);
        return -1;
    }
    
    print_hex("SM3 哈希值", hash, hash_len);
    printf("SM3 哈希测试通过！\n");
    return 0;
}

// 测试 SM2 签名和验签
int test_sm2_sign_verify() {
    printf("\n=== 测试 SM2 签名和验签 ===\n");
    
    // 创建上下文
    CoSignContext *ctx = cosign_context_new();
    if (ctx == NULL) {
        printf("创建上下文失败\n");
        return -1;
    }
    
    // 生成私钥 D1
    unsigned char d1[32];
    unsigned long d1_len = 0;
    int result = cosign_generate_d1(ctx, d1, &d1_len);
    if (result != COSIGN_OK) {
        printf("生成 D1 失败: %d\n", result);
        cosign_context_free(ctx);
        return -1;
    }
    print_hex("私钥 D1", d1, d1_len);
    
    // 计算公钥 P1 = D1 * G
    unsigned char p1[64];
    unsigned long p1_len = 0;
    result = cosign_calculate_p1(ctx, d1, d1_len, p1, &p1_len);
    if (result != COSIGN_OK) {
        printf("计算 P1 失败: %d\n", result);
        cosign_context_free(ctx);
        return -1;
    }
    print_hex("公钥 P1", p1, p1_len);
    
    // 准备消息
    const char *message = "Hello, SM2 Co-Sign!";
    unsigned long message_len = strlen(message);
    printf("消息: %s\n", message);
    
    // SM2 签名
    unsigned char signature[64];
    unsigned long sig_len = 0;
    result = cosign_sm2_sign(d1, d1_len, (const unsigned char *)message, message_len, signature, &sig_len);
    if (result != COSIGN_OK) {
        printf("SM2 签名失败: %d\n", result);
        cosign_context_free(ctx);
        return -1;
    }
    print_hex("签名值", signature, sig_len);
    
    // SM2 验签
    result = cosign_sm2_verify(p1, p1_len, (const unsigned char *)message, message_len, signature, sig_len);
    if (result != COSIGN_OK) {
        printf("SM2 验签失败: %d\n", result);
        cosign_context_free(ctx);
        return -1;
    }
    
    printf("SM2 签名和验签测试通过！\n");
    
    // 测试错误签名验签
    signature[0] ^= 0xff;  // 篡改签名
    result = cosign_sm2_verify(p1, p1_len, (const unsigned char *)message, message_len, signature, sig_len);
    if (result == COSIGN_OK) {
        printf("错误：篡改后的签名应该验签失败！\n");
        cosign_context_free(ctx);
        return -1;
    }
    printf("篡改签名验签失败（符合预期）\n");
    
    cosign_context_free(ctx);
    return 0;
}

// 测试 SM2 加密和解密
int test_sm2_encrypt_decrypt() {
    printf("\n=== 测试 SM2 加密和解密 ===\n");
    
    // 创建上下文
    CoSignContext *ctx = cosign_context_new();
    if (ctx == NULL) {
        printf("创建上下文失败\n");
        return -1;
    }
    
    // 生成私钥 D1
    unsigned char d1[32];
    unsigned long d1_len = 0;
    int result = cosign_generate_d1(ctx, d1, &d1_len);
    if (result != COSIGN_OK) {
        printf("生成 D1 失败: %d\n", result);
        cosign_context_free(ctx);
        return -1;
    }
    print_hex("私钥 D1", d1, d1_len);
    
    // 计算公钥 P1 = D1 * G
    unsigned char p1[64];
    unsigned long p1_len = 0;
    result = cosign_calculate_p1(ctx, d1, d1_len, p1, &p1_len);
    if (result != COSIGN_OK) {
        printf("计算 P1 失败: %d\n", result);
        cosign_context_free(ctx);
        return -1;
    }
    print_hex("公钥 P1", p1, p1_len);
    
    // 准备明文
    const char *plaintext = "Hello, SM2 Encryption!";
    unsigned long plaintext_len = strlen(plaintext);
    printf("明文: %s\n", plaintext);
    
    // SM2 加密
    unsigned char ciphertext[256];
    unsigned long cipher_len = 0;
    result = cosign_sm2_encrypt(p1, p1_len, (const unsigned char *)plaintext, plaintext_len, ciphertext, &cipher_len);
    if (result != COSIGN_OK) {
        printf("SM2 加密失败: %d\n", result);
        cosign_context_free(ctx);
        return -1;
    }
    print_hex("密文", ciphertext, cipher_len);
    
    // SM2 解密
    unsigned char decrypted[256];
    unsigned long decrypted_len = 0;
    result = cosign_sm2_decrypt(d1, d1_len, ciphertext, cipher_len, decrypted, &decrypted_len);
    if (result != COSIGN_OK) {
        printf("SM2 解密失败: %d\n", result);
        cosign_context_free(ctx);
        return -1;
    }
    decrypted[decrypted_len] = '\0';
    printf("解密后明文: %s\n", decrypted);
    
    // 验证解密结果
    if (decrypted_len != plaintext_len || memcmp(plaintext, decrypted, plaintext_len) != 0) {
        printf("错误：解密结果与原文不匹配！\n");
        cosign_context_free(ctx);
        return -1;
    }
    
    printf("SM2 加密和解密测试通过！\n");
    
    // 测试错误密文解密
    ciphertext[10] ^= 0xff;  // 篡改密文
    result = cosign_sm2_decrypt(d1, d1_len, ciphertext, cipher_len, decrypted, &decrypted_len);
    if (result == COSIGN_OK) {
        printf("警告：篡改后的密文解密成功（可能需要检查解密验证）\n");
    } else {
        printf("篡改密文解密失败（符合预期）\n");
    }
    
    cosign_context_free(ctx);
    return 0;
}

// 测试 Base64 编解码
int test_base64() {
    printf("\n=== 测试 Base64 编解码 ===\n");
    
    const char *data = "hello world";
    unsigned long data_len = strlen(data);
    
    // Base64 编码
    char encoded[64];
    unsigned long encoded_len = 0;
    int result = cosign_base64_encode((const unsigned char *)data, data_len, encoded, &encoded_len);
    if (result != COSIGN_OK) {
        printf("Base64 编码失败: %d\n", result);
        return -1;
    }
    encoded[encoded_len] = '\0';
    printf("原始数据: %s\n", data);
    printf("Base64 编码: %s\n", encoded);
    
    // Base64 解码
    unsigned char decoded[64];
    unsigned long decoded_len = 0;
    result = cosign_base64_decode(encoded, decoded, &decoded_len);
    if (result != COSIGN_OK) {
        printf("Base64 解码失败: %d\n", result);
        return -1;
    }
    decoded[decoded_len] = '\0';
    printf("Base64 解码: %s\n", decoded);
    
    // 验证结果
    if (decoded_len != data_len || memcmp(data, decoded, data_len) != 0) {
        printf("错误：编解码结果不匹配！\n");
        return -1;
    }
    
    printf("Base64 编解码测试通过！\n");
    return 0;
}

int main(int argc, char *argv[]) {
    printf("========================================\n");
    printf("  SM2 协同签名 FFI 测试程序\n");
    printf("========================================\n");
    
    int failed = 0;
    
    // 测试 SM3 哈希
    if (test_sm3_hash() != 0) {
        failed++;
    }
    
    // 测试 SM2 签名和验签
    if (test_sm2_sign_verify() != 0) {
        failed++;
    }
    
    // 测试 SM2 加密和解密
    if (test_sm2_encrypt_decrypt() != 0) {
        failed++;
    }
    
    // 测试 Base64 编解码
    if (test_base64() != 0) {
        failed++;
    }
    
    printf("\n========================================\n");
    if (failed == 0) {
        printf("  所有测试通过！\n");
    } else {
        printf("  %d 个测试失败！\n", failed);
    }
    printf("========================================\n");
    
    return failed;
}
