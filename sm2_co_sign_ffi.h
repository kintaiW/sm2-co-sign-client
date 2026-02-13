/**
 * SM2 协同签名 FFI 头文件
 * 
 * 提供 C ABI 兼容的接口，供其他语言调用
 */

#ifndef SM2_CO_SIGN_FFI_H
#define SM2_CO_SIGN_FFI_H

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 错误码定义 */
#define COSIGN_OK               0
#define COSIGN_ERR_NULL_PTR     -1
#define COSIGN_ERR_INVALID_PARAM -2
#define COSIGN_ERR_CRYPTO       -3
#define COSIGN_ERR_NETWORK      -4
#define COSIGN_ERR_ENCODING     -5

/* 协议上下文（不透明指针） */
typedef struct CoSignContext CoSignContext;

/**
 * 创建协议上下文
 * @return 协议上下文指针，失败返回 NULL
 */
CoSignContext *cosign_context_new(void);

/**
 * 销毁协议上下文
 * @param ctx 协议上下文指针
 */
void cosign_context_free(CoSignContext *ctx);

/**
 * 生成客户端私钥分量 D1
 * @param ctx 协议上下文指针
 * @param out_d1 输出缓冲区（至少32字节）
 * @param out_len 输出长度
 * @return 错误码
 */
int cosign_generate_d1(CoSignContext *ctx, unsigned char *out_d1, unsigned long *out_len);

/**
 * 计算 P1 = d1 * G
 * @param ctx 协议上下文指针
 * @param d1 私钥分量 D1
 * @param d1_len D1 长度
 * @param out_p1 输出缓冲区（至少64字节）
 * @param out_len 输出长度
 * @return 错误码
 */
int cosign_calculate_p1(const CoSignContext *ctx,
                        const unsigned char *d1,
                        unsigned long d1_len,
                        unsigned char *out_p1,
                        unsigned long *out_len);

/**
 * 签名预处理：生成 k1，计算 Q1 = k1 * G
 * @param ctx 协议上下文指针
 * @param out_k1 输出缓冲区（至少32字节）
 * @param k1_len 输出长度
 * @param out_q1 输出缓冲区（至少64字节）
 * @param q1_len 输出长度
 * @return 错误码
 */
int cosign_sign_prepare(const CoSignContext *ctx,
                        unsigned char *out_k1,
                        unsigned long *k1_len,
                        unsigned char *out_q1,
                        unsigned long *q1_len);

/**
 * 计算消息哈希
 * @param ctx 协议上下文指针
 * @param message 消息数据
 * @param message_len 消息长度
 * @param public_key 公钥（可选）
 * @param public_key_len 公钥长度
 * @param out_hash 输出缓冲区（至少32字节）
 * @param out_len 输出长度
 * @return 错误码
 */
int cosign_hash_message(const CoSignContext *ctx,
                        const unsigned char *message,
                        unsigned long message_len,
                        const unsigned char *public_key,
                        unsigned long public_key_len,
                        unsigned char *out_hash,
                        unsigned long *out_len);

/**
 * 完成签名计算
 * @param ctx 协议上下文指针
 * @param k1 随机数 K1
 * @param k1_len K1 长度
 * @param d1 私钥分量 D1
 * @param d1_len D1 长度
 * @param r 签名分量 R
 * @param r_len R 长度
 * @param s2 签名分量 S2
 * @param s2_len S2 长度
 * @param s3 签名分量 S3
 * @param s3_len S3 长度
 * @param out_r 输出 R（至少32字节）
 * @param out_r_len 输出长度
 * @param out_s 输出 S（至少32字节）
 * @param out_s_len 输出长度
 * @return 错误码
 */
int cosign_complete_signature(const CoSignContext *ctx,
                              const unsigned char *k1,
                              unsigned long k1_len,
                              const unsigned char *d1,
                              unsigned long d1_len,
                              const unsigned char *r,
                              unsigned long r_len,
                              const unsigned char *s2,
                              unsigned long s2_len,
                              const unsigned char *s3,
                              unsigned long s3_len,
                              unsigned char *out_r,
                              unsigned long *out_r_len,
                              unsigned char *out_s,
                              unsigned long *out_s_len);

/**
 * 解密预处理：计算 T1 = d1 * C1
 * @param ctx 协议上下文指针
 * @param d1 私钥分量 D1
 * @param d1_len D1 长度
 * @param c1 密文分量 C1
 * @param c1_len C1 长度
 * @param out_t1 输出缓冲区（至少64字节）
 * @param out_len 输出长度
 * @return 错误码
 */
int cosign_decrypt_prepare(const CoSignContext *ctx,
                           const unsigned char *d1,
                           unsigned long d1_len,
                           const unsigned char *c1,
                           unsigned long c1_len,
                           unsigned char *out_t1,
                           unsigned long *out_len);

/**
 * 完成解密计算
 * @param ctx 协议上下文指针
 * @param t2 服务端返回的 T2
 * @param t2_len T2 长度
 * @param c3 密文分量 C3
 * @param c3_len C3 长度
 * @param c2 密文分量 C2
 * @param c2_len C2 长度
 * @param out_plaintext 输出明文缓冲区
 * @param out_len 输出长度
 * @return 错误码
 */
int cosign_complete_decryption(const CoSignContext *ctx,
                               const unsigned char *t2,
                               unsigned long t2_len,
                               const unsigned char *c3,
                               unsigned long c3_len,
                               const unsigned char *c2,
                               unsigned long c2_len,
                               unsigned char *out_plaintext,
                               unsigned long *out_len);

/**
 * 计算 SM3 哈希
 * @param data 输入数据
 * @param data_len 数据长度
 * @param out_hash 输出缓冲区（至少32字节）
 * @param out_len 输出长度
 * @return 错误码
 */
int cosign_sm3_hash(const unsigned char *data,
                    unsigned long data_len,
                    unsigned char *out_hash,
                    unsigned long *out_len);

/**
 * SM2 签名（标准签名）
 * @param private_key 私钥
 * @param private_key_len 私钥长度
 * @param message 消息
 * @param message_len 消息长度
 * @param out_signature 输出签名缓冲区（至少64字节）
 * @param out_len 输出长度
 * @return 错误码
 */
int cosign_sm2_sign(const unsigned char *private_key,
                    unsigned long private_key_len,
                    const unsigned char *message,
                    unsigned long message_len,
                    unsigned char *out_signature,
                    unsigned long *out_len);

/**
 * SM2 验签（标准验签）
 * @param public_key 公钥（64字节）
 * @param public_key_len 公钥长度
 * @param message 消息
 * @param message_len 消息长度
 * @param signature 签名（64字节）
 * @param signature_len 签名长度
 * @return COSIGN_OK 验签成功，其他值验签失败
 */
int cosign_sm2_verify(const unsigned char *public_key,
                      unsigned long public_key_len,
                      const unsigned char *message,
                      unsigned long message_len,
                      const unsigned char *signature,
                      unsigned long signature_len);

/**
 * SM2 加密（标准加密）
 * @param public_key 公钥（64字节）
 * @param public_key_len 公钥长度
 * @param message 明文
 * @param message_len 明文长度
 * @param out_ciphertext 输出密文缓冲区
 * @param out_len 输出长度
 * @return 错误码
 */
int cosign_sm2_encrypt(const unsigned char *public_key,
                       unsigned long public_key_len,
                       const unsigned char *message,
                       unsigned long message_len,
                       unsigned char *out_ciphertext,
                       unsigned long *out_len);

/**
 * SM2 解密（标准解密）
 * @param private_key 私钥
 * @param private_key_len 私钥长度
 * @param ciphertext 密文
 * @param ciphertext_len 密文长度
 * @param out_plaintext 输出明文缓冲区
 * @param out_len 输出长度
 * @return 错误码
 */
int cosign_sm2_decrypt(const unsigned char *private_key,
                       unsigned long private_key_len,
                       const unsigned char *ciphertext,
                       unsigned long ciphertext_len,
                       unsigned char *out_plaintext,
                       unsigned long *out_len);

/**
 * Base64 编码
 * @param data 输入数据
 * @param data_len 数据长度
 * @param out_str 输出字符串缓冲区
 * @param out_len 输出长度
 * @return 错误码
 */
int cosign_base64_encode(const unsigned char *data,
                         unsigned long data_len,
                         char *out_str,
                         unsigned long *out_len);

/**
 * Base64 解码
 * @param str Base64 字符串
 * @param out_data 输出数据缓冲区
 * @param out_len 输出长度
 * @return 错误码
 */
int cosign_base64_decode(const char *str,
                         unsigned char *out_data,
                         unsigned long *out_len);

#ifdef __cplusplus
}
#endif

#endif /* SM2_CO_SIGN_FFI_H */
