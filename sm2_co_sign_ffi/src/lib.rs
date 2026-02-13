//! SM2 协同签名 FFI 绑定
//!
//! 提供 C ABI 兼容的接口，供其他语言调用

use std::ffi::{c_char, c_int, c_uchar, c_ulong, CStr, CString};
use std::ptr;
use std::slice;

use sm2_co_sign_core::CoSignProtocol;

/// 错误码定义
pub const COSIGN_OK: c_int = 0;
pub const COSIGN_ERR_NULL_PTR: c_int = -1;
pub const COSIGN_ERR_INVALID_PARAM: c_int = -2;
pub const COSIGN_ERR_CRYPTO: c_int = -3;
pub const COSIGN_ERR_NETWORK: c_int = -4;
pub const COSIGN_ERR_ENCODING: c_int = -5;

/// 协议上下文
pub struct CoSignContext {
    protocol: CoSignProtocol,
}

/// 创建协议上下文
#[no_mangle]
pub extern "C" fn cosign_context_new() -> *mut CoSignContext {
    match CoSignProtocol::new() {
        Ok(protocol) => {
            let ctx = Box::new(CoSignContext { protocol });
            Box::into_raw(ctx)
        }
        Err(_) => ptr::null_mut(),
    }
}

/// 销毁协议上下文
#[no_mangle]
pub extern "C" fn cosign_context_free(ctx: *mut CoSignContext) {
    if !ctx.is_null() {
        unsafe {
            drop(Box::from_raw(ctx));
        }
    }
}

/// 生成客户端私钥分量 D1
#[no_mangle]
pub extern "C" fn cosign_generate_d1(
    ctx: *mut CoSignContext,
    out_d1: *mut c_uchar,
    out_len: *mut c_ulong,
) -> c_int {
    if ctx.is_null() || out_d1.is_null() || out_len.is_null() {
        return COSIGN_ERR_NULL_PTR;
    }

    let ctx = unsafe { &mut *ctx };

    match ctx.protocol.generate_d1() {
        Ok(d1) => {
            let len = d1.len();
            unsafe {
                ptr::copy_nonoverlapping(d1.as_ptr(), out_d1, len);
                *out_len = len as c_ulong;
            }
            COSIGN_OK
        }
        Err(_) => COSIGN_ERR_CRYPTO,
    }
}

/// 计算 P1 = d1 * G
#[no_mangle]
pub extern "C" fn cosign_calculate_p1(
    ctx: *const CoSignContext,
    d1: *const c_uchar,
    d1_len: c_ulong,
    out_p1: *mut c_uchar,
    out_len: *mut c_ulong,
) -> c_int {
    if ctx.is_null() || d1.is_null() || out_p1.is_null() || out_len.is_null() {
        return COSIGN_ERR_NULL_PTR;
    }

    let ctx = unsafe { &*ctx };
    let d1_slice = unsafe { slice::from_raw_parts(d1, d1_len as usize) };

    match ctx.protocol.calculate_p1(d1_slice) {
        Ok(p1) => {
            let len = p1.len();
            unsafe {
                ptr::copy_nonoverlapping(p1.as_ptr(), out_p1, len);
                *out_len = len as c_ulong;
            }
            COSIGN_OK
        }
        Err(_) => COSIGN_ERR_CRYPTO,
    }
}

/// 签名预处理：生成 k1，计算 Q1 = k1 * G
#[no_mangle]
pub extern "C" fn cosign_sign_prepare(
    ctx: *const CoSignContext,
    out_k1: *mut c_uchar,
    k1_len: *mut c_ulong,
    out_q1: *mut c_uchar,
    q1_len: *mut c_ulong,
) -> c_int {
    if ctx.is_null() || out_k1.is_null() || k1_len.is_null() || out_q1.is_null() || q1_len.is_null() {
        return COSIGN_ERR_NULL_PTR;
    }

    let ctx = unsafe { &*ctx };

    match ctx.protocol.sign_prepare() {
        Ok((k1, q1)) => {
            unsafe {
                ptr::copy_nonoverlapping(k1.as_ptr(), out_k1, k1.len());
                *k1_len = k1.len() as c_ulong;
                ptr::copy_nonoverlapping(q1.as_ptr(), out_q1, q1.len());
                *q1_len = q1.len() as c_ulong;
            }
            COSIGN_OK
        }
        Err(_) => COSIGN_ERR_CRYPTO,
    }
}

/// 计算消息哈希
#[no_mangle]
pub extern "C" fn cosign_hash_message(
    ctx: *const CoSignContext,
    message: *const c_uchar,
    message_len: c_ulong,
    public_key: *const c_uchar,
    public_key_len: c_ulong,
    out_hash: *mut c_uchar,
    out_len: *mut c_ulong,
) -> c_int {
    if ctx.is_null() || message.is_null() || out_hash.is_null() || out_len.is_null() {
        return COSIGN_ERR_NULL_PTR;
    }

    let ctx = unsafe { &*ctx };
    let message_slice = unsafe { slice::from_raw_parts(message, message_len as usize) };
    let pk_slice = if public_key.is_null() || public_key_len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(public_key, public_key_len as usize) }
    };

    match ctx.protocol.calculate_message_hash(message_slice, pk_slice) {
        Ok(hash) => {
            let len = hash.len();
            unsafe {
                ptr::copy_nonoverlapping(hash.as_ptr(), out_hash, len);
                *out_len = len as c_ulong;
            }
            COSIGN_OK
        }
        Err(_) => COSIGN_ERR_CRYPTO,
    }
}

/// 完成签名计算
#[no_mangle]
pub extern "C" fn cosign_complete_signature(
    ctx: *const CoSignContext,
    k1: *const c_uchar,
    k1_len: c_ulong,
    d1: *const c_uchar,
    d1_len: c_ulong,
    r: *const c_uchar,
    r_len: c_ulong,
    s2: *const c_uchar,
    s2_len: c_ulong,
    s3: *const c_uchar,
    s3_len: c_ulong,
    out_r: *mut c_uchar,
    out_r_len: *mut c_ulong,
    out_s: *mut c_uchar,
    out_s_len: *mut c_ulong,
) -> c_int {
    if ctx.is_null() || k1.is_null() || d1.is_null() || r.is_null() || s2.is_null() || s3.is_null()
        || out_r.is_null() || out_s.is_null()
    {
        return COSIGN_ERR_NULL_PTR;
    }

    let ctx = unsafe { &*ctx };
    let k1_slice = unsafe { slice::from_raw_parts(k1, k1_len as usize) };
    let d1_slice = unsafe { slice::from_raw_parts(d1, d1_len as usize) };
    let r_slice = unsafe { slice::from_raw_parts(r, r_len as usize) };
    let s2_slice = unsafe { slice::from_raw_parts(s2, s2_len as usize) };
    let s3_slice = unsafe { slice::from_raw_parts(s3, s3_len as usize) };

    match ctx.protocol.complete_signature(k1_slice, d1_slice, r_slice, s2_slice, s3_slice) {
        Ok((r_out, s_out)) => {
            unsafe {
                ptr::copy_nonoverlapping(r_out.as_ptr(), out_r, r_out.len());
                *out_r_len = r_out.len() as c_ulong;
                ptr::copy_nonoverlapping(s_out.as_ptr(), out_s, s_out.len());
                *out_s_len = s_out.len() as c_ulong;
            }
            COSIGN_OK
        }
        Err(_) => COSIGN_ERR_CRYPTO,
    }
}

/// 解密预处理：计算 T1 = d1 * C1
#[no_mangle]
pub extern "C" fn cosign_decrypt_prepare(
    ctx: *const CoSignContext,
    d1: *const c_uchar,
    d1_len: c_ulong,
    c1: *const c_uchar,
    c1_len: c_ulong,
    out_t1: *mut c_uchar,
    out_len: *mut c_ulong,
) -> c_int {
    if ctx.is_null() || d1.is_null() || c1.is_null() || out_t1.is_null() || out_len.is_null() {
        return COSIGN_ERR_NULL_PTR;
    }

    let ctx = unsafe { &*ctx };
    let d1_slice = unsafe { slice::from_raw_parts(d1, d1_len as usize) };
    let c1_slice = unsafe { slice::from_raw_parts(c1, c1_len as usize) };

    match ctx.protocol.decrypt_prepare(d1_slice, c1_slice) {
        Ok(t1) => {
            let len = t1.len();
            unsafe {
                ptr::copy_nonoverlapping(t1.as_ptr(), out_t1, len);
                *out_len = len as c_ulong;
            }
            COSIGN_OK
        }
        Err(_) => COSIGN_ERR_CRYPTO,
    }
}

/// 完成解密计算
#[no_mangle]
pub extern "C" fn cosign_complete_decryption(
    ctx: *const CoSignContext,
    t2: *const c_uchar,
    t2_len: c_ulong,
    c3: *const c_uchar,
    c3_len: c_ulong,
    c2: *const c_uchar,
    c2_len: c_ulong,
    out_plaintext: *mut c_uchar,
    out_len: *mut c_ulong,
) -> c_int {
    if ctx.is_null() || t2.is_null() || c3.is_null() || c2.is_null() || out_plaintext.is_null() || out_len.is_null() {
        return COSIGN_ERR_NULL_PTR;
    }

    let ctx = unsafe { &*ctx };
    let t2_slice = unsafe { slice::from_raw_parts(t2, t2_len as usize) };
    let c3_slice = unsafe { slice::from_raw_parts(c3, c3_len as usize) };
    let c2_slice = unsafe { slice::from_raw_parts(c2, c2_len as usize) };

    match ctx.protocol.complete_decryption(t2_slice, c3_slice, c2_slice) {
        Ok(plaintext) => {
            let len = plaintext.len();
            unsafe {
                ptr::copy_nonoverlapping(plaintext.as_ptr(), out_plaintext, len);
                *out_len = len as c_ulong;
            }
            COSIGN_OK
        }
        Err(_) => COSIGN_ERR_CRYPTO,
    }
}

/// 计算 SM3 哈希
#[no_mangle]
pub extern "C" fn cosign_sm3_hash(
    data: *const c_uchar,
    data_len: c_ulong,
    out_hash: *mut c_uchar,
    out_len: *mut c_ulong,
) -> c_int {
    if data.is_null() || out_hash.is_null() || out_len.is_null() {
        return COSIGN_ERR_NULL_PTR;
    }

    let data_slice = unsafe { slice::from_raw_parts(data, data_len as usize) };
    let hash = CoSignProtocol::sm3_hash(data_slice);

    unsafe {
        ptr::copy_nonoverlapping(hash.as_ptr(), out_hash, hash.len());
        *out_len = hash.len() as c_ulong;
    }

    COSIGN_OK
}

/// SM2 签名（标准签名）
#[no_mangle]
pub extern "C" fn cosign_sm2_sign(
    private_key: *const c_uchar,
    private_key_len: c_ulong,
    message: *const c_uchar,
    message_len: c_ulong,
    out_signature: *mut c_uchar,
    out_len: *mut c_ulong,
) -> c_int {
    if private_key.is_null() || message.is_null() || out_signature.is_null() || out_len.is_null() {
        return COSIGN_ERR_NULL_PTR;
    }

    let private_key_slice = unsafe { slice::from_raw_parts(private_key, private_key_len as usize) };
    let message_slice = unsafe { slice::from_raw_parts(message, message_len as usize) };

    match CoSignProtocol::sign(private_key_slice, message_slice) {
        Ok(signature) => {
            unsafe {
                ptr::copy_nonoverlapping(signature.as_ptr(), out_signature, signature.len());
                *out_len = signature.len() as c_ulong;
            }
            COSIGN_OK
        }
        Err(_) => COSIGN_ERR_CRYPTO,
    }
}

/// SM2 验签（标准验签）
#[no_mangle]
pub extern "C" fn cosign_sm2_verify(
    public_key: *const c_uchar,
    public_key_len: c_ulong,
    message: *const c_uchar,
    message_len: c_ulong,
    signature: *const c_uchar,
    signature_len: c_ulong,
) -> c_int {
    if public_key.is_null() || message.is_null() || signature.is_null() {
        return COSIGN_ERR_NULL_PTR;
    }

    let public_key_slice = unsafe { slice::from_raw_parts(public_key, public_key_len as usize) };
    let message_slice = unsafe { slice::from_raw_parts(message, message_len as usize) };
    let signature_slice = unsafe { slice::from_raw_parts(signature, signature_len as usize) };

    match CoSignProtocol::verify(public_key_slice, message_slice, signature_slice) {
        Ok(true) => COSIGN_OK,
        Ok(false) => COSIGN_ERR_CRYPTO,
        Err(_) => COSIGN_ERR_CRYPTO,
    }
}

/// SM2 加密（标准加密）
#[no_mangle]
pub extern "C" fn cosign_sm2_encrypt(
    public_key: *const c_uchar,
    public_key_len: c_ulong,
    message: *const c_uchar,
    message_len: c_ulong,
    out_ciphertext: *mut c_uchar,
    out_len: *mut c_ulong,
) -> c_int {
    if public_key.is_null() || message.is_null() || out_ciphertext.is_null() || out_len.is_null() {
        return COSIGN_ERR_NULL_PTR;
    }

    let public_key_slice = unsafe { slice::from_raw_parts(public_key, public_key_len as usize) };
    let message_slice = unsafe { slice::from_raw_parts(message, message_len as usize) };

    match CoSignProtocol::encrypt(public_key_slice, message_slice) {
        Ok(ciphertext) => {
            unsafe {
                ptr::copy_nonoverlapping(ciphertext.as_ptr(), out_ciphertext, ciphertext.len());
                *out_len = ciphertext.len() as c_ulong;
            }
            COSIGN_OK
        }
        Err(_) => COSIGN_ERR_CRYPTO,
    }
}

/// SM2 解密（标准解密）
#[no_mangle]
pub extern "C" fn cosign_sm2_decrypt(
    private_key: *const c_uchar,
    private_key_len: c_ulong,
    ciphertext: *const c_uchar,
    ciphertext_len: c_ulong,
    out_plaintext: *mut c_uchar,
    out_len: *mut c_ulong,
) -> c_int {
    if private_key.is_null() || ciphertext.is_null() || out_plaintext.is_null() || out_len.is_null() {
        return COSIGN_ERR_NULL_PTR;
    }

    let private_key_slice = unsafe { slice::from_raw_parts(private_key, private_key_len as usize) };
    let ciphertext_slice = unsafe { slice::from_raw_parts(ciphertext, ciphertext_len as usize) };

    match CoSignProtocol::decrypt(private_key_slice, ciphertext_slice) {
        Ok(Some(plaintext)) => {
            unsafe {
                ptr::copy_nonoverlapping(plaintext.as_ptr(), out_plaintext, plaintext.len());
                *out_len = plaintext.len() as c_ulong;
            }
            COSIGN_OK
        }
        Ok(None) => COSIGN_ERR_CRYPTO,
        Err(_) => COSIGN_ERR_CRYPTO,
    }
}

/// Base64 编码
#[no_mangle]
pub extern "C" fn cosign_base64_encode(
    data: *const c_uchar,
    data_len: c_ulong,
    out_str: *mut c_char,
    out_len: *mut c_ulong,
) -> c_int {
    if data.is_null() || out_str.is_null() || out_len.is_null() {
        return COSIGN_ERR_NULL_PTR;
    }

    let data_slice = unsafe { slice::from_raw_parts(data, data_len as usize) };
    let encoded = sm2_co_sign_core::protocol::base64_encode(data_slice);

    match CString::new(encoded) {
        Ok(c_str) => {
            let bytes = c_str.as_bytes_with_nul();
            unsafe {
                ptr::copy_nonoverlapping(bytes.as_ptr(), out_str as *mut u8, bytes.len());
                *out_len = (bytes.len() - 1) as c_ulong;
            }
            COSIGN_OK
        }
        Err(_) => COSIGN_ERR_ENCODING,
    }
}

/// Base64 解码
#[no_mangle]
pub extern "C" fn cosign_base64_decode(
    str: *const c_char,
    out_data: *mut c_uchar,
    out_len: *mut c_ulong,
) -> c_int {
    if str.is_null() || out_data.is_null() || out_len.is_null() {
        return COSIGN_ERR_NULL_PTR;
    }

    let c_str = unsafe { CStr::from_ptr(str) };
    let str_slice = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return COSIGN_ERR_ENCODING,
    };

    match sm2_co_sign_core::protocol::base64_decode(str_slice) {
        Ok(data) => {
            unsafe {
                ptr::copy_nonoverlapping(data.as_ptr(), out_data, data.len());
                *out_len = data.len() as c_ulong;
            }
            COSIGN_OK
        }
        Err(_) => COSIGN_ERR_ENCODING,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn test_context_new_free() {
        let ctx = cosign_context_new();
        assert!(!ctx.is_null());
        cosign_context_free(ctx);
    }

    #[test]
    fn test_generate_d1() {
        let ctx = cosign_context_new();
        let mut d1 = [0u8; 32];
        let mut len: c_ulong = 0;

        let result = cosign_generate_d1(ctx, d1.as_mut_ptr(), &mut len);
        assert_eq!(result, COSIGN_OK);
        assert!(len > 0);

        cosign_context_free(ctx);
    }

    #[test]
    fn test_sm3_hash() {
        let data = b"hello world";
        let mut hash = [0u8; 32];
        let mut len: c_ulong = 0;

        let result = cosign_sm3_hash(data.as_ptr(), data.len() as c_ulong, hash.as_mut_ptr(), &mut len);
        assert_eq!(result, COSIGN_OK);
        assert_eq!(len, 32);
    }

    #[test]
    fn test_sm2_sign_verify() {
        let ctx = cosign_context_new();
        let mut d1 = [0u8; 32];
        let mut d1_len: c_ulong = 0;
        cosign_generate_d1(ctx, d1.as_mut_ptr(), &mut d1_len);

        let mut p1 = [0u8; 64];
        let mut p1_len: c_ulong = 0;
        cosign_calculate_p1(ctx, d1.as_ptr(), d1_len, p1.as_mut_ptr(), &mut p1_len);

        let message = b"hello world";
        let mut signature = [0u8; 64];
        let mut sig_len: c_ulong = 0;

        let result = cosign_sm2_sign(d1.as_ptr(), d1_len, message.as_ptr(), message.len() as c_ulong, signature.as_mut_ptr(), &mut sig_len);
        assert_eq!(result, COSIGN_OK);
        assert_eq!(sig_len, 64);

        let result = cosign_sm2_verify(p1.as_ptr(), p1_len, message.as_ptr(), message.len() as c_ulong, signature.as_ptr(), sig_len);
        assert_eq!(result, COSIGN_OK);

        cosign_context_free(ctx);
    }

    #[test]
    fn test_sm2_encrypt_decrypt() {
        let ctx = cosign_context_new();
        let mut d1 = [0u8; 32];
        let mut d1_len: c_ulong = 0;
        cosign_generate_d1(ctx, d1.as_mut_ptr(), &mut d1_len);

        let mut p1 = [0u8; 64];
        let mut p1_len: c_ulong = 0;
        cosign_calculate_p1(ctx, d1.as_ptr(), d1_len, p1.as_mut_ptr(), &mut p1_len);

        let message = b"hello world";
        let mut ciphertext = [0u8; 256];
        let mut cipher_len: c_ulong = 0;

        let result = cosign_sm2_encrypt(p1.as_ptr(), p1_len, message.as_ptr(), message.len() as c_ulong, ciphertext.as_mut_ptr(), &mut cipher_len);
        assert_eq!(result, COSIGN_OK);

        let mut plaintext = [0u8; 256];
        let mut plain_len: c_ulong = 0;

        let result = cosign_sm2_decrypt(d1.as_ptr(), d1_len, ciphertext.as_ptr(), cipher_len, plaintext.as_mut_ptr(), &mut plain_len);
        assert_eq!(result, COSIGN_OK);
        assert_eq!(&plaintext[..plain_len as usize], message);

        cosign_context_free(ctx);
    }

    #[test]
    fn test_base64() {
        let data = b"hello world";
        let mut out_str = [0i8; 64];
        let mut len: c_ulong = 0;

        let result = cosign_base64_encode(data.as_ptr(), data.len() as c_ulong, out_str.as_mut_ptr(), &mut len);
        assert_eq!(result, COSIGN_OK);

        let encoded = unsafe { CStr::from_ptr(out_str.as_ptr()) };
        assert!(!encoded.to_bytes().is_empty());

        let mut decoded = [0u8; 64];
        let mut decoded_len: c_ulong = 0;
        let result = cosign_base64_decode(out_str.as_ptr(), decoded.as_mut_ptr(), &mut decoded_len);
        assert_eq!(result, COSIGN_OK);
        assert_eq!(&decoded[..decoded_len as usize], data);
    }
}
