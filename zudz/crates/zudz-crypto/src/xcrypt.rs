//! مفكوكات AES بكتل ZTE — ECB (نوع 2) وCBC (أنواع 3/4/5/6)
//! منقول من ztk/crypto.py: فك تشفير كامل الكتلة ثم القص للطول الفعلي.

use aes::cipher::{BlockDecrypt, KeyInit};
use aes::{Aes128, Aes256};
use sha2::{Digest, Sha256};

/// قطع ECB (نوع 2): الترويسة (chunk_size, dec_size, more)
fn read_chunks_ecb(data: &[u8]) -> Option<(Vec<u8>, usize)> {
    let mut encrypted = Vec::new();
    let mut total_dec = 0usize;
    let mut pos = 0usize;
    loop {
        if pos + 12 > data.len() {
            return None;
        }
        let chunk_size = u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        let dec_size = u32::from_be_bytes(data[pos + 4..pos + 8].try_into().unwrap()) as usize;
        let more = u32::from_be_bytes(data[pos + 8..pos + 12].try_into().unwrap());
        pos += 12;
        if pos + chunk_size > data.len() {
            return None;
        }
        encrypted.extend_from_slice(&data[pos..pos + chunk_size]);
        pos += chunk_size;
        total_dec += dec_size;
        if more == 0 {
            break;
        }
    }
    Some((encrypted, total_dec))
}

/// قطع CBC: الترويسة (dec_size, chunk_size, more)
fn read_chunks_cbc(data: &[u8]) -> Option<(Vec<u8>, usize)> {
    let mut encrypted = Vec::new();
    let mut total_dec = 0usize;
    let mut pos = 0usize;
    loop {
        if pos + 12 > data.len() {
            return None;
        }
        let dec_size = u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        let chunk_size = u32::from_be_bytes(data[pos + 4..pos + 8].try_into().unwrap()) as usize;
        let more = u32::from_be_bytes(data[pos + 8..pos + 12].try_into().unwrap());
        pos += 12;
        if pos + chunk_size > data.len() {
            return None;
        }
        encrypted.extend_from_slice(&data[pos..pos + chunk_size]);
        pos += chunk_size;
        total_dec += dec_size;
        if more == 0 {
            break;
        }
    }
    Some((encrypted, total_dec))
}

fn decrypt_blocks_128(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut k = [0u8; 16];
    k.copy_from_slice(&key[..16]);
    let cipher = Aes128::new(&k.into());
    decrypt_with(&cipher, data)
}

fn decrypt_with<C: BlockDecrypt>(cipher: &C, data: &[u8]) -> Vec<u8> {
    // حشو أصفار إلى مضاعف 16 (كما في الأصل) ثم فك الكتل
    let padded_len = (data.len() + 15) / 16 * 16;
    let mut buf = vec![0u8; padded_len];
    buf[..data.len()].copy_from_slice(data);
    for chunk in buf.chunks_exact_mut(16) {
        let mut block = aes::cipher::generic_array::GenericArray::from_mut_slice(chunk);
        cipher.decrypt_block(&mut block);
    }
    buf
}

fn cbc_decrypt_256(key: &[u8; 32], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let cipher = Aes256::new(key.into());
    let padded_len = (data.len() + 15) / 16 * 16;
    let mut buf = vec![0u8; padded_len];
    buf[..data.len()].copy_from_slice(data);
    let mut prev = *iv;
    for chunk in buf.chunks_exact_mut(16) {
        let mut block_arr = [0u8; 16];
        block_arr.copy_from_slice(chunk);
        let mut block = aes::cipher::generic_array::GenericArray::clone_from_slice(&block_arr);
        cipher.decrypt_block(&mut block);
        for i in 0..16 {
            chunk[i] = block[i] ^ prev[i];
        }
        prev = block_arr;
    }
    buf
}

/// Xcryptor (نوع 2): AES-128-ECB بمفتاح نصي يُحشى/يقص لـ16 بايت
pub fn xcryptor_decrypt(body: &[u8], key_str: &str) -> Option<Vec<u8>> {
    let (encrypted, total_dec) = read_chunks_ecb(body)?;
    let mut key = [0u8; 16];
    let kb = key_str.as_bytes();
    let n = kb.len().min(16);
    key[..n].copy_from_slice(&kb[..n]);
    let plain = decrypt_blocks_128(&key, &encrypted);
    Some(plain[..total_dec.min(plain.len())].to_vec())
}

/// CBCXcryptor: key=SHA256(key_str), iv=SHA256(iv_str)[:16] (AES-256-CBC)
pub fn cbc_xcryptor_decrypt(body: &[u8], key_str: &str, iv_str: &str) -> Option<Vec<u8>> {
    let (encrypted, total_dec) = read_chunks_cbc(body)?;
    let key: [u8; 32] = Sha256::digest(key_str.as_bytes()).into();
    let iv_arr: [u8; 16] = Sha256::digest(iv_str.as_bytes())[..16].try_into().unwrap();
    let plain = cbc_decrypt_256(&key, &iv_arr, &encrypted);
    Some(plain[..total_dec.min(plain.len())].to_vec())
}

/// فك طبقات ZLIB المتسلسلة (ترويسة 12 بايت لكل قطعة)
/// مطابق لـ_decompress_all في الأصل.
pub fn decompress_all(data: &[u8]) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let mut pos = 0usize;
    const MAGIC: u32 = 0x0102_0304;
    if data.len() >= 60 && u32::from_be_bytes(data[0..4].try_into().unwrap()) == MAGIC {
        pos = 60;
    }
    let mut out = Vec::new();
    while pos + 12 <= data.len() {
        let dec_len = u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        let comp_len = u32::from_be_bytes(data[pos + 4..pos + 8].try_into().unwrap()) as usize;
        let more = u32::from_be_bytes(data[pos + 8..pos + 12].try_into().unwrap());
        pos += 12;
        if pos + comp_len > data.len() {
            break;
        }
        let chunk = &data[pos..pos + comp_len];
        pos += comp_len;
        let mut d = flate2::read::ZlibDecoder::new(chunk);
        let mut buf = Vec::new();
        d.read_to_end(&mut buf).map_err(|e| e.to_string())?;
        if buf.len() != dec_len {
            return Err(format!("طول مفكوك غير مطابق {dec_len} != {}", buf.len()));
        }
        out.extend_from_slice(&buf);
        if more == 0 {
            break;
        }
    }
    if out.is_empty() {
        Ok(data.to_vec())
    } else {
        Ok(out)
    }
}
