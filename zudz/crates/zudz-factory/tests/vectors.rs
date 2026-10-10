//! متجهات المصنع ضد vectors.json (من جلسة حية حقيقية + Oracle)

use serde::Deserialize;

#[derive(Deserialize)]
struct Vectors {
    key_derivation: Vec<Kd>,
    payload: Payload,
    payload_magic_mac: PayloadMagic,
}

#[derive(Deserialize)]
struct Kd {
    server_rand: u64,
    aes_key: String,
}

#[derive(Deserialize)]
struct Payload {
    server_mac: String,
    client_mac: String,
    words: Vec<u32>,
    payload_latin1_hex: String,
    padded_hex: String,
}

#[derive(Deserialize)]
struct PayloadMagic {
    words: Vec<u32>,
    payload_latin1_hex: String,
}

fn vectors() -> Vectors {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/vectors/vectors.json");
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn latin1(s: &str) -> Vec<u8> {
    s.chars().map(|c| c as u32 as u8).collect()
}

#[test]
fn key_derivation_matches_live_vectors() {
    let v = vectors();
    assert!(v.key_derivation.len() >= 9);
    for kd in &v.key_derivation {
        let (key, _idx) = zudz_factory::derive_aes_key(kd.server_rand);
        assert_eq!(
            hex::encode(key),
            kd.aes_key,
            "server_rand={}",
            kd.server_rand
        );
    }
}

#[test]
fn payload_words_and_string_match() {
    let v = vectors();
    let srv = hex::decode(&v.payload.server_mac).unwrap();
    let cli = hex::decode(&v.payload.client_mac).unwrap();
    let words = zudz_factory::payload_words(&srv, &cli);
    assert_eq!(words, v.payload.words, "words mismatch");

    let s = zudz_factory::build_payload_str(&words);
    assert_eq!(hex::encode(latin1(&s)), v.payload.payload_latin1_hex, "payload string mismatch");

    let padded = zudz_factory::pad(&latin1(&s));
    assert_eq!(hex::encode(padded), v.payload.padded_hex, "pad mismatch");
}

#[test]
fn payload_with_magic_mac_matches() {
    let v = vectors();
    let words = v.payload_magic_mac.words.clone();
    let s = zudz_factory::build_payload_str(&words);
    assert_eq!(hex::encode(latin1(&s)), v.payload_magic_mac.payload_latin1_hex);
}

#[test]
fn encrypasswd_live_vector() {
    // من الجهاز الحي: 6575d558... → 12345678
    assert_eq!(
        zudz_crypto_shim(),
        "12345678"
    );
}

// نستدعي zudz-crypto عبر الاعتمادية (أضفها في Cargo.toml [dev-dependencies])
fn zudz_crypto_shim() -> String {
    zudz_crypto::decrypt_encrypasswd("6575d558d478c6af58c17815250fdaee").unwrap()
}
