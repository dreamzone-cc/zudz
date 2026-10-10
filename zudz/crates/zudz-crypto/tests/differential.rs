//! الاختبار التفاضلي ضد Oracle البايثوني
//! يقرأ tests/fixtures/manifest.json ويطابق مخرجات Rust بايت-لمبايت.

use serde::Deserialize;
use zudz_crypto::{decrypt_auto, DecryptParams};

#[derive(Deserialize)]
struct ManifestEntry {
    src: String,
    expected: String,
    #[serde(default)]
    size: usize,
    sha256: String,
    #[serde(default)]
    model: Option<String>,
}

fn project_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn fixtures_dir() -> std::path::PathBuf {
    project_root().join("zudz/tests/fixtures")
}

#[test]
fn differential_decrypt_all_fixtures() {
    let manifest: Vec<ManifestEntry> = serde_json::from_str(
        &std::fs::read_to_string(fixtures_dir().join("manifest.json")).expect("manifest"),
    )
    .expect("manifest json");

    let mut checked = 0;
    for entry in &manifest {
        let raw = std::fs::read(project_root().join(&entry.src))
            .unwrap_or_else(|_| panic!("قراءة المصدر {}", entry.src));
        let expected = std::fs::read(fixtures_dir().join(&entry.expected)).expect("expected file");

        let params = DecryptParams {
            model: entry.model.clone(),
            ..Default::default()
        };
        let (xml, desc) = decrypt_auto(&raw, &params)
            .unwrap_or_else(|e| panic!("فك {} فشل: {e}", entry.src));

        // التطابق البايتي الحاسم مع Oracle
        assert_eq!(
            xml, expected,
            "اختلاف بايتي في {} (طريقة Rust: {desc})",
            entry.src
        );
        // وSHA256 من الـmanifest (مصدر مستقل ثالث)
        use sha2::Digest;
        let hash = hex::encode(sha2::Sha256::digest(&xml));
        assert_eq!(hash, entry.sha256, "sha256 لا يطابق manifest لـ{}", entry.src);
        checked += 1;
        eprintln!("✅ {} — {desc}", entry.src);
    }
    assert_eq!(checked, 4, "يجب فحص 4 ملفات مرجعية عامة");
}
