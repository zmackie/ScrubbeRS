use scrubbers::{
    trufflehog_generated_detector_count, trufflehog_generated_signature_count,
    trufflehog_source_commit,
};

include!("generated_trufflehog_pattern_fixtures.rs");

#[allow(dead_code)]
mod generated_signatures {
    include!("../src/generated_trufflehog.rs");
}

#[test]
fn trufflehog_sync_materialized() {
    assert_ne!(
        trufflehog_source_commit(),
        "UNSYNCED",
        "run scripts/sync_trufflehog_signatures.py before tests"
    );

    let count = trufflehog_generated_signature_count();
    assert!(
        count > 0,
        "expected generated trufflehog signatures to be present"
    );
    assert!(
        trufflehog_generated_detector_count() > 0,
        "expected generated trufflehog detector inventory to be present"
    );
}

#[test]
fn trufflehog_pattern_fixture_sync_materialized() {
    assert_ne!(
        TRUFFLEHOG_PATTERN_FIXTURE_SOURCE_COMMIT, "UNSYNCED",
        "run scripts/sync_trufflehog_pattern_fixtures.go before tests"
    );
    assert!(
        !TRUFFLEHOG_PATTERN_FIXTURES.is_empty(),
        "expected generated trufflehog pattern fixtures to be present"
    );
    assert_eq!(
        trufflehog_source_commit(),
        TRUFFLEHOG_PATTERN_FIXTURE_SOURCE_COMMIT,
        "fixture and signature sync should come from the same upstream commit"
    );
}

#[test]
fn trufflehog_signature_ids_are_stable_hashes() {
    for &(_, name, _) in generated_signatures::TRUFFLEHOG_SIGNATURES {
        let (prefix, suffix) = name
            .rsplit_once('_')
            .expect("generated signature name should contain a stable suffix");
        assert!(
            prefix.starts_with("trufflehog_"),
            "expected trufflehog prefix in {name}"
        );
        assert_eq!(
            suffix.len(),
            16,
            "expected 16-hex stable suffix in generated name {name}"
        );
        assert!(
            suffix.chars().all(|ch| ch.is_ascii_hexdigit()),
            "expected hexadecimal stable suffix in generated name {name}"
        );
    }
}
