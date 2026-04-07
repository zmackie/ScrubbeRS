use scrubbers::{trufflehog_generated_signature_count, trufflehog_source_commit};

include!("generated_trufflehog_pattern_fixtures.rs");

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
