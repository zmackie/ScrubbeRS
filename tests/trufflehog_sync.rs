use scrubbers::{trufflehog_generated_signature_count, trufflehog_source_commit};

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
