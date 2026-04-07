use scrubbers::{default_signatures, trufflehog_source_commit};

#[test]
fn trufflehog_sync_materialized() {
    assert_ne!(
        trufflehog_source_commit(),
        "UNSYNCED",
        "run scripts/sync_trufflehog_signatures.py before tests"
    );

    let count = default_signatures()
        .into_iter()
        .filter(|s| s.name.starts_with("trufflehog_"))
        .count();
    assert!(
        count > 0,
        "expected generated trufflehog signatures to be present"
    );
}
