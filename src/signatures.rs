use crate::SignatureSpec;

mod generated {
    include!("generated_trufflehog.rs");
}

/// High-confidence built-in detectors safe to apply directly as redactions.
///
/// TruffleHog's upstream detector corpus is tracked separately, but many of
/// those detectors rely on keyword gating and verifier callbacks. Applying the
/// raw extracted regexes directly as redactors creates false positives.
pub fn default_signatures() -> Vec<SignatureSpec> {
    vec![
        sig("aws_access_key", r"AKIA[0-9A-Z]{16}"),
        sig(
            "aws_secret_key",
            r"(?i)aws(.{0,20})?(secret|access)?.{0,20}[=:]\s*[0-9a-zA-Z/+]{40}",
        ),
        sig("github_pat_classic", r"ghp_[A-Za-z0-9]{36}"),
        sig("github_pat_fine_grained", r"github_pat_[A-Za-z0-9_]{82}"),
        sig("gitlab_pat", r"glpat-[A-Za-z0-9\-_]{20}"),
        sig("slack_token", r"xox[baprs]-[A-Za-z0-9-]{10,120}"),
        sig("stripe_live_key", r"sk_live_[0-9a-zA-Z]{24,}"),
        sig("stripe_restricted", r"rk_live_[0-9a-zA-Z]{24,}"),
        sig("sendgrid", r"SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}"),
        sig("twilio", r"SK[0-9a-fA-F]{32}"),
        sig("mailgun", r"key-[0-9a-zA-Z]{32}"),
        sig("npm_token", r"npm_[A-Za-z0-9]{36}"),
        sig(
            "private_key_block",
            r"-----BEGIN (RSA|DSA|EC|OPENSSH|PGP|PRIVATE) PRIVATE KEY-----[\s\S]{16,}?-----END (RSA|DSA|EC|OPENSSH|PGP|PRIVATE) PRIVATE KEY-----",
        ),
        sig(
            "jwt",
            r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}",
        ),
        sig("google_api", r"AIza[0-9A-Za-z\-_]{35}"),
        sig("gcp_service_account", r#""type"\s*:\s*"service_account""#),
        sig(
            "azure_storage",
            r"DefaultEndpointsProtocol=https;AccountName=[^;\s]+;AccountKey=[A-Za-z0-9+/=]{64,}",
        ),
        sig("shopify", r"shpat_[a-fA-F0-9]{32}"),
        sig("atlassian", r"ATATT3xFfGF0[A-Za-z0-9_\-=]{20,}"),
        sig("discord_token", r"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}"),
        sig("heroku_api", r"(?i)heroku.{0,20}[=:]\s*[0-9a-f]{32}"),
        sig("rsa_private_literal", "-----BEGIN RSA PRIVATE KEY-----"),
        sig(
            "oauth_bearer",
            r"(?i)authorization:\s*bearer\s+[A-Za-z0-9._\-]{20,}",
        ),
    ]
}

pub fn trufflehog_source_commit() -> &'static str {
    generated::TRUFFLEHOG_SOURCE_COMMIT
}

pub fn trufflehog_generated_signature_count() -> usize {
    generated::TRUFFLEHOG_SIGNATURES.len()
}

pub fn trufflehog_generated_detector_count() -> usize {
    generated::TRUFFLEHOG_DETECTORS.len()
}

pub fn trufflehog_detector_signatures(detector: &str) -> Vec<SignatureSpec> {
    let detector = detector.split('/').next().unwrap_or(detector);
    generated::TRUFFLEHOG_SIGNATURES
        .iter()
        .filter(|(generated_detector, _, _)| *generated_detector == detector)
        .map(|(_, name, pattern)| sig(name, pattern))
        .collect()
}

fn sig(name: &str, pattern: &str) -> SignatureSpec {
    SignatureSpec {
        name: name.to_string(),
        pattern: pattern.to_string(),
    }
}
