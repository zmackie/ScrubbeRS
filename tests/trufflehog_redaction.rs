use regex::escape;
use scrubbers::{Scrubber, SignatureSpec};

include!("generated_trufflehog_pattern_fixtures.rs");

const MIN_INLINE_FRAGMENT_LEN: usize = 6;

#[test]
fn trufflehog_positive_fixtures_produce_inline_redaction() {
    for &(detector, name, input, wants) in TRUFFLEHOG_PATTERN_FIXTURES {
        let fragments = inline_secret_fragments(input, wants);
        assert!(
            !fragments.is_empty(),
            "expected inline secret fragments for {detector}/{name}"
        );

        let specs = fragments
            .iter()
            .enumerate()
            .map(|(idx, fragment)| SignatureSpec {
                name: format!("fixture_{detector}_{idx}"),
                pattern: escape(fragment),
            })
            .collect();
        let scrubber =
            Scrubber::with_signatures(specs, b'*').expect("fixture scrubber should build");

        let output = scrubber.scrubbed(input.as_bytes());
        assert_eq!(
            output.len(),
            input.len(),
            "redaction should preserve length for {detector}/{name}"
        );
        assert_ne!(
            output,
            input.as_bytes(),
            "expected redaction output to differ for {detector}/{name}"
        );

        let spans = inline_secret_spans(input, &fragments);
        assert!(
            !spans.is_empty(),
            "expected literal secret spans for {detector}/{name}"
        );

        for (start, end) in spans {
            assert!(
                output[start..end].iter().all(|&b| b == b'*'),
                "expected inline mask for {detector}/{name} at {start}..{end}"
            );
        }
    }
}

fn inline_secret_fragments(input: &str, wants: &[&str]) -> Vec<String> {
    let mut fragments = Vec::new();

    for want in wants {
        let boundaries = char_boundaries(want);
        let mut start_idx = 0;

        while start_idx + 1 < boundaries.len() {
            let start = boundaries[start_idx];
            let mut matched_end_idx = None;

            for end_idx in ((start_idx + 1)..boundaries.len()).rev() {
                let end = boundaries[end_idx];
                let candidate = &want[start..end];
                if candidate.len() < MIN_INLINE_FRAGMENT_LEN {
                    break;
                }
                if input.contains(candidate) {
                    fragments.push(candidate.to_string());
                    matched_end_idx = Some(end_idx);
                    break;
                }
            }

            if let Some(end_idx) = matched_end_idx {
                start_idx = end_idx;
            } else {
                start_idx += 1;
            }
        }
    }

    prune_redundant_fragments(&mut fragments);
    fragments
}

fn char_boundaries(input: &str) -> Vec<usize> {
    let mut boundaries: Vec<usize> = input.char_indices().map(|(idx, _)| idx).collect();
    boundaries.push(input.len());
    boundaries
}

fn prune_redundant_fragments(fragments: &mut Vec<String>) {
    fragments.sort_by(|left, right| right.len().cmp(&left.len()).then(left.cmp(right)));
    fragments.dedup();

    let mut pruned = Vec::with_capacity(fragments.len());
    for fragment in fragments.drain(..) {
        if pruned
            .iter()
            .any(|existing: &String| existing.contains(&fragment))
        {
            continue;
        }
        pruned.push(fragment);
    }

    pruned.sort_unstable();
    *fragments = pruned;
}

fn inline_secret_spans(input: &str, fragments: &[String]) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();

    for fragment in fragments {
        let mut offset = 0;
        while let Some(index) = input[offset..].find(fragment) {
            let start = offset + index;
            let end = start + fragment.len();
            spans.push((start, end));
            offset = end;
        }
    }

    spans.sort_unstable();
    spans.dedup();
    spans
}
