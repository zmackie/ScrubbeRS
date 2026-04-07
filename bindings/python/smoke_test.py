import scrubbers


def assert_equal(name: str, actual, expected) -> None:
    if actual != expected:
        raise AssertionError(f"{name}: expected {expected!r}, got {actual!r}")


def main() -> None:
    token = b"ghp_123456789012345678901234567890123456"
    masked = b"****************************************"

    plain_bytes = scrubbers.scrub_bytes(b"test")
    plain_text = scrubbers.scrub_text("test")
    assert isinstance(plain_bytes, bytes)
    assert isinstance(plain_text, str)
    assert_equal("plain bytes", plain_bytes, b"test")
    assert_equal("plain text", plain_text, "test")

    assert_equal("empty bytes", scrubbers.scrub_bytes(b""), b"")
    assert_equal("empty text", scrubbers.scrub_text(""), "")

    assert_equal(
        "redacted bytes",
        scrubbers.scrub_bytes(b"prefix " + token + b" suffix"),
        b"prefix " + masked + b" suffix",
    )
    assert_equal(
        "redacted text",
        scrubbers.scrub_text("prefix ghp_123456789012345678901234567890123456 suffix"),
        "prefix **************************************** suffix",
    )

    multiline_input = "safe\nprefix ghp_123456789012345678901234567890123456 suffix\n"
    multiline_output = "safe\nprefix **************************************** suffix\n"
    assert_equal("multiline text", scrubbers.scrub_text(multiline_input), multiline_output)

    binary_input = b"\x00prefix " + token + b" suffix\xff"
    binary_output = b"\x00prefix " + masked + b" suffix\xff"
    assert_equal("binary bytes", scrubbers.scrub_bytes(binary_input), binary_output)

    repeated = scrubbers.scrub_text("prefix ghp_123456789012345678901234567890123456 suffix")
    assert_equal("repeat call 1", repeated, "prefix **************************************** suffix")
    assert_equal(
        "repeat call 2",
        scrubbers.scrub_text("prefix ghp_123456789012345678901234567890123456 suffix"),
        "prefix **************************************** suffix",
    )


if __name__ == "__main__":
    main()
