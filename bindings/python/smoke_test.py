import scrubbers


def main() -> None:
    assert scrubbers.scrub_bytes(b"test") == b"test"
    assert scrubbers.scrub_text("test") == "test"
    assert (
        scrubbers.scrub_bytes(b"prefix ghp_123456789012345678901234567890123456 suffix")
        == b"prefix **************************************** suffix"
    )
    assert (
        scrubbers.scrub_text("prefix ghp_123456789012345678901234567890123456 suffix")
        == "prefix **************************************** suffix"
    )


if __name__ == "__main__":
    main()
