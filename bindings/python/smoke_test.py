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
    assert_equal(
        "multiline bytes via line scrub",
        scrubbers.scrub_lines_bytes(multiline_input.encode("utf8")),
        multiline_output.encode("utf8"),
    )
    assert_equal(
        "multiline text via line scrub",
        scrubbers.scrub_lines_text(multiline_input),
        multiline_output,
    )

    binary_input = b"\x00prefix " + token + b" suffix\xff"
    binary_output = b"\x00prefix " + masked + b" suffix\xff"
    assert_equal("binary bytes", scrubbers.scrub_bytes(binary_input), binary_output)
    assert_equal("binary bytes via line scrub", scrubbers.scrub_lines_bytes(binary_input), binary_output)

    repeated = scrubbers.scrub_text("prefix ghp_123456789012345678901234567890123456 suffix")
    assert_equal("repeat call 1", repeated, "prefix **************************************** suffix")
    assert_equal(
        "repeat call 2",
        scrubbers.scrub_text("prefix ghp_123456789012345678901234567890123456 suffix"),
        "prefix **************************************** suffix",
    )


def test_scrub_writer() -> None:
    import io
    import logging

    # --- Basic ScrubWriter usage ---
    buf = io.StringIO()
    writer = scrubbers.ScrubWriter(buf)

    n = writer.write("token=ghp_123456789012345678901234567890123456 done")
    writer.flush()
    assert_equal("ScrubWriter write len", n, len("token=ghp_123456789012345678901234567890123456 done"))
    assert_equal(
        "ScrubWriter redacts",
        buf.getvalue(),
        "token=**************************************** done",
    )

    # --- Protocol methods ---
    assert writer.writable() is True
    assert writer.readable() is False
    assert writer.seekable() is False
    assert repr(writer) == "ScrubWriter(...)"

    # --- Plain text passes through unchanged ---
    buf2 = io.StringIO()
    writer2 = scrubbers.ScrubWriter(buf2)
    writer2.write("hello world")
    assert_equal("ScrubWriter passthrough", buf2.getvalue(), "hello world")

    # --- Integration with logging.StreamHandler ---
    buf3 = io.StringIO()
    handler = logging.StreamHandler(stream=scrubbers.ScrubWriter(buf3))
    handler.setFormatter(logging.Formatter("%(message)s"))

    logger = logging.getLogger("scrubbers.test.writer")
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    logger.info("key=ghp_123456789012345678901234567890123456")

    output = buf3.getvalue()
    assert "ghp_" not in output, f"Secret leaked in log output: {output!r}"
    assert "********" in output, f"Expected mask in log output: {output!r}"

    logger.removeHandler(handler)


def test_scrub_stream() -> None:
    import io

    # --- Basic ScrubStream (binary) usage ---
    buf = io.BytesIO()
    stream = scrubbers.ScrubStream(buf)

    token = b"ghp_123456789012345678901234567890123456"
    n = stream.write(b"prefix " + token + b" suffix")
    stream.flush()
    assert_equal("ScrubStream write len", n, len(b"prefix " + token + b" suffix"))
    assert_equal(
        "ScrubStream redacts",
        buf.getvalue(),
        b"prefix " + b"*" * 40 + b" suffix",
    )

    # --- Protocol methods ---
    assert stream.writable() is True
    assert stream.readable() is False
    assert stream.seekable() is False
    assert repr(stream) == "ScrubStream(...)"

    # --- Plain bytes pass through ---
    buf2 = io.BytesIO()
    stream2 = scrubbers.ScrubStream(buf2)
    stream2.write(b"no secrets here")
    assert_equal("ScrubStream passthrough", buf2.getvalue(), b"no secrets here")


if __name__ == "__main__":
    main()
    test_scrub_writer()
    test_scrub_stream()
    print("All tests passed.")
