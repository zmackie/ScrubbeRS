const bindingPath = process.argv[2];

if (!bindingPath) {
  throw new Error("expected binding path");
}

const binding = require(bindingPath);

function assertBuffer(name, input, expected) {
  const actual = binding.scrubBuffer(input);
  if (!Buffer.isBuffer(actual)) {
    throw new Error(`${name}: expected Buffer result`);
  }
  if (!actual.equals(expected)) {
    throw new Error(
      `${name}: expected ${JSON.stringify(expected.toString("latin1"))}, got ${JSON.stringify(actual.toString("latin1"))}`,
    );
  }
}

function assertLineBuffer(name, input, expected) {
  const actual = binding.scrubLinesBuffer(input);
  if (!Buffer.isBuffer(actual)) {
    throw new Error(`${name}: expected Buffer result`);
  }
  if (!actual.equals(expected)) {
    throw new Error(
      `${name}: expected ${JSON.stringify(expected.toString("latin1"))}, got ${JSON.stringify(actual.toString("latin1"))}`,
    );
  }
}

const token = Buffer.from("ghp_123456789012345678901234567890123456", "utf8");
const masked = Buffer.from("****************************************", "utf8");

assertBuffer("plain text", Buffer.from("test", "utf8"), Buffer.from("test", "utf8"));
assertBuffer("empty", Buffer.alloc(0), Buffer.alloc(0));
assertBuffer(
  "builtin redaction",
  Buffer.concat([
    Buffer.from("prefix ", "utf8"),
    token,
    Buffer.from(" suffix", "utf8"),
  ]),
  Buffer.concat([
    Buffer.from("prefix ", "utf8"),
    masked,
    Buffer.from(" suffix", "utf8"),
  ]),
);
assertBuffer(
  "multiline redaction",
  Buffer.from("safe\nprefix ghp_123456789012345678901234567890123456 suffix\n", "utf8"),
  Buffer.from("safe\nprefix **************************************** suffix\n", "utf8"),
);
assertLineBuffer(
  "multiline line scrub",
  Buffer.from("safe\nprefix ghp_123456789012345678901234567890123456 suffix\n", "utf8"),
  Buffer.from("safe\nprefix **************************************** suffix\n", "utf8"),
);
assertBuffer(
  "binary redaction",
  Buffer.concat([
    Buffer.from([0x00]),
    Buffer.from("prefix ", "utf8"),
    token,
    Buffer.from(" suffix", "utf8"),
    Buffer.from([0xff]),
  ]),
  Buffer.concat([
    Buffer.from([0x00]),
    Buffer.from("prefix ", "utf8"),
    masked,
    Buffer.from(" suffix", "utf8"),
    Buffer.from([0xff]),
  ]),
);
assertLineBuffer(
  "binary line scrub",
  Buffer.concat([
    Buffer.from([0x00]),
    Buffer.from("prefix ", "utf8"),
    token,
    Buffer.from(" suffix", "utf8"),
    Buffer.from([0xff]),
  ]),
  Buffer.concat([
    Buffer.from([0x00]),
    Buffer.from("prefix ", "utf8"),
    masked,
    Buffer.from(" suffix", "utf8"),
    Buffer.from([0xff]),
  ]),
);
assertBuffer(
  "repeat call 1",
  Buffer.from("prefix ghp_123456789012345678901234567890123456 suffix", "utf8"),
  Buffer.from("prefix **************************************** suffix", "utf8"),
);
assertBuffer(
  "repeat call 2",
  Buffer.from("prefix ghp_123456789012345678901234567890123456 suffix", "utf8"),
  Buffer.from("prefix **************************************** suffix", "utf8"),
);
