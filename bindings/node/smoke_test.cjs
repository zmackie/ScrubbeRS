const bindingPath = process.argv[2];

if (!bindingPath) {
  throw new Error("expected binding path");
}

const binding = require(bindingPath);

const plain = binding.scrubBuffer(Buffer.from("test"));
if (plain.toString("utf8") !== "test") {
  throw new Error(`plain text mismatch: ${plain.toString("utf8")}`);
}

const redacted = binding
  .scrubBuffer(Buffer.from("prefix ghp_123456789012345678901234567890123456 suffix"))
  .toString("utf8");

if (redacted !== "prefix **************************************** suffix") {
  throw new Error(`redacted text mismatch: ${redacted}`);
}
