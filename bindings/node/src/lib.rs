use napi::bindgen_prelude::Buffer;
use napi_derive::napi;
use scrubbers_core::Scrubber;
use std::io::Cursor;
use std::sync::OnceLock;

fn default_scrubber() -> &'static Scrubber {
    static SCRUBBER: OnceLock<Scrubber> = OnceLock::new();
    SCRUBBER.get_or_init(|| Scrubber::new().expect("default scrubber should initialize"))
}

#[napi]
pub fn scrub_buffer(buf: Buffer) -> napi::Result<Buffer> {
    let out = default_scrubber().scrubbed(&buf);
    Ok(out.into())
}

#[napi]
pub fn scrub_lines_buffer(buf: Buffer) -> napi::Result<Buffer> {
    let mut out = Vec::with_capacity(buf.len());
    default_scrubber()
        .scrub_lines(Cursor::new(&buf[..]), &mut out)
        .map_err(|e| napi::Error::from_reason(e.to_string()))?;
    Ok(out.into())
}
