//! Port of Go 1.25.5 `net/http/sniff.go` (`DetectContentType`) and the
//! built-in `mime` extension table. The 2026.2.7 image ships no
//! `/etc/mime.types` or shared-mime-info database, so Go only ever consults
//! `builtinTypesLower` there.

/// `sniffLen`
const SNIFF_LEN: usize = 512;

/// `mime.builtinTypesLower`
const BUILTIN_TYPES: &[(&str, &str)] = &[
    (".avif", "image/avif"),
    (".css", "text/css; charset=utf-8"),
    (".gif", "image/gif"),
    (".htm", "text/html; charset=utf-8"),
    (".html", "text/html; charset=utf-8"),
    (".jpeg", "image/jpeg"),
    (".jpg", "image/jpeg"),
    (".js", "text/javascript; charset=utf-8"),
    (".json", "application/json"),
    (".mjs", "text/javascript; charset=utf-8"),
    (".pdf", "application/pdf"),
    (".png", "image/png"),
    (".svg", "image/svg+xml"),
    (".wasm", "application/wasm"),
    (".webp", "image/webp"),
    (".xml", "text/xml; charset=utf-8"),
];

/// `mime.TypeByExtension`: exact match first, then the lower-cased extension.
pub(super) fn type_by_extension(ext: &str) -> Option<&'static str> {
    let find = |e: &str| BUILTIN_TYPES.iter().find(|(k, _)| *k == e).map(|(_, v)| *v);
    find(ext).or_else(|| find(&ext.to_ascii_lowercase()))
}

/// `filepath.Ext`: the suffix starting at the final dot of the last element.
pub(super) fn extension(name: &str) -> &str {
    let base_start = name.rfind('/').map_or(0, |i| i + 1);
    name[base_start..]
        .rfind('.')
        .map_or("", |i| &name[base_start + i..])
}

enum Sig {
    Html(&'static [u8]),
    Masked {
        mask: &'static [u8],
        pat: &'static [u8],
        skip_ws: bool,
        ct: &'static str,
    },
    Exact(&'static [u8], &'static str),
    Mp4,
    Text,
}

const fn masked(mask: &'static [u8], pat: &'static [u8], ct: &'static str) -> Sig {
    Sig::Masked {
        mask,
        pat,
        skip_ws: false,
        ct,
    }
}

/// `sniffSignatures`, in order.
const SIGNATURES: &[Sig] = &[
    Sig::Html(b"<!DOCTYPE HTML"),
    Sig::Html(b"<HTML"),
    Sig::Html(b"<HEAD"),
    Sig::Html(b"<SCRIPT"),
    Sig::Html(b"<IFRAME"),
    Sig::Html(b"<H1"),
    Sig::Html(b"<DIV"),
    Sig::Html(b"<FONT"),
    Sig::Html(b"<TABLE"),
    Sig::Html(b"<A"),
    Sig::Html(b"<STYLE"),
    Sig::Html(b"<TITLE"),
    Sig::Html(b"<B"),
    Sig::Html(b"<BODY"),
    Sig::Html(b"<BR"),
    Sig::Html(b"<P"),
    Sig::Html(b"<!--"),
    Sig::Masked {
        mask: b"\xFF\xFF\xFF\xFF\xFF",
        pat: b"<?xml",
        skip_ws: true,
        ct: "text/xml; charset=utf-8",
    },
    Sig::Exact(b"%PDF-", "application/pdf"),
    Sig::Exact(b"%!PS-Adobe-", "application/postscript"),
    masked(
        b"\xFF\xFF\x00\x00",
        b"\xFE\xFF\x00\x00",
        "text/plain; charset=utf-16be",
    ),
    masked(
        b"\xFF\xFF\x00\x00",
        b"\xFF\xFE\x00\x00",
        "text/plain; charset=utf-16le",
    ),
    masked(
        b"\xFF\xFF\xFF\x00",
        b"\xEF\xBB\xBF\x00",
        "text/plain; charset=utf-8",
    ),
    Sig::Exact(b"\x00\x00\x01\x00", "image/x-icon"),
    Sig::Exact(b"\x00\x00\x02\x00", "image/x-icon"),
    Sig::Exact(b"BM", "image/bmp"),
    Sig::Exact(b"GIF87a", "image/gif"),
    Sig::Exact(b"GIF89a", "image/gif"),
    masked(
        b"\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF",
        b"RIFF\x00\x00\x00\x00WEBPVP",
        "image/webp",
    ),
    Sig::Exact(b"\x89PNG\x0D\x0A\x1A\x0A", "image/png"),
    Sig::Exact(b"\xFF\xD8\xFF", "image/jpeg"),
    masked(
        b"\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF",
        b"FORM\x00\x00\x00\x00AIFF",
        "audio/aiff",
    ),
    masked(b"\xFF\xFF\xFF", b"ID3", "audio/mpeg"),
    masked(b"\xFF\xFF\xFF\xFF\xFF", b"OggS\x00", "application/ogg"),
    masked(
        b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
        b"MThd\x00\x00\x00\x06",
        "audio/midi",
    ),
    masked(
        b"\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF",
        b"RIFF\x00\x00\x00\x00AVI ",
        "video/avi",
    ),
    masked(
        b"\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF",
        b"RIFF\x00\x00\x00\x00WAVE",
        "audio/wave",
    ),
    Sig::Mp4,
    Sig::Exact(b"\x1A\x45\xDF\xA3", "video/webm"),
    masked(
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF",
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00LP",
        "application/vnd.ms-fontobject",
    ),
    Sig::Exact(b"\x00\x01\x00\x00", "font/ttf"),
    Sig::Exact(b"OTTO", "font/otf"),
    Sig::Exact(b"ttcf", "font/collection"),
    Sig::Exact(b"wOFF", "font/woff"),
    Sig::Exact(b"wOF2", "font/woff2"),
    Sig::Exact(b"\x1F\x8B\x08", "application/x-gzip"),
    Sig::Exact(b"PK\x03\x04", "application/zip"),
    Sig::Exact(b"Rar!\x1A\x07\x00", "application/x-rar-compressed"),
    Sig::Exact(b"Rar!\x1A\x07\x01\x00", "application/x-rar-compressed"),
    Sig::Exact(b"\x00\x61\x73\x6D", "application/wasm"),
    Sig::Text,
];

const fn is_ws(b: u8) -> bool {
    matches!(b, b'\t' | b'\n' | b'\x0c' | b'\r' | b' ')
}

/// Tag-terminating byte (0xTT).
const fn is_tt(b: u8) -> bool {
    matches!(b, b' ' | b'>')
}

impl Sig {
    fn matches(&self, data: &[u8], first_non_ws: usize) -> Option<&'static str> {
        match self {
            Self::Html(sig) => {
                let data = &data[first_non_ws..];
                if data.len() < sig.len() + 1 {
                    return None;
                }
                for (i, &b) in sig.iter().enumerate() {
                    let mut db = data[i];
                    if b.is_ascii_uppercase() {
                        db &= 0xdf;
                    }
                    if b != db {
                        return None;
                    }
                }
                is_tt(data[sig.len()]).then_some("text/html; charset=utf-8")
            }
            Self::Masked {
                mask,
                pat,
                skip_ws,
                ct,
            } => {
                let data = if *skip_ws {
                    &data[first_non_ws..]
                } else {
                    data
                };
                if pat.len() != mask.len() || data.len() < pat.len() {
                    return None;
                }
                pat.iter()
                    .zip(mask.iter())
                    .zip(data.iter())
                    .all(|((p, m), d)| d & m == *p)
                    .then_some(ct)
            }
            Self::Exact(sig, ct) => data.starts_with(sig).then_some(ct),
            Self::Mp4 => {
                if data.len() < 12 {
                    return None;
                }
                let (size, ftype) = (data.get(..4)?, data.get(4..8)?);
                let box_size = usize::try_from(u32::from_be_bytes(size.try_into().ok()?)).ok()?;
                if data.len() < box_size || box_size % 4 != 0 || ftype != b"ftyp" {
                    return None;
                }
                let mut st = 8;
                while st < box_size {
                    if st != 12 && data.get(st..st + 3) == Some(b"mp4") {
                        return Some("video/mp4");
                    }
                    st += 4;
                }
                None
            }
            Self::Text => data[first_non_ws..]
                .iter()
                .all(|&b| !matches!(b, 0x00..=0x08 | 0x0B | 0x0E..=0x1A | 0x1C..=0x1F))
                .then_some("text/plain; charset=utf-8"),
        }
    }
}

/// `http.DetectContentType`
pub(crate) fn detect_content_type(data: &[u8]) -> &'static str {
    let data = &data[..data.len().min(SNIFF_LEN)];
    let first_non_ws = data.iter().position(|&b| !is_ws(b)).unwrap_or(data.len());
    SIGNATURES
        .iter()
        .find_map(|sig| sig.matches(data, first_non_ws))
        .unwrap_or("application/octet-stream")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniffing_matches_go() {
        // Expected values follow net/http/sniff.go; several mirror sniff_test.go.
        for (data, ct) in [
            (&b""[..], "text/plain; charset=utf-8"),
            (b"\x00", "application/octet-stream"),
            (b"Hello, world!", "text/plain; charset=utf-8"),
            (b"  <HtMl>", "text/html; charset=utf-8"),
            (b"<!DOCTYPE HTML>...", "text/html; charset=utf-8"),
            (b"<HTML", "text/plain; charset=utf-8"),
            (b"\n<?xml!", "text/xml; charset=utf-8"),
            (b"\xFF\xD8\xFF", "image/jpeg"),
            (b"wOF2\x00\x01", "font/woff2"),
            (b"{\"version\":3}", "text/plain; charset=utf-8"),
            (b"\xEF\xBB\xBF\x00", "text/plain; charset=utf-8"),
        ] {
            assert_eq!(detect_content_type(data), ct, "{data:?}");
        }
    }

    #[test]
    fn extensions_match_go() {
        assert_eq!(extension("poly-2026.2.7.js.map"), ".map");
        assert_eq!(extension("a/b.c/d"), "");
        assert_eq!(
            type_by_extension(".JS"),
            Some("text/javascript; charset=utf-8")
        );
        assert_eq!(type_by_extension(".map"), None);
        assert_eq!(type_by_extension(".woff2"), None);
    }
}
