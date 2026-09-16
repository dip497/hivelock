use aho_corasick::{AhoCorasick, MatchKind};
use base64::Engine;
use std::fs::OpenOptions;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

/// Values shorter than this are not masked (would shred normal output).
pub const MIN_LEN: usize = 8;

pub struct Redactor {
    ac: Option<AhoCorasick>,
    owner: Vec<String>,
    pub max: usize,
}

fn url_encode(v: &str) -> String {
    v.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

impl Redactor {
    pub fn new(pairs: Vec<(String, String)>) -> Self {
        let mut pats: Vec<String> = Vec::new();
        let mut owner = Vec::new();
        for (name, v) in pairs {
            if v.len() < MIN_LEN {
                continue;
            }
            let json = serde_json::to_string(&v).unwrap_or_default();
            // ponytail: whole-value encodings only; a secret embedded mid-way in a larger base64 blob is missed
            let variants = [
                v.clone(),
                base64::engine::general_purpose::STANDARD.encode(&v),
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&v),
                url_encode(&v),
                json[1..json.len() - 1].to_string(),
            ];
            for p in variants {
                if !pats.contains(&p) {
                    pats.push(p);
                    owner.push(name.clone());
                }
            }
        }
        let max = pats.iter().map(|p| p.len()).max().unwrap_or(0);
        let ac = (!pats.is_empty()).then(|| {
            AhoCorasick::builder().match_kind(MatchKind::LeftmostLongest).build(&pats).expect("patterns")
        });
        Redactor { ac, owner, max }
    }

    pub fn is_empty(&self) -> bool {
        self.ac.is_none()
    }

    /// (start, end, name)
    pub fn find<'a>(&'a self, hay: &[u8]) -> Vec<(usize, usize, &'a str)> {
        match &self.ac {
            None => Vec::new(),
            Some(ac) => ac
                .find_iter(hay)
                .map(|m| (m.start(), m.end(), self.owner[m.pattern().as_usize()].as_str()))
                .collect(),
        }
    }

    pub fn redact(&self, s: &str) -> Option<String> {
        let found = self.find(s.as_bytes());
        if found.is_empty() {
            return None;
        }
        let mut out = String::with_capacity(s.len());
        let mut last = 0;
        for (a, b, name) in found {
            out.push_str(&s[last..a]);
            out.push_str(&format!("[lock:{name}]"));
            last = b;
        }
        out.push_str(&s[last..]);
        Some(out)
    }

    /// Streams `r` to `w`, masking secrets even when split across reads.
    pub fn copy(&self, mut r: impl Read, mut w: impl Write) -> io::Result<()> {
        // ponytail: holds back max-1 bytes, so a prompt without trailing output appears only at EOF
        let keep = self.max.saturating_sub(1);
        let mut buf: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            let n = match r.read(&mut chunk) {
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            buf.extend_from_slice(&chunk[..n]);
            let mut cut = if n == 0 { buf.len() } else { buf.len().saturating_sub(keep) };
            let mut out = Vec::with_capacity(cut);
            let mut last = 0;
            for (a, b, name) in self.find(&buf) {
                if a >= cut {
                    break;
                }
                out.extend_from_slice(&buf[last..a]);
                out.extend_from_slice(format!("[lock:{name}]").as_bytes());
                last = b;
                cut = cut.max(b);
            }
            out.extend_from_slice(&buf[last..cut]);
            w.write_all(&out)?;
            w.flush()?;
            buf.drain(..cut);
            if n == 0 {
                return Ok(());
            }
        }
    }

    /// Same-length mask so files being appended to concurrently stay intact.
    fn mask(name: &str, len: usize) -> Vec<u8> {
        let mut m = format!("[lock:{name}]").into_bytes();
        m.truncate(len);
        m.resize(len, b'*');
        m
    }

    /// Masks secrets inside a file in place (no truncation, no rename). Returns count.
    pub fn scrub_file(&self, path: &Path) -> io::Result<usize> {
        if self.is_empty() {
            return Ok(0);
        }
        let mut f = OpenOptions::new().read(true).write(true).open(path)?;
        let len = f.metadata()?.len();
        const WINDOW: u64 = 8 << 20;
        let mut pos = 0u64;
        let mut count = 0;
        let mut buf = Vec::new();
        while pos < len {
            buf.clear();
            f.seek(SeekFrom::Start(pos))?;
            (&mut f).take(WINDOW + self.max as u64).read_to_end(&mut buf)?;
            let last_window = pos + WINDOW >= len;
            for (a, b, name) in self.find(&buf) {
                if a as u64 >= WINDOW && !last_window {
                    break; // next window sees it whole
                }
                f.seek(SeekFrom::Start(pos + a as u64))?;
                f.write_all(&Self::mask(name, b - a))?;
                count += 1;
            }
            pos += WINDOW;
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r() -> Redactor {
        Redactor::new(vec![("TOK".into(), "s3cr3t-value-123".into()), ("SHORT".into(), "abc".into())])
    }

    #[test]
    fn redacts_variants() {
        let r = r();
        assert_eq!(r.redact("x s3cr3t-value-123 y").unwrap(), "x [lock:TOK] y");
        assert_eq!(r.redact("czNjcjN0LXZhbHVlLTEyMw==").unwrap(), "[lock:TOK]");
        assert!(r.redact("abc is too short to mask").is_none());
    }

    #[test]
    fn stream_split_across_reads() {
        struct Drip<'a>(&'a [u8]);
        impl Read for Drip<'_> {
            fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
                let n = self.0.len().min(3).min(b.len());
                b[..n].copy_from_slice(&self.0[..n]);
                self.0 = &self.0[n..];
                Ok(n)
            }
        }
        let mut out = Vec::new();
        r().copy(Drip(b"head s3cr3t-value-123 tail s3cr3t-value-123"), &mut out).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "head [lock:TOK] tail [lock:TOK]");
    }

    #[test]
    fn scrub_same_length() {
        let p = std::env::temp_dir().join(format!("hl-scrub-{}.jsonl", std::process::id()));
        let orig = "{\"c\":\"s3cr3t-value-123\"}\n";
        std::fs::write(&p, orig).unwrap();
        assert_eq!(r().scrub_file(&p).unwrap(), 1);
        let got = std::fs::read_to_string(&p).unwrap();
        assert_eq!(got, "{\"c\":\"[lock:TOK]******\"}\n");
        assert_eq!(got.len(), orig.len());
        std::fs::remove_file(p).unwrap();
    }
}
