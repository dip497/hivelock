use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::XChaCha20Poly1305;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(test)]
pub static TEST_ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());

const VAULT_MAGIC: &[u8] = b"HLV1";
const LOCKED_MAGIC: &[u8] = b"HLL1";

pub fn home() -> PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

pub fn data_dir() -> PathBuf {
    if let Some(p) = std::env::var_os("HIVELOCK_HOME") {
        return p.into();
    }
    #[cfg(windows)]
    let base = std::env::var_os("APPDATA").map(PathBuf::from).unwrap_or_else(home);
    #[cfg(target_os = "macos")]
    let base = home().join("Library/Application Support");
    #[cfg(all(unix, not(target_os = "macos")))]
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home().join(".local/share"));
    base.join("hivelocker")
}

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).expect("os rng");
    b
}

pub fn private_open(path: &Path, append: bool) -> std::io::Result<File> {
    let mut o = OpenOptions::new();
    o.create(true);
    if append {
        o.append(true);
    } else {
        o.write(true).truncate(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)
}

/// Atomic write: temp file + rename, never a half-written vault.
fn write_private(path: &Path, data: &[u8]) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    let mut f = private_open(&tmp, false).map_err(|e| e.to_string())?;
    f.write_all(data).and_then(|_| f.sync_all()).map_err(|e| e.to_string())?;
    fs::rename(&tmp, path).map_err(|e| e.to_string())
}

fn seal(key: &[u8; 32], header: &[u8], plain: &[u8]) -> Vec<u8> {
    let nonce = random::<24>();
    let mut buf = plain.to_vec();
    XChaCha20Poly1305::new(key.into())
        .encrypt_in_place(&nonce.into(), header, &mut buf)
        .expect("encrypt");
    [header, &nonce, &buf].concat()
}

fn unseal(key: &[u8; 32], header_len: usize, data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < header_len + 24 {
        return Err("vault file truncated".into());
    }
    let (header, rest) = data.split_at(header_len);
    let (nonce, ct) = rest.split_at(24);
    let mut buf = ct.to_vec();
    XChaCha20Poly1305::new(key.into())
        .decrypt_in_place(nonce.into(), header, &mut buf)
        .map_err(|_| "decrypt failed (wrong key/passphrase or corrupted file)".to_string())?;
    Ok(buf)
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Entry {
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub value: String,
    pub kind: String,
    /// "global" or an absolute project path
    pub scope: String,
    pub source: String,
    pub created: u64,
    #[serde(default)]
    pub locked: bool,
    /// agent use needs the user's approval each time
    #[serde(default)]
    pub ask: bool,
    /// used as a file: `{{lock:NAME}}` becomes a path to a 0600 temp copy (keys, service-account json, kubeconfig)
    #[serde(default)]
    pub file: bool,
    #[serde(default)]
    pub retired: bool,
}

#[derive(Serialize, Deserialize, Default)]
pub struct Vault {
    pub entries: Vec<Entry>,
}

pub struct Store {
    pub dir: PathBuf,
    key: [u8; 32],
    pub vault: Vault,
    _lock: Option<File>,
}

/// Key material that tools expect as a file path, not as a string.
pub fn is_file_secret(kind: &str, value: &str) -> bool {
    kind == "private-key" || kind.starts_with("file") || (value.contains('\n') && value.trim_start().starts_with("-----BEGIN"))
}

pub fn valid_name(n: &str) -> bool {
    let b = n.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && b[0].is_ascii_uppercase()
        && b.iter().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == b'_')
}

pub fn sanitize_name(raw: &str) -> String {
    let mut s: String = raw
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_uppercase() } else { '_' })
        .collect();
    if !s.starts_with(|c: char| c.is_ascii_uppercase()) {
        s.insert_str(0, "S_");
    }
    s.truncate(64);
    s
}

impl Store {
    pub fn key_path() -> PathBuf {
        data_dir().join("key")
    }

    pub fn initialized() -> bool {
        Self::key_path().exists()
    }

    /// Creates data dir + random key if missing. Returns true when newly created.
    pub fn init() -> Result<bool, String> {
        let dir = data_dir();
        fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
        }
        if Self::initialized() {
            return Ok(false);
        }
        let hex: String = random::<32>().iter().map(|b| format!("{b:02x}")).collect();
        write_private(&Self::key_path(), hex.as_bytes())?;
        Ok(true)
    }

    fn load(lock: bool) -> Result<Self, String> {
        let dir = data_dir();
        let hex = fs::read_to_string(dir.join("key")).map_err(|_| "not initialized: run `hivelock init`".to_string())?;
        let hex = hex.trim();
        if hex.len() != 64 {
            return Err("key file malformed".into());
        }
        let mut key = [0u8; 32];
        for (i, k) in key.iter_mut().enumerate() {
            *k = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| "key file malformed")?;
        }
        let _lock = if lock {
            // not append-only: Windows LockFileEx rejects append-only handles
            let mut o = OpenOptions::new();
            o.write(true).create(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                o.mode(0o600);
            }
            let f = o.open(dir.join("lock")).map_err(|e| e.to_string())?;
            f.lock().map_err(|e| e.to_string())?;
            Some(f)
        } else {
            None
        };
        let vault = match fs::read(dir.join("vault.bin")) {
            Ok(data) => serde_json::from_slice(&unseal(&key, VAULT_MAGIC.len(), &data)?).map_err(|e| e.to_string())?,
            Err(_) => Vault::default(),
        };
        Ok(Store { dir, key, vault, _lock })
    }

    /// Read-only snapshot (hooks on the hot path).
    pub fn open() -> Result<Self, String> {
        Self::load(false)
    }

    /// Exclusive lock held until drop; use for read-modify-write.
    pub fn open_rw() -> Result<Self, String> {
        Self::load(true)
    }

    pub fn save(&self) -> Result<(), String> {
        let plain = serde_json::to_vec(&self.vault).map_err(|e| e.to_string())?;
        write_private(&self.dir.join("vault.bin"), &seal(&self.key, VAULT_MAGIC, &plain))
    }

    pub fn live(&self) -> impl Iterator<Item = &Entry> {
        self.vault.entries.iter().filter(|e| !e.retired)
    }

    fn scope_rank(scope: &str, cwd: &Path) -> Option<usize> {
        if scope == "global" {
            Some(0)
        } else if cwd.starts_with(scope) {
            Some(1 + scope.len())
        } else {
            None
        }
    }

    /// Deepest project scope containing cwd wins, then global.
    pub fn resolve_idx(&self, name: &str, cwd: &Path) -> Option<usize> {
        self.vault
            .entries
            .iter()
            .enumerate()
            .filter(|(_, e)| !e.retired && e.name == name)
            .filter_map(|(i, e)| Self::scope_rank(&e.scope, cwd).map(|r| (r, i)))
            .max()
            .map(|(_, i)| i)
    }

    pub fn resolve(&self, name: &str, cwd: &Path) -> Option<&Entry> {
        self.resolve_idx(name, cwd).map(|i| &self.vault.entries[i])
    }

    /// Names visible from cwd (for hints to agents).
    pub fn visible_names(&self, cwd: &Path) -> Vec<String> {
        let mut v: Vec<String> = self
            .live()
            .filter(|e| Self::scope_rank(&e.scope, cwd).is_some())
            .map(|e| match (e.locked, e.ask) {
                (true, _) => format!("{} (locked)", e.name),
                (_, true) => format!("{} (ask)", e.name),
                _ => e.name.clone(),
            })
            .collect();
        v.sort();
        v.dedup();
        v
    }

    /// Adds a secret. Same value already stored → existing name, false.
    /// Name taken in the same scope → NAME_2, NAME_3...
    pub fn add(&mut self, hint: &str, value: &str, kind: &str, scope: &str, source: &str) -> (String, bool) {
        if let Some(e) = self.live().find(|e| !e.value.is_empty() && e.value == value) {
            return (e.name.clone(), false);
        }
        let base = if valid_name(hint) { hint.to_string() } else { sanitize_name(hint) };
        let taken = |n: &str| self.live().any(|e| e.name == n && e.scope == scope);
        let mut name = base.clone();
        let mut i = 2;
        while taken(&name) {
            name = format!("{base}_{i}");
            i += 1;
        }
        self.vault.entries.push(Entry {
            name: name.clone(),
            value: value.to_string(),
            kind: kind.to_string(),
            scope: scope.to_string(),
            source: source.to_string(),
            created: now(),
            locked: false,
            ask: false,
            file: is_file_secret(kind, value),
            retired: false,
        });
        (name, true)
    }

    /// (name, value) for everything that must be masked, retired values included.
    pub fn mask_pairs(&self) -> Vec<(String, String)> {
        let mut v: Vec<(String, String)> = self
            .vault
            .entries
            .iter()
            .filter(|e| !e.value.is_empty())
            .flat_map(|e| {
                let mut p = vec![(e.name.clone(), e.value.clone())];
                // key files get printed re-wrapped or partially; mask each body line too
                if e.file {
                    p.extend(e.value.lines().map(str::trim).filter(|l| l.len() >= 20 && !l.starts_with("-----")).map(|l| (e.name.clone(), l.to_string())));
                }
                p
            })
            .collect();
        // the vault key itself must never reach an agent either
        if let Ok(k) = fs::read_to_string(Self::key_path()) {
            v.push(("HIVELOCK_KEY".into(), k.trim().to_string()));
        }
        v
    }

    fn locked_path(&self) -> PathBuf {
        self.dir.join("locked.bin")
    }

    pub fn has_locked_file(&self) -> bool {
        self.locked_path().exists()
    }

    fn pass_key(pass: &str, salt: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let params = scrypt::Params::new(15, 8, 1, 32).expect("scrypt params");
        scrypt::scrypt(pass.as_bytes(), salt, &params, &mut out).expect("scrypt");
        out
    }

    /// Locked values keyed by "scope\nname"; encrypted with a passphrase-derived key only.
    pub fn read_locked(&self, pass: &str) -> Result<BTreeMap<String, String>, String> {
        let Ok(data) = fs::read(self.locked_path()) else { return Ok(BTreeMap::new()) };
        let hdr = LOCKED_MAGIC.len() + 16;
        if data.len() < hdr {
            return Err("locked file truncated".into());
        }
        let key = Self::pass_key(pass, &data[LOCKED_MAGIC.len()..hdr]);
        serde_json::from_slice(&unseal(&key, hdr, &data)?).map_err(|e| e.to_string())
    }

    pub fn write_locked(&self, pass: &str, map: &BTreeMap<String, String>) -> Result<(), String> {
        let salt = random::<16>();
        let key = Self::pass_key(pass, &salt);
        let header = [LOCKED_MAGIC, &salt].concat();
        let plain = serde_json::to_vec(map).map_err(|e| e.to_string())?;
        write_private(&self.locked_path(), &seal(&key, &header, &plain))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_dedupe_scope_lock() {
        let _env = TEST_ENV.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("hivelock-test-{}", std::process::id()));
        std::env::set_var("HIVELOCK_HOME", &dir);
        assert!(Store::init().unwrap());
        let mut s = Store::open_rw().unwrap();
        assert_eq!(s.add("GITHUB_TOKEN", "ghp_aaaaaaaaaaaaaaaa", "github-pat", "global", "chat"), ("GITHUB_TOKEN".into(), true));
        assert_eq!(s.add("OTHER", "ghp_aaaaaaaaaaaaaaaa", "x", "global", "chat"), ("GITHUB_TOKEN".into(), false));
        assert_eq!(s.add("GITHUB_TOKEN", "ghp_bbbbbbbbbbbbbbbb", "x", "global", "chat").0, "GITHUB_TOKEN_2");
        s.add("DB_URL", "postgres://proj", "x", "/work/shop", "import");
        s.add("DB_URL", "postgres://glob", "x", "global", "import");
        s.save().unwrap();
        drop(s);
        let s = Store::open().unwrap();
        assert_eq!(s.resolve("DB_URL", Path::new("/work/shop/api")).unwrap().value, "postgres://proj");
        assert_eq!(s.resolve("DB_URL", Path::new("/work/blog")).unwrap().value, "postgres://glob");
        let mut m = BTreeMap::new();
        m.insert("global\nX".to_string(), "v".to_string());
        s.write_locked("pw", &m).unwrap();
        assert_eq!(s.read_locked("pw").unwrap(), m);
        assert!(s.read_locked("bad").is_err());
        let _ = fs::remove_dir_all(dir);
    }
}
