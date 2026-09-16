use aho_corasick::AhoCorasick;
use regex::Regex;
use std::sync::OnceLock;

pub struct Rule {
    pub id: &'static str,
    pub re: &'static str,
    pub group: i64,
    pub entropy: f64,
    pub keywords: &'static [&'static str],
}

include!(concat!(env!("OUT_DIR"), "/rules.rs"));

#[derive(Debug, Clone)]
pub struct Finding {
    pub start: usize,
    pub end: usize,
    pub value: String,
    pub kind: String,
    pub name: String,
}

fn prefilter() -> &'static (AhoCorasick, Vec<usize>) {
    static P: OnceLock<(AhoCorasick, Vec<usize>)> = OnceLock::new();
    P.get_or_init(|| {
        let mut pats = Vec::new();
        let mut owner = Vec::new();
        for (i, r) in RULES.iter().enumerate() {
            for k in r.keywords {
                pats.push(*k);
                owner.push(i);
            }
        }
        let ac = AhoCorasick::builder().ascii_case_insensitive(true).build(pats).expect("keywords");
        (ac, owner)
    })
}

/// ASCII classes like Go RE2 (gitleaks' engine); Unicode `\\w` + `(?i)` is orders of magnitude slower.
pub fn compile(re: &str) -> Option<regex::bytes::Regex> {
    regex::bytes::RegexBuilder::new(re).unicode(false).size_limit(64 << 20).build().ok()
}

pub fn entropy(s: &str) -> f64 {
    let mut counts = [0usize; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    let n = s.len() as f64;
    counts.iter().filter(|c| **c > 0).map(|c| {
        let p = *c as f64 / n;
        -p * p.log2()
    }).sum()
}

/// Placeholders, templates and already-masked values are not secrets.
fn allowlisted(v: &str) -> bool {
    let l = v.to_ascii_lowercase();
    let first = v.as_bytes().first().copied().unwrap_or(0);
    v.bytes().all(|b| b == first)
        || v.starts_with('$')
        || v.contains("{{")
        || v.contains("[lock:")
        || ["example", "xxxxx", "changeme", "placeholder", "your_", "your-", "dummy", "redacted", "<", ">"]
            .iter()
            .any(|w| l.contains(w))
}

fn label_for_rule(id: &str) -> String {
    let fixed = match id {
        "github-pat" | "github-fine-grained-pat" | "github-oauth" | "github-app-token" | "github-refresh-token" => "GITHUB_TOKEN",
        "gitlab-pat" | "gitlab-pat-routable" => "GITLAB_TOKEN",
        "aws-access-token" => "AWS_ACCESS_KEY_ID",
        "gcp-api-key" => "GOOGLE_API_KEY",
        "stripe-access-token" => "STRIPE_SECRET_KEY",
        "npm-access-token" => "NPM_TOKEN",
        "pypi-upload-token" => "PYPI_TOKEN",
        "huggingface-access-token" | "huggingface-organization-api-token" => "HF_TOKEN",
        "anthropic-admin-api-key" => "ANTHROPIC_ADMIN_KEY",
        "sendgrid-api-token" => "SENDGRID_API_KEY",
        "digitalocean-pat" | "digitalocean-access-token" => "DIGITALOCEAN_TOKEN",
        "cloudflare-api-key" => "CLOUDFLARE_API_TOKEN",
        "databricks-api-token" => "DATABRICKS_TOKEN",
        "notion-api-token" => "NOTION_TOKEN",
        "sentry-access-token" | "sentry-org-token" | "sentry-user-token" => "SENTRY_AUTH_TOKEN",
        "doppler-api-token" => "DOPPLER_TOKEN",
        "hashicorp-tf-api-token" => "TF_TOKEN",
        "vault-service-token" | "vault-batch-token" => "VAULT_TOKEN",
        "discord-api-token" => "DISCORD_TOKEN",
        "telegram-bot-api-token" => "TELEGRAM_BOT_TOKEN",
        "mailgun-private-api-token" => "MAILGUN_API_KEY",
        "1password-service-account-token" => "OP_SERVICE_ACCOUNT_TOKEN",
        "private-key" => "PRIVATE_KEY",
        "jwt" | "jwt-base64" => "JWT",
        "curl-auth-header" | "curl-auth-user" => "API_TOKEN",
        _ => "",
    };
    if fixed.is_empty() { crate::vault::sanitize_name(id) } else { fixed.to_string() }
}

/// `FOO_TOKEN=...`, `"stripe_key": "...` → use the name written next to the value.
fn label_from_context(text: &str, start: usize) -> Option<String> {
    static CTX: OnceLock<Regex> = OnceLock::new();
    let re = CTX.get_or_init(|| {
        Regex::new(r#"([A-Za-z_][A-Za-z0-9_.-]*)["']?\s*(?:=|:=|:|=>)\s*["']?(?:(?i:bearer|token)\s+)?$"#).unwrap()
    });
    let line_start = text[..start].rfind('\n').map_or(0, |i| i + 1);
    let caps = re.captures(&text[line_start..start])?;
    let m = caps.get(1)?;
    let mut raw = m.as_str();
    // JVM style `-Dsonar.token=` and JSON-escaped `\\nFOO=` prefixes are not part of the name
    let before = &text[line_start..line_start + m.start()];
    if (before.ends_with('-') && raw.starts_with('D')) || (before.ends_with('\\') && raw.starts_with(['n', 't', 'r'])) {
        raw = &raw[1..];
    }
    let generic = ["authorization", "bearer", "token", "key", "apikey", "api_key", "password", "secret", "value", "auth", "export"];
    // prose like "nothing else: ghp_..." is not a variable name
    let identifier_like = raw.contains(['_', '-', '.']) || raw.chars().any(|c| c.is_ascii_uppercase());
    if generic.contains(&raw.to_ascii_lowercase().as_str()) || raw.len() < 3 || !identifier_like {
        return None;
    }
    Some(crate::vault::sanitize_name(raw))
}

pub fn detect(text: &str) -> Vec<Finding> {
    let (ac, owner) = prefilter();
    let mut hit = vec![false; RULES.len()];
    let mut any = false;
    for m in ac.find_overlapping_iter(text) {
        hit[owner[m.pattern().as_usize()]] = true;
        any = true;
    }
    if !any {
        return Vec::new();
    }
    let mut out: Vec<Finding> = Vec::new();
    for (rule, _) in RULES.iter().zip(hit).filter(|(_, h)| *h) {
        let Some(re) = compile(rule.re) else { continue };
        for caps in re.captures_iter(text.as_bytes()) {
            let m = if rule.group > 0 {
                caps.get(rule.group as usize)
            } else {
                (1..caps.len()).find_map(|g| caps.get(g)).or_else(|| caps.get(0))
            };
            let Some(m) = m else { continue };
            // ASCII-only classes may split a multi-byte char; such a span is not a token
            if !text.is_char_boundary(m.start()) || !text.is_char_boundary(m.end()) {
                continue;
            }
            let v = &text[m.start()..m.end()];
            if v.len() < 8 || (rule.entropy > 0.0 && entropy(v) < rule.entropy) || allowlisted(v) {
                continue;
            }
            let name = label_from_context(text, m.start()).unwrap_or_else(|| label_for_rule(rule.id));
            out.push(Finding { start: m.start(), end: m.end(), value: v.to_string(), kind: rule.id.to_string(), name });
        }
    }
    // longest span wins on overlap
    out.sort_by_key(|f| (f.start, std::cmp::Reverse(f.end)));
    let mut kept: Vec<Finding> = Vec::new();
    for f in out {
        if kept.last().is_some_and(|k| f.start < k.end) {
            continue;
        }
        kept.push(f);
    }
    kept
}

/// `KEY=value` lines of a dotenv file: (line index, key, value).
pub fn parse_env(text: &str) -> Vec<(usize, String, String)> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let l = line.trim();
        let l = l.strip_prefix("export ").unwrap_or(l);
        if l.starts_with('#') {
            continue;
        }
        let Some((k, v)) = l.split_once('=') else { continue };
        let k = k.trim();
        if k.is_empty() || !k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            continue;
        }
        let v = v.trim();
        let v = match v.chars().next() {
            Some(q @ ('"' | '\'')) => v[1..].split(q).next().unwrap_or(""),
            _ => v.split(" #").next().unwrap_or("").trim(),
        };
        out.push((i, k.to_string(), v.to_string()));
    }
    out
}

/// Heuristic: does this dotenv entry hold a secret (vs PORT=3000)?
pub fn env_secretish(key: &str, value: &str) -> bool {
    static USERINFO: OnceLock<Regex> = OnceLock::new();
    let k = key.to_ascii_uppercase();
    if value.is_empty() || value.contains("{{lock:") || allowlisted(value) || k.contains("PUBLIC") || k.contains("PUBLISHABLE") {
        return false;
    }
    ["KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "PWD", "AUTH", "CREDENTIAL", "PRIVATE", "DSN", "SALT"]
        .iter()
        .any(|w| k.contains(w))
        || USERINFO.get_or_init(|| Regex::new(r"://[^/\s:@]+:[^@\s]+@").unwrap()).is_match(value)
        || !detect(value).is_empty()
}

/// Rules + context-based generic secrets (`password = "..."`, `Authorization: Bearer ...`,
/// `scheme://user:pass@host`). Generic matches are noisier, so this runs on chat text only,
/// never on tool output that gets auto-captured.
pub fn detect_chat(text: &str) -> Vec<Finding> {
    let mut out = detect(text);
    for f in generic(text) {
        if !out.iter().any(|k| f.start < k.end && k.start < f.end) {
            out.push(f);
        }
    }
    out.sort_by_key(|f| f.start);
    out
}

fn generic_res() -> &'static [(Regex, &'static str); 3] {
    static RES: OnceLock<[(Regex, &'static str); 3]> = OnceLock::new();
    RES.get_or_init(|| {
        [
            (
                Regex::new(
                    r#"(?i)(?:^|\\[ntr]|[^A-Za-z0-9_.-])([A-Za-z0-9_.-]*(?:passw(?:or)?d|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|auth[_-]?key|private[_-]?key|client[_-]?secret|credentials?)[A-Za-z0-9_]*)["']?[ \t]*(?:=|:=|:|=>)[ \t]*(["'`]?)([^\s"'`,;)}\]]{8,200})"#,
                )
                .unwrap(),
                "generic-secret",
            ),
            (
                Regex::new(r#"(?i)\b(?:authorization|proxy-authorization|x-api-key|api-key|x-auth-token)["']?[ \t]*[:=][ \t]*["']?(?:(?:bearer|token|basic)[ \t]+)?([A-Za-z0-9._~+/=-]{16,})"#).unwrap(),
                "auth-header",
            ),
            (Regex::new(r#"\b([a-z][a-z0-9+.-]{1,20})://[^:/\s@'"]+:([^@\s/'"]{6,})@[^\s/:'"]+"#).unwrap(), "url-password"),
        ]
    })
}

/// Key names that mention a secret but hold metadata, not the secret.
fn metadata_key(k: &str) -> bool {
    let l = k.to_ascii_lowercase();
    l.contains("public")
        || l.contains("publishable")
        || ["_id", "_url", "_uri", "_file", "_path", "_name", "_type", "_len", "_length", "_count", "_endpoint", "_header",
            "_field", "_hint", "_expires", "_expiry", "_ttl", "_policy", "_prompt", "_label", "_env", "_var", "_limit", "_size",
            "_usage", "_budget"]
            .iter()
            .any(|s| l.ends_with(s))
        || ["tokens", "cost", "exception", "error", "context", "service", "provider", "manager", "factory", "handler"]
            .iter()
            .any(|w| l.contains(w))
        || l.starts_with("max_")
}

/// Values that look like code/prose, not a secret.
fn not_secret_value(v: &str, quoted: bool, env_style: bool) -> bool {
    let l = v.to_ascii_lowercase();
    let classes = [v.bytes().any(|b| b.is_ascii_lowercase()), v.bytes().any(|b| b.is_ascii_uppercase()), v.bytes().any(|b| b.is_ascii_digit()), v.bytes().any(|b| !b.is_ascii_alphanumeric())]
        .iter()
        .filter(|x| **x)
        .count();
    let env_name = v.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_') && v.contains('_');
    let uuidish = v.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') && v.matches('-').count() >= 3;
    allowlisted(v)
        || env_name
        || uuidish
        || v.contains("://")
        // env-style assignments may hold real weak lowercase passwords; in prose the same shape is a word
        || (!env_style && (classes < 2 || !v.bytes().any(|b| b.is_ascii_digit() || b.is_ascii_uppercase())))
        // unquoted code: calls and member access (token = req.header("x"), key = cfg.api.key)
        || (!quoted && (v.contains('(') || v.contains('\\') || (v.contains('.') && v.split('.').all(|p| p.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')))))
        || entropy(v) < if env_style { 2.5 } else { 3.0 }
        || ["null", "none", "true", "false", "undefined", "password", "secret", "process.env", "os.environ", "getenv", "env.", "config.", "settings.", "self.", "this.", "***", "%s", "{}", "()", "=>"]
            .iter()
            .any(|w| l.contains(w))
        // unquoted identifiers / dotted paths / calls are references: token = get_token()
        || (!quoted && !env_style && v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'(' || b == b')') && !v.bytes().any(|b| b.is_ascii_digit()))
        // file paths and urls
        || v.contains('/') && !v.contains("://") && v.chars().filter(|c| *c == '/').count() > 1
}

fn generic(text: &str) -> Vec<Finding> {
    let res = generic_res();
    let mut out = Vec::new();
    for c in res[0].0.captures_iter(text) {
        let (key, val) = (c.get(1).unwrap(), c.get(3).unwrap());
        let k = key.as_str();
        let env_style = k.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_') && text[key.end()..val.start()].trim_matches(['"', '\'']).trim() == "=";
        if metadata_key(k) || not_secret_value(val.as_str(), !c[2].is_empty(), env_style) {
            continue;
        }
        let name = crate::vault::sanitize_name(key.as_str().trim_matches(['-', '.']));
        out.push(Finding { start: val.start(), end: val.end(), value: val.as_str().into(), kind: res[0].1.into(), name });
    }
    for c in res[1].0.captures_iter(text) {
        let v = c.get(1).unwrap();
        if allowlisted(v.as_str()) || entropy(v.as_str()) < 3.5 {
            continue;
        }
        out.push(Finding { start: v.start(), end: v.end(), value: v.as_str().into(), kind: res[1].1.into(), name: "API_TOKEN".into() });
    }
    for c in res[2].0.captures_iter(text) {
        let v = c.get(2).unwrap();
        if allowlisted(v.as_str()) || ["password", "pass", "passwd", "secret", "user", "admin"].contains(&v.as_str().to_ascii_lowercase().as_str()) {
            continue;
        }
        let name = format!("{}_PASSWORD", crate::vault::sanitize_name(c[1].split('+').next().unwrap_or("DB")));
        out.push(Finding { start: v.start(), end: v.end(), value: v.as_str().into(), kind: res[2].1.into(), name });
    }
    out
}

/// Synthetic GitHub-token-shaped string for self-tests (`doctor`). Not a real credential.
pub fn fake_token() -> String {
    let mut seed = crate::vault::now() ^ std::process::id() as u64;
    let chars: String = (0..36)
        .map(|_| {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"[(seed >> 33) as usize % 62] as char
        })
        .collect();
    format!("ghp_{chars}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_rules_compile() {
        let bad: Vec<_> = RULES.iter().filter(|r| compile(r.re).is_none()).map(|r| r.id).collect();
        assert!(bad.is_empty(), "rules failing to compile: {bad:?}");
        assert!(RULES.len() > 190);
    }

    #[test]
    fn detects_and_labels() {
        let t = fake_token();
        let f = detect(&format!("please use {t} for the api"));
        assert_eq!(f.len(), 1);
        assert_eq!((f[0].name.as_str(), f[0].value.as_str()), ("GITHUB_TOKEN", t.as_str()));

        let f = detect(&format!("MY_BOT_PAT={t}"));
        assert_eq!(f[0].name, "MY_BOT_PAT");
        assert_eq!(detect(&format!("reply with nothing else: {t}"))[0].name, "GITHUB_TOKEN");
        assert_eq!(detect(&format!("myToken: {t}"))[0].name, "MYTOKEN");

        // fixtures are assembled at runtime so secret scanners never see a literal token in this repo
        let aws = detect(&format!("key AKIAIOSFODNN7EXAMPLE and {}{}", "AKIA", "Z4Q2LMNB7XK3PQRS"));
        assert_eq!(aws.len(), 1, "EXAMPLE placeholder must be ignored");
        assert_eq!(aws[0].name, "AWS_ACCESS_KEY_ID");

        let (begin, end) = (["-----BEGIN OPENSSH ", "PRIVATE KEY-----"].concat(), ["-----END OPENSSH ", "PRIVATE KEY-----"].concat());
        let pem = format!("{begin}\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n{end}");
        assert_eq!(detect(&pem)[0].name, "PRIVATE_KEY");
    }

    #[test]
    fn ignores_normal_text() {
        for s in [
            "commit 3f786850e387550fdab836ed7e6dc881de23001b fixed the key handling",
            "uuid 550e8400-e29b-41d4-a716-446655440000, they said okay",
            "set GITHUB_TOKEN={{lock:GITHUB_TOKEN}} then run",
            "export API_KEY=your_api_key_here",
        ] {
            assert!(detect(s).is_empty(), "false positive on: {s} -> {:?}", detect(s));
        }
    }

    #[test]
    fn generic_chat_secrets() {
        let names = |t: &str| detect_chat(t).into_iter().map(|f| (f.name, f.value)).collect::<Vec<_>>();
        assert_eq!(names("db_password = \"hunter2-Xk92pq\""), vec![("DB_PASSWORD".into(), "hunter2-Xk92pq".into())]);
        assert_eq!(names("connect to postgres://app:s3cretPw77@db.local/app"), vec![("POSTGRES_PASSWORD".into(), "s3cretPw77".into())]);
        assert_eq!(names("curl -H 'Authorization: Bearer abC9dEf2GhI5jKl8MnO1'")[0].0, "API_TOKEN");
        assert_eq!(names(&format!("STRIPE_WEBHOOK_SECRET: {}9fJk2LmQ7rT4vX8z", "whsec_"))[0].0, "STRIPE_WEBHOOK_SECRET");
        assert_eq!(names("PGPASSWORD=correcthorse psql -h db")[0].0, "PGPASSWORD");
        assert_eq!(names("{\"cmd\":\"x\\nAPP_DB_PASSWORD=Q7vT9mK2pL\"}")[0].0, "APP_DB_PASSWORD");
    }

    #[test]
    fn generic_ignores_code_and_prose() {
        for s in [
            "token = get_token()",
            "password = os.environ['DB_PASSWORD']",
            "api_key: ${{ secrets.API_KEY }}",
            "const secret = config.jwtSecret;",
            "password: changeme123",
            "max_tokens: 4096",
            "token_url = https://auth.example.com/oauth/token",
            "the password field is required",
            "your password: anything",
            "secret_name: prod/db/credentials",
            "input_tokens: 12345678",
            "Authorization: Bearer {{lock:API_TOKEN}}",
            "postgres://user:password@localhost/db",
            "passwordHash = bcrypt(password)",
            "String oauthAccessToken = generateOAuth2AccessToken(user);",
            "BadCredentialsException: Bad credentials for user admin2",
            "UP_TOKEN::https://auth.example.org/realms/x",
            "XSRF_TOKEN=0bb47c1e-4f2a-4b9e-9d3c-1a2b3c4d5e6f",
            "latestToken = tokenStore.get(key1)",
            "input_token_cost_flex: 0.0000025",
            "\"github-refresh-token\" => \"GITHUB_TOKEN\",",
        ] {
            assert!(detect_chat(s).is_empty(), "false positive on: {s} -> {:?}", detect_chat(s));
        }
    }
}
