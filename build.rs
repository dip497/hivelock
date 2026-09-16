// Turns vendored gitleaks rules (MIT, rules/LICENSE-gitleaks) into a static table.
use std::{env, fs, path::Path};

fn skip(id: &str) -> bool {
    // noisy generic rule + identifiers that are public, not secrets
    id == "generic-api-key"
        || id.ends_with("-client-id")
        || id.contains("-pub-")
        || id.contains("public-key")
        || id.ends_with("-access-id")
        || id.ends_with("-api-id")
}

fn main() {
    println!("cargo:rerun-if-changed=rules/gitleaks.toml");
    let src = fs::read_to_string("rules/gitleaks.toml").unwrap();
    let doc: toml::Table = src.parse().unwrap();
    let mut out = String::from("pub static RULES: &[Rule] = &[\n");
    for r in doc["rules"].as_array().unwrap() {
        let id = r["id"].as_str().unwrap();
        let (Some(re), Some(kws)) = (r.get("regex"), r.get("keywords")) else { continue };
        // path-scoped rules (e.g. only *.tf) are too noisy on free text
        if skip(id) || r.get("path").is_some() {
            continue;
        }
        let group = r.get("secretGroup").and_then(|v| v.as_integer()).unwrap_or(0);
        let entropy = r.get("entropy").and_then(|v| v.as_float()).unwrap_or(0.0);
        let kws: Vec<String> = kws
            .as_array()
            .unwrap()
            .iter()
            .map(|k| format!("{:?}", k.as_str().unwrap().to_ascii_lowercase()))
            .collect();
        out += &format!(
            "Rule {{ id: {:?}, re: {:?}, group: {}, entropy: {:?}, keywords: &[{}] }},\n",
            id,
            re.as_str().unwrap(),
            group,
            entropy,
            kws.join(",")
        );
    }
    out += "];\n";
    fs::write(Path::new(&env::var("OUT_DIR").unwrap()).join("rules.rs"), out).unwrap();
}
