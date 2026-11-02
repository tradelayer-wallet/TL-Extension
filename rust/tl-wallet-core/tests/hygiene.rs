//! The crate must stay wasm32-compatible in principle: no clock, filesystem, threads,
//! network, environment or ambient randomness in library sources (all subdirectories included).
use std::path::{Path, PathBuf};

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

#[test]
fn library_sources_have_no_ambient_authority() {
    let forbidden = [
        "std::fs",
        "std::thread",
        "std::net",
        "std::env",
        "std::process",
        "SystemTime",
        "Instant::now",
        "thread_rng",
        "getrandom",
        "OsRng",
        "unsafe ",
        "println!",
        "eprintln!",
        "dbg!",
        "unwrap()",
        "expect(",
        "panic!",
    ];
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&dir, &mut files);
    let mut seen = 0;
    let mut vault_seen = 0;
    for path in files {
        let text = std::fs::read_to_string(&path).unwrap();
        // strip doc/line comments so prose may mention the words
        let code: String = text
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        for f in forbidden {
            if f == "unsafe " && code.contains("forbid(unsafe_code)") {
                continue;
            }
            assert!(
                !code.replace("forbid(unsafe_code)", "").contains(f),
                "{} contains {f:?}",
                path.display()
            );
        }
        seen += 1;
        if path.components().any(|c| c.as_os_str() == "vault") {
            vault_seen += 1;
        }
    }
    assert!(seen >= 10);
    assert_eq!(vault_seen, 5, "mod, legacy, format, store, manager");
}

/// The dependency tree must not pull an ambient entropy source (it would break wasm32 builds
/// that have no `js` feature): the lockfile may not contain `getrandom` or `rand_core`.
#[test]
fn lockfile_has_no_ambient_entropy_crates() {
    let lock =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.lock")).unwrap();
    for name in ["getrandom", "rand_core", "rand"] {
        assert!(
            !lock.contains(&format!("name = \"{name}\"")),
            "{name} is in Cargo.lock"
        );
    }
}
