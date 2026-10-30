//! The crate must stay wasm32-compatible in principle: no clock, filesystem, threads,
//! network, environment or ambient randomness in library sources.
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
        "unsafe ",
        "println!",
        "eprintln!",
        "dbg!",
        "unwrap()",
        "expect(",
        "panic!",
    ];
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut seen = 0;
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
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
    }
    assert!(seen >= 10);
}
