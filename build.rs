use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::Path};
fn main() {
    let mut files = BTreeMap::new();
    fn visit(path: &Path, files: &mut BTreeMap<String, String>) {
        for entry in fs::read_dir(path).unwrap() {
            let p = entry.unwrap().path();
            if p.is_dir() {
                visit(&p, files)
            } else if p.extension().is_some_and(|e| e == "rs" || e == "json") {
                let name = p.to_str().unwrap().replace('\\', "/");
                println!("cargo:rerun-if-changed={name}");
                files.insert(name, format!("{:x}", Sha256::digest(fs::read(p).unwrap())));
            }
        }
    }
    println!("cargo:rerun-if-changed=src");
    visit(Path::new("src"), &mut files);
    for name in ["Cargo.toml", "Cargo.lock", "build.rs"] {
        println!("cargo:rerun-if-changed={name}");
        if let Ok(data) = fs::read(name) {
            files.insert(name.into(), format!("{:x}", Sha256::digest(data)));
        }
    }
    let bytes = serde_json::to_vec(&files).unwrap();
    println!(
        "cargo:rustc-env=AGENTICSANDBOX_SOURCE_SHA256={:x}",
        Sha256::digest(&bytes)
    );
}
