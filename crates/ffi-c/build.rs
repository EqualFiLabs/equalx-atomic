fn main() {
    let crate_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let out = format!("{}/include/eswp.h", crate_dir);
    std::fs::create_dir_all(format!("{}/include", crate_dir)).unwrap();
    cbindgen::generate(crate_dir)
        .expect("cbindgen")
        .write_to_file(out);
}
