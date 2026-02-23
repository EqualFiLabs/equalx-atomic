fn main() {
    let crate_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let include_dir = format!("{}/include", crate_dir);
    let out = format!("{include_dir}/eswp.h");
    std::fs::create_dir_all(&include_dir).unwrap();

    let bindings = cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_pragma_once(true)
        .with_documentation(true)
        .generate()
        .expect("cbindgen");
    bindings.write_to_file(&out);

    // Keep Flutter-side vendored header in sync with the generated source of truth.
    let flutter_out = format!("{crate_dir}/../../flutter/ffi/assets/include/eswp.h");
    if let Some(parent) = std::path::Path::new(&flutter_out).parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::copy(&out, flutter_out).expect("copy generated header to flutter assets");
}
