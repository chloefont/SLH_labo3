use std::path::Path;
use std::env;
use std::fs;

fn main() {
    // This is just a hack to simplify Windows build
    if cfg!(target_os = "windows") {
        let dir = env::var("CARGO_MANIFEST_DIR").unwrap();
        let profile = env::var("PROFILE").unwrap();
        
        // Set libpq.lib folder for the linker
        let libs = Path::new(&dir).join("win_libs");
        println!("cargo:rustc-link-search={}", libs.display());

        // Copy postgres libraries to output folder
        let out_dir = Path::new(&dir).join("target").join(&profile);
        fs::copy(libs.join("libcrypto-3-x64.dll"), out_dir.join("libcrypto-3-x64.dll")).unwrap();
        fs::copy(libs.join("libiconv-2.dll"), out_dir.join("libiconv-2.dll")).unwrap();
        fs::copy(libs.join("libintl-9.dll"), out_dir.join("libintl-9.dll")).unwrap();
        fs::copy(libs.join("libpq.dll"), out_dir.join("libpq.dll")).unwrap();
        fs::copy(libs.join("libssl-3-x64.dll"), out_dir.join("libssl-3-x64.dll")).unwrap();
    }
}

