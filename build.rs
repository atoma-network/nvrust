use std::process::Command;

fn main() {
    // Find Python's library path
    let python_lib_path = String::from_utf8(
        Command::new("python3")
            .args(&["-c", "import sysconfig; print(sysconfig.get_config_var('LIBDIR'))"])
            .output()
            .expect("Failed to run python")
            .stdout,
    )
    .expect("Failed to parse python output")
    .trim()
    .to_string();

    // Find Python's library name (might be libpython3.x.dylib on macOS)
    let python_lib_name = String::from_utf8(
        Command::new("python3")
            .args(&["-c", "import sysconfig; import re; print(re.sub(r'^lib|\\.(so|dylib)$', '', sysconfig.get_config_var('INSTSONAME')))"])
            .output()
            .expect("Failed to run python")
            .stdout,
    )
    .expect("Failed to parse python output")
    .trim()
    .to_string();

    // Tell cargo to tell rustc to link the Python library
    println!("cargo:rustc-link-search={}", python_lib_path);
    println!("cargo:rustc-link-lib={}", python_lib_name);
    
    // Force re-run if the build script changes
    println!("cargo:rerun-if-changed=build.rs");
} 