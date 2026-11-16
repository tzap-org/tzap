use std::{env, ffi::OsString, fs, path::PathBuf};

const BUILD_HELP: &str = "Run scripts/build-openssl.py and set OPENSSL_DIR and OPENSSL_STATIC=1. See https://github.com/tzap-org/tzap/blob/main/public-docs/tzap-installation.md#openssl-for-source-builds";
const RSA_PSS_ALIAS: &[u8] = b"RSA-PSS:RSASSA-PSS:rsassaPss:1.2.840.113549.1.1.10\0";

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=DOCS_RS");

    // Docs.rs builds API documentation in a sandbox without the provisioned OpenSSL.
    if env::var("DOCS_RS").as_deref() == Ok("1") {
        return;
    }

    // openssl-sys reports the version of the headers selected for this Cargo target.
    let version = env::var("DEP_OPENSSL_VERSION_NUMBER").ok().and_then(|value| u64::from_str_radix(&value, 16).ok());
    if version != Some(0x3050_0090) {
        let found = version.map_or_else(
            || "an unrecognized SSL library".to_owned(),
            |number| format!("OpenSSL {}.{}.{}", number >> 28, (number >> 20) & 0xff, (number >> 4) & 0xffff),
        );
        panic!("TZAP requires OpenSSL 3.5.9. Found {found}. {BUILD_HELP}");
    }

    let target = env::var("TARGET").expect("Cargo sets TARGET");
    let target_prefix = target.to_ascii_uppercase().replace('-', "_");
    let (library, default_libs) = if target.ends_with("-windows-msvc") { ("libcrypto.lib", "libssl:libcrypto") } else { ("libcrypto.a", "ssl:crypto") };
    let static_link = openssl_env(&target_prefix, "OPENSSL_STATIC");
    let custom_libs = openssl_env(&target_prefix, "OPENSSL_LIBS");
    if env::var_os("DEP_OPENSSL_VENDORED").is_some()
        || static_link.as_deref().is_some_and(|value| value == "0")
        || custom_libs.as_deref().is_some_and(|value| value != default_libs)
    {
        panic!("TZAP requires the patched OpenSSL 3.5.9 static libraries with their default library names. {BUILD_HELP}");
    }

    // Match openssl-sys's explicit library directory selection, including lib64 precedence.
    let directories = if let Some(directory) = openssl_env(&target_prefix, "OPENSSL_LIB_DIR") {
        vec![PathBuf::from(directory)]
    } else if let Some(prefix) = openssl_env(&target_prefix, "OPENSSL_DIR") {
        let prefix = PathBuf::from(prefix);
        vec![prefix.join("lib64"), prefix.join("lib")]
    } else {
        panic!("TZAP requires an explicit installation path for the patched OpenSSL 3.5.9 libraries. {BUILD_HELP}");
    };
    if static_link.as_deref().and_then(|value| value.to_str()).is_none()
        && default_libs.split(':').all(|name| {
            let shared_names = [format!("lib{name}.so"), format!("{name}.dll"), format!("lib{name}.dylib")];
            directories.iter().any(|directory| shared_names.iter().any(|file| directory.join(file).exists()))
        })
    {
        panic!("TZAP requires static OpenSSL 3.5.9. Set OPENSSL_STATIC=1 when shared libraries are also present. {BUILD_HELP}");
    }
    let archive = directories
        .into_iter()
        .map(|directory| directory.join(library))
        .find(|file| file.is_file())
        .unwrap_or_else(|| panic!("TZAP could not find the selected static {library}. {BUILD_HELP}"));
    println!("cargo:rerun-if-changed={}", archive.display());
    let bytes = fs::read(&archive).unwrap_or_else(|error| panic!("TZAP could not read {}: {error}", archive.display()));
    // The provider alias lives in libcrypto itself. Checking the archive also works for cross builds.
    if !bytes.windows(RSA_PSS_ALIAS.len()).any(|bytes| bytes == RSA_PSS_ALIAS) {
        panic!("TZAP requires the RSA-PSS provider alias backport in OpenSSL 3.5.9. {} is missing it. {BUILD_HELP}", archive.display());
    }
}

fn openssl_env(target_prefix: &str, name: &str) -> Option<OsString> {
    let target_name = format!("{target_prefix}_{name}");
    println!("cargo:rerun-if-env-changed={target_name}");
    println!("cargo:rerun-if-env-changed={name}");
    env::var_os(target_name).or_else(|| env::var_os(name))
}
