use std::fs;
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

fn workspace_file(path: &str) -> PathBuf {
    workspace_root().join(path)
}

fn read_workspace_file(path: &str) -> String {
    fs::read_to_string(workspace_file(path)).unwrap()
}

fn manifest_string_value(manifest: &str, key: &str) -> String {
    let prefix = format!("{key} = ");
    let line = manifest
        .lines()
        .find(|line| line.trim_start().starts_with(&prefix))
        .unwrap_or_else(|| panic!("missing manifest key `{key}`"));
    line.trim_start()
        .strip_prefix(&prefix)
        .unwrap()
        .trim()
        .trim_matches('"')
        .to_string()
}

fn manifest_array_values(manifest: &str, key: &str) -> Vec<String> {
    let prefix = format!("{key} = [");
    let start = manifest
        .find(&prefix)
        .unwrap_or_else(|| panic!("missing manifest array `{key}`"))
        + prefix.len();
    let end = manifest[start..]
        .find(']')
        .unwrap_or_else(|| panic!("unterminated manifest array `{key}`"))
        + start;

    manifest[start..end]
        .split(',')
        .map(|item| item.trim().trim_matches('"'))
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn assert_package_metadata(
    manifest_path: &str,
    crate_name: &str,
    docs_url: &str,
    expected_description_fragment: &str,
) {
    let manifest = read_workspace_file(manifest_path);

    assert!(manifest.contains(&format!("name = \"{crate_name}\"")));
    assert!(manifest.contains("version = \"0.1.0\""));
    assert!(manifest.contains("repository.workspace = true"));
    assert!(manifest.contains(&format!("documentation = \"{docs_url}\"")));
    assert_eq!(manifest_string_value(&manifest, "readme"), "README.md");

    let description = manifest_string_value(&manifest, "description");
    assert!(
        description.contains(expected_description_fragment),
        "description `{description}` should mention `{expected_description_fragment}`"
    );
    assert!(
        !manifest.contains("description.workspace = true"),
        "{crate_name} must use a package-specific description"
    );

    let readme = workspace_file(manifest_path)
        .parent()
        .unwrap()
        .join("README.md");
    assert!(readme.is_file(), "{crate_name} readme should exist");
}

#[test]
fn milestone12_manifests_have_crates_io_metadata() {
    assert_package_metadata(
        "crates/tzap-core/Cargo.toml",
        "tzap-core",
        "https://docs.rs/tzap-core",
        "Core library",
    );
    assert_package_metadata(
        "crates/tzap-cli/Cargo.toml",
        "tzap",
        "https://docs.rs/tzap",
        "Command-line tool",
    );
}

#[test]
fn milestone12_cli_uses_versioned_core_dependency_for_publish() {
    let manifest = read_workspace_file("crates/tzap-cli/Cargo.toml");

    assert!(manifest.contains(r#"tzap-core = { path = "../tzap-core", version = "0.1.0" }"#));
}

#[test]
fn milestone12_keywords_and_categories_fit_crates_io_limits() {
    for manifest_path in [
        "Cargo.toml",
        "crates/tzap-core/Cargo.toml",
        "crates/tzap-cli/Cargo.toml",
    ] {
        let manifest = read_workspace_file(manifest_path);
        let keywords = manifest_array_values(&manifest, "keywords");
        let categories = manifest_array_values(&manifest, "categories");

        assert!(
            !keywords.is_empty() && keywords.len() <= 5,
            "{manifest_path} should define one to five keywords"
        );
        assert!(
            !categories.is_empty() && categories.len() <= 5,
            "{manifest_path} should define one to five categories"
        );

        for keyword in keywords {
            assert!(
                keyword.len() <= 20
                    && keyword
                        .chars()
                        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_'),
                "`{keyword}` in {manifest_path} is not crates.io keyword-shaped"
            );
        }
    }
}

#[test]
fn milestone12_package_readmes_render_without_workspace_paths() {
    let root_readme = read_workspace_file("README.md");
    let cli_readme = read_workspace_file("crates/tzap-cli/README.md");
    let core_readme = read_workspace_file("crates/tzap-core/README.md");

    assert!(root_readme.contains("cargo install tzap"));
    assert!(cli_readme.contains("# tzap"));
    assert!(cli_readme.contains("cargo install tzap"));
    assert!(cli_readme.contains("tzap create --keyfile"));
    assert!(core_readme.contains("# tzap-core"));
    assert!(core_readme.contains("use tzap_core::"));
    assert!(core_readme.contains("write_archive"));

    for readme in [cli_readme, core_readme] {
        assert!(
            !readme.contains("../"),
            "package README should use publish-safe links"
        );
        assert!(
            readme.contains("https://github.com/frankmanzhu/tzap"),
            "package README should link to the repository"
        );
    }
}

#[test]
fn milestone12_package_trees_are_small_and_focused() {
    for package_dir in ["crates/tzap-core", "crates/tzap-cli"] {
        let package_dir = workspace_file(package_dir);
        let mut pending = vec![package_dir.clone()];
        while let Some(path) = pending.pop() {
            for entry in fs::read_dir(&path).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                let relative = path.strip_prefix(&package_dir).unwrap();
                let root_name = relative
                    .components()
                    .next()
                    .unwrap()
                    .as_os_str()
                    .to_string_lossy();

                assert!(
                    ["Cargo.toml", "README.md", "src", "tests"].contains(&root_name.as_ref()),
                    "unexpected package file: {}",
                    relative.display()
                );

                if path.is_dir() {
                    pending.push(path);
                } else {
                    let len = entry.metadata().unwrap().len();
                    assert!(
                        len < 1_000_000,
                        "package file {} is unexpectedly large ({len} bytes)",
                        relative.display()
                    );
                }
            }
        }
    }
}

#[test]
fn milestone12_release_readiness_checks_are_documented_in_order() {
    let plan = read_workspace_file("docs/tzap-cli-ux-production-readiness-plan.md");

    assert!(plan.contains("## Milestone 12: Crates.io Readiness\n\nStatus: done."));
    assert!(plan.contains("0.1.0 has been published before the CLI crate"));

    for command in [
        "cargo package -p tzap-core --list",
        "cargo package -p tzap --list",
        "cargo publish -p tzap-core --dry-run",
        "cargo publish -p tzap --dry-run",
        "cargo doc --workspace --no-deps",
    ] {
        assert!(
            plan.contains(command),
            "missing readiness command `{command}`"
        );
    }

    let core_publish = plan.find("cargo publish -p tzap-core --dry-run").unwrap();
    let cli_publish = plan.find("cargo publish -p tzap --dry-run").unwrap();
    assert!(
        core_publish < cli_publish,
        "tzap-core should be checked before tzap"
    );
}
