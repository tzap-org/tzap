mod support;
mod seeds;

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

const TARGETS: [(&str, fn(&[u8])); 3] = [
    ("parse_fixed_structures", support::parse_fixed_structures),
    ("parse_metadata", support::parse_metadata),
    (
        "parse_compressed_and_padding",
        support::parse_compressed_and_padding,
    ),
];

const EMBEDDED_SEEDS: [(&str, &[u8]); 5] = [
    ("empty", b""),
    ("v36-magic-markers", b"TZAPTZCHTZBKTZMFTZVTTZBS"),
    ("metadata-magic-markers", b"TZIRTZISTZDH"),
    ("zstd-skippable-marker", &[0x50, 0x2a, 0x4d, 0x18, 0, 0, 0, 0]),
    ("wide-padding-marker", &[0, 0, 0, 0, 5, 0xff]),
];

fn main() -> Result<(), Box<dyn Error>> {
    let corpus_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus");
    let mut total = 0usize;

    for seed in seeds::structured_seeds() {
        let harness = TARGETS
            .iter()
            .find(|(name, _)| *name == seed.target)
            .map(|(_, harness)| *harness)
            .ok_or_else(|| format!("unknown structured seed target {}", seed.target))?;
        seeds::assert_structured_seed_success(&seed)
            .map_err(|err| format!("{}/{} did not hit expected valid parse path: {err}", seed.target, seed.name))?;
        harness(&seed.bytes);
        total += 1;
        println!("smoke: {}/{}", seed.target, seed.name);
    }

    for (name, harness) in TARGETS {
        for (seed_name, seed) in EMBEDDED_SEEDS {
            harness(seed);
            total += 1;
            println!("smoke: {name}/{seed_name}");
        }

        let target_dir = corpus_root.join(name);
        let file_count = run_target_corpus(&target_dir, harness)?;
        if file_count == 0 {
            return Err(format!("no fuzz corpus seeds found in {}", target_dir.display()).into());
        }
        total += file_count;
    }

    println!("fuzz smoke parsed {total} deterministic seeds");
    Ok(())
}

fn run_target_corpus(
    target_dir: &Path,
    harness: fn(&[u8]),
) -> Result<usize, Box<dyn Error>> {
    let mut seed_paths = fs::read_dir(target_dir)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<PathBuf>, _>>()?;
    seed_paths.sort();

    let mut count = 0usize;
    for path in seed_paths {
        if !path.is_file() {
            continue;
        }
        let data = fs::read(&path)?;
        harness(&data);
        count += 1;
        println!("smoke: {}", path.display());
    }
    Ok(count)
}
