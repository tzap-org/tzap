//! The reconstructed member stream must be readable by standard tar tools.
//!
//! §16 defines the payload as ustar headers with PAX extended headers -- the
//! POSIX.1-2001 pax interchange format -- so a stream tzap produces has to be
//! readable by the two implementations that actually matter, and a stream they
//! produce has to be ingestible here. That is a property of the format, not of
//! this crate's own reader agreeing with its own writer, so it needs an external
//! check: our reader would happily accept a header only we can parse.
//!
//! Skipped when no tar binary is present rather than failing, so the suite still
//! runs in a bare container.

use std::process::Command;
use tzap_core::{sequential_extract_tar_stream, write_archive, MasterKey, RegularFile, WriterOptions};

fn tar_binaries() -> Vec<&'static str> {
    ["tar", "gtar", "bsdtar"].into_iter().filter(|name| Command::new(name).arg("--version").output().is_ok_and(|out| out.status.success())).collect()
}

#[test]
fn standard_tar_tools_can_read_the_reconstructed_member_stream() {
    let binaries = tar_binaries();
    if binaries.is_empty() {
        eprintln!("no tar binary available; skipping the interop check");
        return;
    }

    let files =
        [RegularFile::new("src/f1.txt", b"content 1\n"), RegularFile::new("src/f2.txt", b"content 2\n"), RegularFile::new("src/sub/nested.txt", b"nested\n")];
    let key = MasterKey::from_raw_key(&[0x5a; 32]).unwrap();
    let options = WriterOptions { stripe_width: 1, volume_loss_tolerance: 0, bit_rot_buffer_pct: 0, ..WriterOptions::default() };
    let archive = write_archive(&files, &key, options).expect("archive");
    let tar = sequential_extract_tar_stream(&archive.bytes, &key).expect("member stream");

    let temp = tempfile::tempdir().unwrap();
    let tar_path = temp.path().join("members.tar");
    std::fs::write(&tar_path, &tar).unwrap();

    for binary in binaries {
        // Listing exercises the header parse; extracting proves the sizes and
        // block alignment are right, which a listing alone would not catch.
        let listed = Command::new(binary).args(["-tf", tar_path.to_str().unwrap()]).output().expect("tar must run");
        assert!(listed.status.success(), "{binary} could not read the stream: {}", String::from_utf8_lossy(&listed.stderr));
        let names = String::from_utf8_lossy(&listed.stdout);
        for expected in ["src/f1.txt", "src/f2.txt", "src/sub/nested.txt"] {
            assert!(names.contains(expected), "{binary} did not list {expected}; got:\n{names}");
        }

        let out = temp.path().join(format!("out-{binary}"));
        std::fs::create_dir_all(&out).unwrap();
        let extracted = Command::new(binary).args(["-xf", tar_path.to_str().unwrap(), "-C", out.to_str().unwrap()]).output().expect("tar must run");
        assert!(extracted.status.success(), "{binary} could not extract: {}", String::from_utf8_lossy(&extracted.stderr));
        assert_eq!(std::fs::read(out.join("src/f1.txt")).unwrap(), b"content 1\n", "{binary} extracted the wrong bytes");
        assert_eq!(std::fs::read(out.join("src/sub/nested.txt")).unwrap(), b"nested\n", "{binary} lost a nested member");
    }
}

/// And the other direction: a stream those tools produce must archive faithfully.
#[test]
fn a_standard_tar_stream_is_ingested_without_loss() {
    use tzap_core::{write_tar_stream_archive_to_sink_with_kdf_and_root_auth, KdfParams, MemoryArchiveSink};

    let binaries = tar_binaries();
    if binaries.is_empty() {
        eprintln!("no tar binary available; skipping the interop check");
        return;
    }

    for binary in binaries {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("tree");
        std::fs::create_dir_all(source.join("sub")).unwrap();
        std::fs::write(source.join("a.txt"), b"alpha\n").unwrap();
        std::fs::write(source.join("sub/b.txt"), b"beta\n").unwrap();

        let produced = Command::new(binary).args(["-cf", "-", "-C", temp.path().to_str().unwrap(), "tree"]).output().expect("tar must run");
        assert!(produced.status.success(), "{binary} could not create a stream");

        let key = MasterKey::from_raw_key(&[0x5a; 32]).unwrap();
        let kdf = KdfParams::Argon2id { t_cost: 1, m_cost_kib: 8, parallelism: 1, salt: b"12345678".to_vec() };
        let options = WriterOptions { stripe_width: 1, volume_loss_tolerance: 0, bit_rot_buffer_pct: 0, ..WriterOptions::default() };
        let mut sink = MemoryArchiveSink::default();
        write_tar_stream_archive_to_sink_with_kdf_and_root_auth(produced.stdout.as_slice(), &key, options, &kdf, None, None, &mut sink)
            .unwrap_or_else(|error| panic!("{binary} stream must be ingestible: {error:?}"));

        let refs = sink.volumes.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let opened = tzap_core::open_archive_volumes(&refs, &key).expect("archive must open");
        opened.verify().expect("archive must verify");
        assert_eq!(opened.extract_file("tree/a.txt").unwrap(), Some(b"alpha\n".to_vec()), "{binary}: member content must survive");
        assert_eq!(opened.extract_file("tree/sub/b.txt").unwrap(), Some(b"beta\n".to_vec()), "{binary}: nested member must survive");
    }
}
