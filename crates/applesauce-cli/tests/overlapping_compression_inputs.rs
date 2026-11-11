//! Generated APFS fixtures: overlapping compression roots must schedule one writer.
//! No user files or experimental Raven/Mesh filesystem modes are involved.

use std::fs;
use std::process::Command;

#[test]
fn overlapping_compression_roots_do_not_race_publication() {
    // Exercise both root orders: a directory before its file and vice versa.
    // A second writer previously could race the source inode's replacement.
    for file_first in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("selection");
        fs::create_dir(&root).unwrap();
        let source = root.join("generated.txt");
        let bytes = vec![b'K'; 3 * 65_536 + 17];
        fs::write(&source, &bytes).unwrap();

        let mut command = Command::new(env!("CARGO_BIN_EXE_applesauce"));
        command.args(["compress", "--verify", "-c", "zlib"]);
        if file_first {
            command.arg(&source).arg(&root);
        } else {
            command.arg(&root).arg(&source);
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "overlapping compression (file_first={file_first}) failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            applesauce::info::get(&source).unwrap().is_compressed,
            "generated input should be transparently compressed"
        );
        assert_eq!(
            fs::read(&source).unwrap(),
            bytes,
            "native compressed file must retain identical logical bytes"
        );

        // The other operation must also remain safe with overlapping roots.
        let restored = Command::new(env!("CARGO_BIN_EXE_applesauce"))
            .arg("decompress")
            .arg(&root)
            .arg(&source)
            .output()
            .unwrap();
        assert!(
            restored.status.success(),
            "overlapping restoration (file_first={file_first}) failed: {}",
            String::from_utf8_lossy(&restored.stderr)
        );
        assert!(!applesauce::info::get(&source).unwrap().is_compressed);
        assert_eq!(fs::read(&source).unwrap(), bytes);
    }
}
