//! Atomic publish of a new operator artifact. An existing destination is
//! refused, and a failed write never leaves a partial file at the final path.

use std::path::Path;

/// Refuses `output` when it already exists, including as a dangling symlink.
pub(crate) fn refuse_existing_output(output: &Path, kind: &str) -> std::io::Result<()> {
    if std::fs::symlink_metadata(output).is_ok() {
        return Err(std::io::Error::other(format!(
            "output already exists: {} (refusing to overwrite {kind})",
            output.display()
        )));
    }
    Ok(())
}

/// Stages `bytes` beside `output`, syncs, and hard-links them into place.
pub(crate) fn publish_new_file(output: &Path, bytes: &[u8], kind: &str) -> std::io::Result<()> {
    refuse_existing_output(output, kind)?;
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let staged = parent.join(format!(
        ".artifact-{}-{}.partial",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0)
    ));
    {
        use std::io::Write;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let write_result = (|| {
            let mut file = options.open(&staged)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            Ok(())
        })();
        if let Err(error) = write_result {
            let _ = std::fs::remove_file(&staged);
            return Err(error);
        }
    }
    if let Err(error) = std::fs::hard_link(&staged, output) {
        let _ = std::fs::remove_file(&staged);
        return Err(std::io::Error::new(
            error.kind(),
            format!(
                "failed to publish {}: {error} (destination must not already exist)",
                output.display()
            ),
        ));
    }
    let _ = std::fs::remove_file(&staged);
    match std::fs::File::open(parent) {
        Ok(dir) => {
            if let Err(error) = dir.sync_all() {
                let _ = std::fs::remove_file(output);
                return Err(error);
            }
        }
        Err(error) => {
            let _ = std::fs::remove_file(output);
            return Err(error);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{publish_new_file, refuse_existing_output};

    #[test]
    fn an_existing_output_is_refused_and_left_intact() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bundle.json");
        std::fs::write(&path, b"signed").unwrap();
        let error = refuse_existing_output(&path, "a signed attestation bundle").unwrap_err();
        assert!(
            error.to_string().contains("output already exists"),
            "{error}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"signed");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn publish_writes_the_exact_bytes_and_leaves_no_partial() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bundle.json");
        publish_new_file(&path, b"canonical-bytes", "a signed attestation bundle").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"canonical-bytes");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn a_failed_write_leaves_no_destination_and_no_partial() {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("not-a-directory");
        std::fs::write(&parent, b"file").unwrap();
        let path = parent.join("bundle.json");
        assert!(publish_new_file(&path, b"bundle", "a signed attestation bundle").is_err());
        assert!(!path.exists());
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, ["not-a-directory"]);
    }
}
