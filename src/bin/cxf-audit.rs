use std::{
    env, fs,
    path::{Path, PathBuf},
    process::ExitCode,
};

use cxf_audit::{scan_archive, scan_source, to_sarif, zipslip_poc_archive, Severity};

fn print_usage() {
    eprintln!(
        "cxf-audit — CXF/CXP zip-slip + source-code scanner (research tool, xem README.md)\n\n\
         Usage:\n  \
         cxf-audit gen-poc <output.zip> [traversal-entry-name]\n  \
         cxf-audit scan <archive.zip> [archive2.zip ...]\n  \
         cxf-audit scan-source [--format text|sarif] <file-or-dir> [file-or-dir2 ...]"
    );
}

/// Directory names pruned while *recursing* — never applied to a path given
/// directly on the command line, only to subdirectories discovered while
/// walking (so `cxf-audit scan-source target/` still works if you really
/// mean it). VCS metadata and build-artifact trees across the languages
/// this tool cares about (Rust, Kotlin/Gradle, Swift/CocoaPods, plus the
/// generic JS `node_modules` since importer glue code is sometimes TS/JS):
/// scanning into them is both wasteful (thousands of generated files) and
/// produces duplicate findings (e.g. `cargo package`'s `target/package/`
/// copy of the source tree).
const SKIP_DIRS: &[&str] = &[
    ".git",
    "target",
    "node_modules",
    "build",
    ".build",
    ".gradle",
    "dist",
    ".venv",
    "venv",
    "Pods",
    ".idea",
    ".vscode",
];

fn is_pruned_dir(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|name| SKIP_DIRS.contains(&name))
}

/// Recursively collects file paths under `root` (or just `root` itself if
/// it's a file). Skips paths it can't read rather than failing the whole
/// walk — a locked/permission-denied subdirectory shouldn't abort scanning
/// the rest of the tree. Does not follow symlinks (avoids cycles and
/// silently scanning outside the tree the caller asked for).
fn collect_files(root: &Path, out: &mut Vec<PathBuf>) {
    let Ok(meta) = fs::symlink_metadata(root) else {
        return;
    };
    if meta.is_symlink() {
        return;
    }
    if meta.is_file() {
        out.push(root.to_path_buf());
        return;
    }
    if !meta.is_dir() {
        return;
    }
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if is_pruned_dir(&path) {
            continue;
        }
        collect_files(&path, out);
    }
}

/// Scans one file, printing findings. Returns `true` if the file is clean.
fn scan_one(path: &str) -> bool {
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Lỗi đọc file {path}: {e}");
            return false;
        }
    };
    match scan_archive(&bytes) {
        Ok(findings) if findings.is_empty() => true,
        Ok(findings) => {
            for f in &findings {
                let tag = match f.severity {
                    Severity::Critical => "CRITICAL",
                    Severity::Info => "INFO",
                };
                println!("{path}: [{tag}] {} — {}", f.entry_name, f.message);
            }
            false
        }
        Err(e) => {
            eprintln!("Lỗi đọc archive {path}: {e}");
            false
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("gen-poc") => {
            let Some(out_path) = args.get(2) else {
                print_usage();
                return ExitCode::FAILURE;
            };
            let entry_name = args
                .get(3)
                .map(String::as_str)
                .unwrap_or("../../../../tmp/cxf-audit-poc-marker");
            match zipslip_poc_archive(entry_name) {
                Ok(bytes) => {
                    if let Err(e) = fs::write(out_path, bytes) {
                        eprintln!("Lỗi ghi file {out_path}: {e}");
                        return ExitCode::FAILURE;
                    }
                    println!("Đã tạo {out_path} (entry name: {entry_name})");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("Lỗi tạo archive: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Some("scan") => {
            let paths = &args[2..];
            if paths.is_empty() {
                print_usage();
                return ExitCode::FAILURE;
            }
            let all_clean = paths.iter().map(String::as_str).fold(true, |acc, path| {
                let clean = scan_one(path);
                acc && clean
            });
            if all_clean {
                println!("Không phát hiện path traversal trong tên entry.");
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Some("scan-source") => {
            let mut format = "text";
            let mut roots: Vec<&str> = Vec::new();
            let mut rest = args[2..].iter();
            while let Some(arg) = rest.next() {
                if arg == "--format" {
                    let Some(value) = rest.next() else {
                        print_usage();
                        return ExitCode::FAILURE;
                    };
                    format = value.as_str();
                } else {
                    roots.push(arg.as_str());
                }
            }
            if roots.is_empty() || !["text", "sarif"].contains(&format) {
                print_usage();
                return ExitCode::FAILURE;
            }

            let mut files = Vec::new();
            for root in &roots {
                collect_files(Path::new(root), &mut files);
            }
            let mut all_findings = Vec::new();
            for path in &files {
                let Ok(content) = fs::read_to_string(path) else {
                    continue; // binary/non-UTF8 file — not a source file we scan, skip silently
                };
                let Some(findings) = scan_source(path, &content) else {
                    continue; // extension not recognized (not .rs/.kt/.kts/.swift)
                };
                all_findings.extend(findings);
            }

            let any_findings = !all_findings.is_empty();
            if format == "sarif" {
                let sarif = to_sarif(&all_findings);
                println!("{}", serde_json::to_string_pretty(&sarif).unwrap());
            } else {
                for f in &all_findings {
                    let tag = match f.severity {
                        Severity::Critical => "CRITICAL",
                        Severity::Info => "INFO",
                    };
                    println!("{}:{}: [{tag}] {}", f.file, f.line, f.message);
                }
                if !any_findings {
                    println!("Không phát hiện pattern đáng ngờ trong source đã quét.");
                }
            }
            if any_findings {
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            }
        }
        _ => {
            print_usage();
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Unique temp dir per test — avoids collisions when tests run in
    /// parallel (the default for `cargo test`).
    fn temp_dir(label: &str) -> PathBuf {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            env::temp_dir().join(format!("cxf-audit-test-{label}-{n}-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn is_pruned_dir_matches_known_noise_names() {
        assert!(is_pruned_dir(Path::new("some/path/target")));
        assert!(is_pruned_dir(Path::new(".git")));
        assert!(is_pruned_dir(Path::new("a/b/node_modules")));
    }

    #[test]
    fn is_pruned_dir_does_not_match_unrelated_names() {
        assert!(!is_pruned_dir(Path::new("src")));
        assert!(!is_pruned_dir(Path::new("targets"))); // not an exact match
    }

    #[test]
    fn collect_files_skips_pruned_subdirectories() {
        let root = temp_dir("prune");
        fs::write(root.join("real.rs"), "fn f() {}").unwrap();
        let noise = root.join("target");
        fs::create_dir_all(&noise).unwrap();
        fs::write(noise.join("generated.rs"), "fn g() {}").unwrap();

        let mut files = Vec::new();
        collect_files(&root, &mut files);

        assert_eq!(files, vec![root.join("real.rs")]);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn collect_files_still_scans_a_pruned_name_if_passed_explicitly() {
        // SKIP_DIRS only prunes subdirectories found while recursing — a
        // root the caller names directly (e.g. `scan-source target/`) is
        // still scanned, matching the doc comment on SKIP_DIRS.
        let root = temp_dir("explicit-target").join("target");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("real.rs"), "fn f() {}").unwrap();

        let mut files = Vec::new();
        collect_files(&root, &mut files);

        assert_eq!(files, vec![root.join("real.rs")]);
        fs::remove_dir_all(root.parent().unwrap()).unwrap();
    }

    #[test]
    fn collect_files_does_not_follow_a_cyclic_symlink() {
        let root = temp_dir("symlink-cycle");
        fs::write(root.join("real.rs"), "fn f() {}").unwrap();
        std::os::unix::fs::symlink(&root, root.join("loop")).unwrap();

        let mut files = Vec::new();
        collect_files(&root, &mut files); // must terminate, not recurse forever

        assert_eq!(files, vec![root.join("real.rs")]);
        fs::remove_dir_all(&root).unwrap();
    }
}
