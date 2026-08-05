use std::{
    env, fs,
    path::{Path, PathBuf},
    process::ExitCode,
};

use cxf_audit::{scan_archive, scan_source, zipslip_poc_archive, Severity};

fn print_usage() {
    eprintln!(
        "cxf-audit — CXF/CXP zip-slip + source-code scanner (research tool, xem README.md)\n\n\
         Usage:\n  \
         cxf-audit gen-poc <output.zip> [traversal-entry-name]\n  \
         cxf-audit scan <archive.zip> [archive2.zip ...]\n  \
         cxf-audit scan-source <file-or-dir> [file-or-dir2 ...]"
    );
}

/// Recursively collects file paths under `root` (or just `root` itself if
/// it's a file). Skips paths it can't read rather than failing the whole
/// walk — a locked/permission-denied subdirectory shouldn't abort scanning
/// the rest of the tree.
fn collect_files(root: &Path, out: &mut Vec<PathBuf>) {
    if root.is_file() {
        out.push(root.to_path_buf());
        return;
    }
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_files(&path, out);
        } else {
            out.push(path);
        }
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
            let roots = &args[2..];
            if roots.is_empty() {
                print_usage();
                return ExitCode::FAILURE;
            }
            let mut files = Vec::new();
            for root in roots {
                collect_files(Path::new(root), &mut files);
            }
            let mut any_findings = false;
            for path in &files {
                let Ok(content) = fs::read_to_string(path) else {
                    continue; // binary/non-UTF8 file — not a source file we scan, skip silently
                };
                let Some(findings) = scan_source(path, &content) else {
                    continue; // extension not recognized (not .rs/.kt/.kts/.swift)
                };
                for f in &findings {
                    any_findings = true;
                    let tag = match f.severity {
                        Severity::Critical => "CRITICAL",
                        Severity::Info => "INFO",
                    };
                    println!("{}:{}: [{tag}] {}", f.file, f.line, f.message);
                }
            }
            if any_findings {
                ExitCode::FAILURE
            } else {
                println!("Không phát hiện pattern đáng ngờ trong source đã quét.");
                ExitCode::SUCCESS
            }
        }
        _ => {
            print_usage();
            ExitCode::FAILURE
        }
    }
}
