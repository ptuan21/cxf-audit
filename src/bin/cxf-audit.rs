use std::{env, fs, process::ExitCode};

use cxf_audit::{scan_archive, zipslip_poc_archive, Severity};

fn print_usage() {
    eprintln!(
        "cxf-audit — CXF zip-slip PoC generator/scanner (research tool, xem README.md)\n\n\
         Usage:\n  \
         cxf-audit gen-poc <output.zip> [traversal-entry-name]\n  \
         cxf-audit scan <archive.zip>"
    );
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
            let Some(path) = args.get(2) else {
                print_usage();
                return ExitCode::FAILURE;
            };
            let bytes = match fs::read(path) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("Lỗi đọc file {path}: {e}");
                    return ExitCode::FAILURE;
                }
            };
            match scan_archive(&bytes) {
                Ok(findings) if findings.is_empty() => {
                    println!("Không phát hiện path traversal trong tên entry.");
                    ExitCode::SUCCESS
                }
                Ok(findings) => {
                    for f in &findings {
                        let tag = match f.severity {
                            Severity::Critical => "CRITICAL",
                            Severity::Info => "INFO",
                        };
                        println!("[{tag}] {} — {}", f.entry_name, f.message);
                    }
                    ExitCode::FAILURE
                }
                Err(e) => {
                    eprintln!("Lỗi đọc archive: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        _ => {
            print_usage();
            ExitCode::FAILURE
        }
    }
}
