use std::{
    fs,
    io::{self, BufRead, Write},
    path::{Path, PathBuf},
    process::ExitCode,
};

use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::{generate, Shell};
use cxf_audit::{scan_archive, scan_source, to_sarif, zipslip_poc_archive, Severity};

const DEFAULT_POC_ENTRY_NAME: &str = "../../../../tmp/cxf-audit-poc-marker";

#[derive(Parser)]
#[command(
    name = "cxf-audit",
    version,
    about = "CXF/CXP zip-slip + source-code scanner (research tool, xem README.md)"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Tạo archive PoC zip có path traversal trong tên entry
    GenPoc {
        /// File zip sẽ tạo
        out_path: PathBuf,
        /// Tên entry (mặc định: path traversal marker)
        entry_name: Option<String>,
    },
    /// Quét archive zip tìm path traversal trong tên entry
    Scan {
        /// 1 hoặc nhiều file archive
        #[arg(required = true)]
        archives: Vec<PathBuf>,
    },
    /// Quét source code (Rust/Kotlin/Swift) tìm pattern zip-slip
    ScanSource {
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
        /// 1 hoặc nhiều file/thư mục (đệ quy)
        #[arg(required = true)]
        paths: Vec<PathBuf>,
    },
    /// In shell completion script (bash/zsh/fish/...) ra stdout
    Completions { shell: Shell },
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    Text,
    Sarif,
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

/// Scans one archive, writing findings to `out`. Returns `Ok(true)` if the
/// file is clean. Shared between the `scan` subcommand and the interactive
/// menu so both go through identical logic.
fn scan_one_archive(path: &Path, out: &mut impl Write) -> io::Result<bool> {
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            writeln!(out, "Lỗi đọc file {}: {e}", path.display())?;
            return Ok(false);
        }
    };
    match scan_archive(&bytes) {
        Ok(findings) if findings.is_empty() => Ok(true),
        Ok(findings) => {
            for f in &findings {
                let tag = match f.severity {
                    Severity::Critical => "CRITICAL",
                    Severity::Info => "INFO",
                };
                writeln!(
                    out,
                    "{}: [{tag}] {} — {}",
                    path.display(),
                    f.entry_name,
                    f.message
                )?;
            }
            Ok(false)
        }
        Err(e) => {
            writeln!(out, "Lỗi đọc archive {}: {e}", path.display())?;
            Ok(false)
        }
    }
}

/// Runs the source-code scan and writes results (text or SARIF) to `out`.
/// Returns `Ok(true)` if nothing was flagged. Shared between the
/// `scan-source` subcommand and the interactive menu.
fn run_scan_source(
    paths: &[PathBuf],
    format: OutputFormat,
    out: &mut impl Write,
) -> io::Result<bool> {
    let mut files = Vec::new();
    for root in paths {
        collect_files(root, &mut files);
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
    if format == OutputFormat::Sarif {
        let sarif = to_sarif(&all_findings);
        writeln!(out, "{}", serde_json::to_string_pretty(&sarif).unwrap())?;
    } else {
        for f in &all_findings {
            let tag = match f.severity {
                Severity::Critical => "CRITICAL",
                Severity::Info => "INFO",
            };
            writeln!(out, "{}:{}: [{tag}] {}", f.file, f.line, f.message)?;
        }
        if !any_findings {
            writeln!(
                out,
                "Không phát hiện pattern đáng ngờ trong source đã quét."
            )?;
        }
    }
    Ok(!any_findings)
}

/// Generates a zip-slip PoC archive, writing status to `out`. Returns
/// `Ok(true)` on success. Shared between the `gen-poc` subcommand and the
/// interactive menu.
fn run_gen_poc(out_path: &Path, entry_name: &str, out: &mut impl Write) -> io::Result<bool> {
    match zipslip_poc_archive(entry_name) {
        Ok(bytes) => {
            if let Err(e) = fs::write(out_path, bytes) {
                writeln!(out, "Lỗi ghi file {}: {e}", out_path.display())?;
                return Ok(false);
            }
            writeln!(
                out,
                "Đã tạo {} (entry name: {entry_name})",
                out_path.display()
            )?;
            Ok(true)
        }
        Err(e) => {
            writeln!(out, "Lỗi tạo archive: {e}")?;
            Ok(false)
        }
    }
}

/// Writes `text`, flushes, then reads one line from `input`. Returns
/// `Ok(None)` on EOF (e.g. piped stdin ran out, or the user's terminal
/// closed) so callers can exit cleanly instead of looping forever.
fn prompt<R: BufRead, W: Write>(
    text: &str,
    input: &mut R,
    out: &mut W,
) -> io::Result<Option<String>> {
    write!(out, "{text}")?;
    out.flush()?;
    let mut line = String::new();
    if input.read_line(&mut line)? == 0 {
        return Ok(None);
    }
    Ok(Some(line.trim().to_string()))
}

/// One entry the file/directory browser can present, plus what selecting
/// it does. Kept separate from its display label so `browse()` never has
/// to re-parse text to figure out what the user picked.
#[derive(Clone)]
enum BrowseChoice {
    Up(PathBuf),
    SelectCurrentDir,
    Descend(PathBuf),
    PickFile(PathBuf),
}

/// Lists one screen's worth of browser entries for `current`: ".." (if not
/// at a filesystem root), "select this directory" (only when
/// `allow_dir_selection`), then subdirectories and files, alphabetically.
/// Unreadable directories (permissions) just show as empty rather than
/// erroring the whole browse session.
fn list_browse_entries(current: &Path, allow_dir_selection: bool) -> Vec<(String, BrowseChoice)> {
    let mut items = Vec::new();
    if let Some(parent) = current.parent() {
        items.push((
            ".. (lên thư mục cha)".to_string(),
            BrowseChoice::Up(parent.to_path_buf()),
        ));
    }
    if allow_dir_selection {
        items.push((
            format!("✅ Chọn thư mục này ({})", current.display()),
            BrowseChoice::SelectCurrentDir,
        ));
    }
    let mut entries: Vec<_> = fs::read_dir(current)
        .map(|r| r.flatten().collect())
        .unwrap_or_default();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if is_pruned_dir(&path) {
            continue; // same noise list as scan-source's own recursion
        }
        if path.is_dir() {
            items.push((format!("📁 {name}/"), BrowseChoice::Descend(path)));
        } else {
            items.push((format!("   {name}"), BrowseChoice::PickFile(path)));
        }
    }
    items
}

/// Numbered file/directory browser: prints `current`'s contents, reads a
/// number choice, and either descends/ascends or returns the picked path.
/// `allow_dir_selection` controls whether there's a "select this
/// directory" option (needed for `scan-source`, which accepts a directory;
/// not offered for `scan`, which needs a specific archive file). Returns
/// `Ok(None)` on EOF or an explicit cancel ("0").
fn browse<R: BufRead, W: Write>(
    start: &Path,
    allow_dir_selection: bool,
    input: &mut R,
    out: &mut W,
) -> io::Result<Option<PathBuf>> {
    let mut current = start.to_path_buf();
    loop {
        let items = list_browse_entries(&current, allow_dir_selection);
        writeln!(out)?;
        writeln!(out, "📂 {}", current.display())?;
        for (i, (label, _)) in items.iter().enumerate() {
            writeln!(out, "  {}) {label}", i + 1)?;
        }
        writeln!(out, "  0) Huỷ, quay lại menu chính")?;

        let Some(choice) = prompt("> ", input, out)? else {
            return Ok(None);
        };
        if choice == "0" {
            return Ok(None);
        }
        let Ok(idx) = choice.parse::<usize>() else {
            writeln!(out, "Không hợp lệ, nhập số trong danh sách.")?;
            continue;
        };
        let Some((_, action)) = idx.checked_sub(1).and_then(|i| items.get(i)) else {
            writeln!(out, "Không hợp lệ, nhập số trong danh sách.")?;
            continue;
        };
        match action.clone() {
            BrowseChoice::Up(p) | BrowseChoice::Descend(p) => current = p,
            BrowseChoice::SelectCurrentDir => return Ok(Some(current)),
            BrowseChoice::PickFile(p) => return Ok(Some(p)),
        }
    }
}

/// Interactive menu for `cxf-audit` run with no subcommand — guides a user
/// through the same operations the flag-based subcommands offer via
/// numbered choices, including a file/directory browser instead of typing
/// full paths by hand. Generic over input/output so tests can drive it
/// with a scripted `Cursor<&[u8]>` instead of real stdin/stdout, and takes
/// an explicit `start_dir` (rather than reading `env::current_dir()`
/// itself) so tests can point the browser at a controlled temp directory.
fn run_interactive_menu<R: BufRead, W: Write>(
    mut input: R,
    out: &mut W,
    start_dir: &Path,
) -> io::Result<ExitCode> {
    loop {
        writeln!(out)?;
        writeln!(out, "cxf-audit — chọn 1 việc:")?;
        writeln!(out, "  1) Scan archive zip tìm path traversal")?;
        writeln!(out, "  2) Scan source code (Rust/Kotlin/Swift)")?;
        writeln!(out, "  3) Tạo archive PoC zip-slip")?;
        writeln!(out, "  q) Thoát")?;

        let Some(choice) = prompt("> ", &mut input, out)? else {
            return Ok(ExitCode::SUCCESS);
        };

        match choice.as_str() {
            "1" => {
                let Some(path) = browse(start_dir, false, &mut input, out)? else {
                    continue;
                };
                if scan_one_archive(&path, out)? {
                    writeln!(out, "OK: không phát hiện path traversal.")?;
                }
            }
            "2" => {
                let Some(path) = browse(start_dir, true, &mut input, out)? else {
                    continue;
                };
                let Some(format_str) =
                    prompt("Format [text/sarif] (Enter = text): ", &mut input, out)?
                else {
                    return Ok(ExitCode::SUCCESS);
                };
                let format = if format_str == "sarif" {
                    OutputFormat::Sarif
                } else {
                    OutputFormat::Text
                };
                run_scan_source(&[path], format, out)?;
            }
            "3" => {
                let Some(dir) = browse(start_dir, true, &mut input, out)? else {
                    continue;
                };
                let Some(filename) = prompt("Tên file zip (v.d. poc.zip): ", &mut input, out)?
                else {
                    return Ok(ExitCode::SUCCESS);
                };
                if filename.is_empty() {
                    continue;
                }
                let Some(entry_name_input) =
                    prompt("Entry name (Enter = mặc định): ", &mut input, out)?
                else {
                    return Ok(ExitCode::SUCCESS);
                };
                let entry_name = if entry_name_input.is_empty() {
                    DEFAULT_POC_ENTRY_NAME.to_string()
                } else {
                    entry_name_input
                };
                run_gen_poc(&dir.join(filename), &entry_name, out)?;
            }
            "q" | "quit" | "exit" => return Ok(ExitCode::SUCCESS),
            "" => {}
            other => writeln!(out, "Không hiểu lựa chọn '{other}', thử lại.")?,
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let mut stdout = io::stdout();

    match cli.command {
        Some(Command::GenPoc {
            out_path,
            entry_name,
        }) => {
            let entry_name = entry_name.unwrap_or_else(|| DEFAULT_POC_ENTRY_NAME.to_string());
            match run_gen_poc(&out_path, &entry_name, &mut stdout) {
                Ok(true) => ExitCode::SUCCESS,
                _ => ExitCode::FAILURE,
            }
        }
        Some(Command::Scan { archives }) => {
            let mut all_clean = true;
            for path in &archives {
                match scan_one_archive(path, &mut stdout) {
                    Ok(clean) => all_clean &= clean,
                    Err(_) => all_clean = false,
                }
            }
            if all_clean {
                let _ = writeln!(stdout, "Không phát hiện path traversal trong tên entry.");
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Some(Command::ScanSource { format, paths }) => {
            match run_scan_source(&paths, format, &mut stdout) {
                Ok(true) => ExitCode::SUCCESS,
                _ => ExitCode::FAILURE,
            }
        }
        Some(Command::Completions { shell }) => {
            let mut cmd = Cli::command();
            let name = cmd.get_name().to_string();
            generate(shell, &mut cmd, name, &mut stdout);
            ExitCode::SUCCESS
        }
        None => {
            let stdin = io::stdin();
            let start_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            run_interactive_menu(stdin.lock(), &mut stdout, &start_dir).unwrap_or(ExitCode::FAILURE)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::Cursor,
        sync::atomic::{AtomicU32, Ordering},
    };

    /// Unique temp dir per test — avoids collisions when tests run in
    /// parallel (the default for `cargo test`).
    fn temp_dir(label: &str) -> PathBuf {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = env_temp_dir().join(format!("cxf-audit-test-{label}-{n}-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn env_temp_dir() -> PathBuf {
        std::env::temp_dir()
    }

    #[test]
    fn cli_parses_all_subcommands_without_panicking() {
        // A regression check for the clap migration itself: every
        // subcommand shape used elsewhere in this repo (pre-commit hooks,
        // CI, README examples) must still parse.
        Cli::try_parse_from(["cxf-audit", "gen-poc", "out.zip"]).unwrap();
        Cli::try_parse_from(["cxf-audit", "gen-poc", "out.zip", "../evil"]).unwrap();
        Cli::try_parse_from(["cxf-audit", "scan", "a.zip", "b.zip"]).unwrap();
        Cli::try_parse_from(["cxf-audit", "scan-source", "src/"]).unwrap();
        Cli::try_parse_from(["cxf-audit", "scan-source", "--format", "sarif", "src/"]).unwrap();
        Cli::try_parse_from(["cxf-audit", "completions", "bash"]).unwrap();
    }

    #[test]
    fn cli_rejects_scan_source_with_no_paths() {
        assert!(Cli::try_parse_from(["cxf-audit", "scan-source"]).is_err());
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

    #[test]
    fn interactive_menu_quit_immediately_exits_cleanly() {
        let input = Cursor::new(b"q\n".to_vec());
        let mut out = Vec::new();
        let code = run_interactive_menu(input, &mut out, Path::new(".")).unwrap();
        assert_eq!(code, ExitCode::SUCCESS);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("chọn 1 việc"));
    }

    #[test]
    fn interactive_menu_exits_cleanly_on_eof_instead_of_looping_forever() {
        let input = Cursor::new(Vec::new()); // immediate EOF, no "q" needed
        let mut out = Vec::new();
        let code = run_interactive_menu(input, &mut out, Path::new(".")).unwrap();
        assert_eq!(code, ExitCode::SUCCESS);
    }

    #[test]
    fn interactive_menu_unknown_choice_reprompts_instead_of_exiting() {
        let input = Cursor::new(b"nonsense\nq\n".to_vec());
        let mut out = Vec::new();
        let code = run_interactive_menu(input, &mut out, Path::new(".")).unwrap();
        assert_eq!(code, ExitCode::SUCCESS);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("Không hiểu lựa chọn"));
    }

    #[test]
    fn browse_lists_up_and_dir_selection_before_entries_alphabetically() {
        let dir = temp_dir("browse-list");
        fs::write(dir.join("b.rs"), "").unwrap();
        fs::write(dir.join("a.rs"), "").unwrap();
        fs::create_dir_all(dir.join("z_subdir")).unwrap();

        let entries = list_browse_entries(&dir, true);
        let labels: Vec<&str> = entries.iter().map(|(l, _)| l.as_str()).collect();

        assert_eq!(labels[0], ".. (lên thư mục cha)");
        assert!(labels[1].starts_with("✅ Chọn thư mục này"));
        // a.rs before b.rs before z_subdir/ — read_dir sorted by file name.
        assert!(labels[2].contains("a.rs"));
        assert!(labels[3].contains("b.rs"));
        assert!(labels[4].contains("z_subdir"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn browse_without_dir_selection_omits_that_option() {
        let dir = temp_dir("browse-nodirselect");
        let entries = list_browse_entries(&dir, false);
        assert!(!entries.iter().any(|(l, _)| l.starts_with("✅")));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn browse_prunes_noise_directories_like_scan_source_does() {
        let dir = temp_dir("browse-prune");
        fs::create_dir_all(dir.join("target")).unwrap();
        fs::write(dir.join("real.rs"), "").unwrap();

        let entries = list_browse_entries(&dir, false);
        assert!(!entries.iter().any(|(l, _)| l.contains("target")));
        assert!(entries.iter().any(|(l, _)| l.contains("real.rs")));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn browse_selects_current_dir_via_numbered_choice() {
        let dir = temp_dir("browse-select");
        // ".. " is item 1 (parent always exists under a temp dir), "✅
        // Chọn thư mục này" is item 2 since the dir starts empty.
        let mut input = Cursor::new(b"2\n".to_vec());
        let mut out = Vec::new();
        let picked = browse(&dir, true, &mut input, &mut out).unwrap().unwrap();
        assert_eq!(picked, dir);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn browse_descends_into_subdirectory_then_picks_a_file() {
        let dir = temp_dir("browse-descend");
        let subdir = dir.join("sub");
        fs::create_dir_all(&subdir).unwrap();
        fs::write(subdir.join("target.rs"), "").unwrap();
        // No dir-selection offered, so with an empty top-level dir except
        // "sub/": item 1 = "..", item 2 = "sub/". Descend (2), then in
        // "sub/" item 1 = "..", item 2 = "target.rs" — pick it (2).
        let mut input = Cursor::new(b"2\n2\n".to_vec());
        let mut out = Vec::new();
        let picked = browse(&dir, false, &mut input, &mut out).unwrap().unwrap();
        assert_eq!(picked, subdir.join("target.rs"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn browse_cancel_returns_none_and_invalid_choice_reprompts() {
        let dir = temp_dir("browse-cancel");
        let mut input = Cursor::new(b"not-a-number\n0\n".to_vec());
        let mut out = Vec::new();
        let picked = browse(&dir, true, &mut input, &mut out).unwrap();
        assert!(picked.is_none());
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("Không hợp lệ"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn interactive_menu_gen_poc_flow_creates_real_archive_via_browser() {
        let dir = temp_dir("menu-genpoc");
        // "3" (gen-poc) -> browse: "2" (✅ select this empty dir, item 2
        // after ".."), -> filename -> entry name (default) -> "q".
        let script = "3\n2\npoc.zip\n\nq\n";
        let input = Cursor::new(script.as_bytes().to_vec());
        let mut out = Vec::new();

        let code = run_interactive_menu(input, &mut out, &dir).unwrap();

        assert_eq!(code, ExitCode::SUCCESS);
        let out_path = dir.join("poc.zip");
        assert!(
            out_path.exists(),
            "gen-poc menu flow did not create the archive"
        );
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains(DEFAULT_POC_ENTRY_NAME));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn interactive_menu_scan_source_flow_finds_real_finding_via_browser() {
        let dir = temp_dir("menu-scansource");
        fs::write(
            dir.join("vuln.rs"),
            "fn f(a: &mut zip::ZipArchive<std::fs::File>) { a.by_index(0).unwrap(); }",
        )
        .unwrap();
        // "2" (scan-source) -> browse: ".." is item 1, "✅ select dir" is
        // item 2, "vuln.rs" is item 3 (only file, alphabetically first) ->
        // pick the file directly -> format (default) -> "q".
        let script = "2\n3\n\nq\n";
        let input = Cursor::new(script.as_bytes().to_vec());
        let mut out = Vec::new();

        let code = run_interactive_menu(input, &mut out, &dir).unwrap();

        assert_eq!(code, ExitCode::SUCCESS);
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains("by_index"),
            "expected the real finding in menu output: {text}"
        );
        fs::remove_dir_all(&dir).unwrap();
    }
}
