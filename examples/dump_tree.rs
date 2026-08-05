//! Dev utility for writing new source_scan rules: prints the tree-sitter
//! S-expression for a snippet, so query node names can be verified against
//! the real grammar instead of guessed. Usage:
//!   cargo run --example dump_tree -- rust   < snippet.rs
//!   cargo run --example dump_tree -- kotlin < snippet.kt
//!   cargo run --example dump_tree -- swift  < snippet.swift

use std::io::Read;

fn main() {
    let lang = std::env::args()
        .nth(1)
        .expect("usage: dump_tree <rust|kotlin|swift>");
    let mut source = String::new();
    std::io::stdin().read_to_string(&mut source).unwrap();

    let language = match lang.as_str() {
        "rust" => tree_sitter_rust::language(),
        "kotlin" => tree_sitter_kotlin::language(),
        "swift" => tree_sitter_swift::language(),
        other => panic!("unknown language: {other}"),
    };

    let mut parser = tree_sitter::Parser::new();
    parser.set_language(language).unwrap();
    let tree = parser.parse(&source, None).unwrap();
    println!("{}", tree.root_node().to_sexp());
}
