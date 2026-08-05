# Contributing

Cảm ơn bạn quan tâm đến `cxf-audit`. Đây là tool nhỏ, phạm vi hẹp (audit
archive/protocol CXF/CXP) — issue/PR phù hợp nhất là:

- Rule mới cho 1 vấn đề cụ thể trong spec CXF/CXP (kèm tham chiếu tới đoạn
  spec liên quan).
- Sửa false positive/false negative ở rule hiện có, kèm test tái hiện.
- Cải thiện tích hợp (pre-commit hook, CI, ergonomics của API thư viện).

Không phải hướng phù hợp: rule cho 1 lớp lỗ hổng chung chung không gắn với
CXF/CXP cụ thể (SQL injection, XSS, secret leak tổng quát...) — đã cân nhắc
mở rộng thành scanner bảo mật tổng quát và **cố tình không đi hướng đó**
(xem README). Thêm ngôn ngữ mới cho `scan-source` thì được, miễn rule vẫn
nhắm đúng 1 pattern CXF/CXP-relevant cụ thể (v.d. zip-slip khi implement
importer) — không phải "thêm ngôn ngữ" là lý do để mở rộng phạm vi rule.

## Chạy thử local

```sh
cargo build --all-targets
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

Cả 4 lệnh trên đều chạy trong CI (`.github/workflows/ci.yml`) — PR phải xanh
cả 4 mới được merge.

## Thêm 1 rule mới — quét dữ liệu (archive/protocol)

Mỗi rule là 1 hàm trả `Vec<Finding>` (xem `src/archive.rs`, `src/limits.rs`,
`src/version.rs` làm ví dụ). Yêu cầu:

1. Trích dẫn đúng phần spec (CXF hoặc CXP) làm căn cứ cho rule — không thêm
   check dựa trên suy đoán/best-practice chung chung không liên quan CXF/CXP.
2. Test cả trường hợp dương tính lẫn "không được flag nhầm" (false positive)
   — xem `tests/zipslip.rs::does_not_flag_legitimate_nested_relative_path`
   làm ví dụ mẫu.
3. Nếu rule đủ quan trọng để chặn runtime (không chỉ báo cáo), thêm hàm
   `assert_*` tương ứng trong `src/guard.rs`.

## Thêm 1 rule mới — quét source code (`scan-source`)

Mỗi ngôn ngữ là 1 file trong `src/source_scan/` (`rust.rs`, `kotlin.rs`,
`swift.rs`), trả `Vec<SourceFinding>`, dùng tree-sitter.

- Không biết chắc tên node/field của grammar? Đừng đoán — dùng
  `cargo run --example dump_tree -- <rust|kotlin|swift> < snippet` để in
  S-expression thật rồi tra `node-types.json` của crate grammar tương ứng
  (đã làm vậy khi viết 3 rule hiện có, build pass ngay lần đầu nhờ đọc trước
  thay vì đoán).
- Grammar khác nhau về độ giàu field: Rust/Swift có field name (`function:`,
  `suffix:`...) nên dùng query khai báo (`Query`/`QueryCursor`) được; Kotlin
  không có field trên `call_expression` nên phải tự walk cây thủ công (xem
  `kotlin.rs` làm ví dụ) — đừng cố ép query khai báo nếu grammar không hỗ
  trợ, sẽ ra query sai mà không báo lỗi rõ ràng.
- Ghi rõ giới hạn heuristic của rule (false positive khi nào, false negative
  khi nào) — xem phần "Riêng scan-source" trong README làm mẫu cách viết.
- Thêm ngôn ngữ hoàn toàn mới: kiểm tra ràng buộc version `tree-sitter` của
  grammar crate mới có tương thích với 3 grammar hiện có không (xem comment
  trong `Cargo.toml` — tất cả đang pin về `0.20.x` vì đó là dải chung duy
  nhất giữa rust/kotlin/swift ở thời điểm viết). Nếu không tương thích, cần
  đánh giá lại có đáng downgrade/tách hay không trước khi thêm.

## Thêm 1 rule mới — taint analysis thật (`semgrep/`)

`semgrep/zip-slip-taint.yaml` dùng Semgrep taint mode thật (không phải
pattern-matching cú pháp như `scan-source`) — xem
[semgrep/README.md](semgrep/README.md) để biết vì sao chọn Semgrep thay vì
CodeQL (đã thử, thất bại vì giới hạn resolve trait method của CodeQL Rust,
không phải lỗi có thể vá từ bên ngoài) và kỹ thuật `by-side-effect` +
`focus-metavariable` cần dùng cho sanitizer dạng guard clause (`if bad(x) { return }`)
— cách viết sanitizer "ngây thơ" trông hợp lý nhưng **không hoạt động**, đã
verify bằng thực nghiệm.

Thêm rule mới ở đây: viết rule + fixture có comment `// ruleid: <id>` (dòng
phải bị flag) và `// ok: <id>` (dòng không được flag) trong
`semgrep/fixtures/`, thêm dòng `check` tương ứng vào `semgrep/verify.sh`
(không dùng `semgrep --test` — xem lý do trong semgrep/README.md).

## Báo cáo lỗ hổng thật tìm được bằng tool này

Nếu bạn dùng `cxf-audit` và phát hiện 1 lỗ hổng **thật** ở 1 implementation
CXF/CXP cụ thể (Bitwarden, 1Password, Apple Passwords...) — đây **không**
phải nơi để báo cáo. Đừng mở public issue kèm PoC hoạt động được nhắm vào
1 vendor cụ thể. Hãy báo qua chương trình bug bounty/security contact chính
thức của vendor đó trước (HackerOne, security@..., v.v.), theo thông lệ
responsible disclosure.

Issue/PR ở đây chỉ nên bàn về bản thân tool `cxf-audit` (rule, false
positive, tích hợp) — không phải nơi thảo luận chi tiết khai thác nhắm vào
1 sản phẩm cụ thể.
