# cxf-audit

Research tool đi kèm project [passkey-cxf-security](../../README.md), phục vụ
mục [threat-model.md §2.4](../../docs/threat-model.md) (zip-slip / path
traversal trong archive CXF).

## Vì sao cần tool này

CXF (Credential Exchange Format) đóng gói credential đã mã hoá thành các file
riêng trong 1 zip archive. Theo spec, với `FileCredential`:

> "The file's identifier, used as the file name in the zip archive."

Tên file trong zip lấy trực tiếp từ 1 field dữ liệu (`id`, kiểu `B64Url` —
"opaque byte sequence"). Spec không nói rõ importer phải sanitize giá trị này
thế nào trước khi ghi ra đĩa — đây là lớp bug kinh điển (zip-slip) nếu
implementer nào đó bỏ sót bước validate tên entry trước khi giải nén.

## Tool làm gì

- `gen-poc`: build 1 archive zip hợp lệ về mặt cấu trúc (nội dung bên trong
  là 1 `Header` CXF thật, dùng type từ crate chính thức
  `credential-exchange-format`), nhưng **tên entry chứa chuỗi path
  traversal** (`../../...`).
- `scan`: đọc 1 archive zip bất kỳ, liệt kê các entry có tên đáng ngờ (chứa
  `..`, đường dẫn tuyệt đối Unix/Windows, hoặc `\`) — không giải nén, an toàn
  để chạy trên input không tin cậy.

## Giới hạn — đọc trước khi dùng

- Nội dung bên trong archive PoC là **JSON dạng plaintext**, không phải JWE
  đã mã hoá HPKE thật như một export hợp lệ theo spec. Tool này chỉ nhắm vào
  **tầng giải nén archive**, không mô phỏng toàn bộ giao thức CXP.
- Kết quả `scan` chỉ nói lên "tên entry đáng ngờ" — **không** tự chứng minh
  1 importer cụ thể (Bitwarden, 1Password...) thực sự bị exploit. Muốn xác
  nhận cần thử `gen-poc` với 1 importer thật trong môi trường test/lab của
  bạn (xem [docs/research-log.md](../../docs/research-log.md) cho tình trạng
  hiện tại — phase test thực nghiệm trên thiết bị thật chưa chạy).
- Chỉ dùng trên hệ thống/tài khoản bạn được phép test. Không dùng để tấn
  công người dùng thật.

## Dùng thử (CLI)

```sh
cargo run -- gen-poc poc.zip                 # dùng entry name mặc định
cargo run -- gen-poc poc.zip "../../etc/foo" # tuỳ chỉnh entry name
cargo run -- scan poc.zip other.zip ...      # scan 1 hoặc nhiều file, exit code != 0 nếu có finding
```

## Test

```sh
cargo test
```

14 test, bao gồm cả trường hợp biên: archive rỗng, nhiều entry (chỉ entry
độc hại bị flag), Windows-style path không có ổ đĩa, input không phải zip
hợp lệ, và test khẳng định `zip` crate **không** tự sanitize tên entry khi
ghi (xác nhận thực nghiệm rằng nguy cơ zip-slip tồn tại thật ở tầng thư viện
archive, không chỉ là suy đoán từ đọc spec).

## Tích hợp vào project của bạn

3 cách, tuỳ vào bạn đang implement CXF/CXP (cần chặn archive độc hại lúc
runtime) hay chỉ muốn CI/pre-commit tự động soát các file test/fixture.

### 1. Làm thư viện Rust — chặn ngay trong code import của bạn (khuyến nghị nếu bạn tự viết importer)

```toml
# Cargo.toml của bạn — trỏ path/git đến crate này (chưa publish lên crates.io)
[dependencies]
cxf-audit = { path = "path/to/cxf-audit" }
```

```rust
// Trước khi giải nén archive nhận được từ Exporter:
cxf_audit::assert_safe_archive(&received_bytes)?; // Err nếu có entry đáng ngờ -> từ chối, không extract
```

`assert_safe_archive` trả `Result<(), GuardError>` — `GuardError::UnsafeEntries`
kèm danh sách finding chi tiết, `GuardError::InvalidArchive` nếu bytes không
phải zip hợp lệ. Đây là API dành riêng cho việc nhúng vào code thật (khác
`scan_archive`, vốn trả `Vec<Finding>` để tự xử lý/hiển thị).

### 2. Pre-commit hook — tự động soát file `.zip`/`.cxf` trước khi commit

Đã verify thật bằng `pre-commit try-repo` (không chỉ viết cho có — chạy thử
trên 1 file sạch + 1 file PoC độc hại, hook fail đúng file độc hại, bỏ qua
file sạch). Repo của bạn thêm vào `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: <url-repo-này-khi-đã-publish-lên-git>
    rev: <commit-hoặc-tag>
    hooks:
      - id: cxf-audit-zipslip
```

(`language: rust` trong `.pre-commit-hooks.yaml` khiến pre-commit tự
`cargo install` binary — không cần cài `cxf-audit` sẵn trên máy dev.)

### 3. CI (GitHub Actions) — ví dụ, chưa tự chạy thử trong CI thật

Chưa có pipeline CI thật để verify end-to-end, nên đây chỉ là snippet ví dụ
dựng từ các action chuẩn (`actions/checkout`, `dtolnay/rust-toolchain`) —
bạn nên tự thử trong repo của mình trước khi tin tưởng hoàn toàn:

```yaml
- uses: actions/checkout@v4
- uses: dtolnay/rust-toolchain@stable
- run: cargo install --path path/to/cxf-audit
- run: cxf-audit scan path/to/fixtures/*.zip
```
