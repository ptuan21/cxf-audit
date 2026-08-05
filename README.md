# cxf-audit

[![Crates.io](https://img.shields.io/crates/v/cxf-audit.svg)](https://crates.io/crates/cxf-audit)
[![CI](https://github.com/ptuan21/cxf-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/ptuan21/cxf-audit/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**[ptuan21.github.io/cxf-audit](https://ptuan21.github.io/cxf-audit/)**

Scanner cho lỗ hổng trong implementation CXF/CXP (Credential Exchange
Format/Protocol) — chuẩn FIDO Alliance cho phép di chuyển passkey/password
giữa các trình quản lý mật khẩu (Apple, Google, 1Password, Bitwarden,
Dashlane...). Quét cả 2 tầng:

- **Dữ liệu**: archive CXF thật (zip-slip, zip-bomb) và protocol response
  (version downgrade).
- **Source code** của dev tự implement CXF/CXP (Rust, Kotlin, Swift) — 2 lớp:
  - `scan-source` (tree-sitter, syntactic): nhanh, không phụ thuộc gì thêm.
  - [`semgrep/`](semgrep/) (Semgrep, **taint analysis thật**): theo dõi dữ
    liệu xuyên biến/hàm, hiểu đúng guard clause — mạnh hơn `scan-source`
    nhưng cần cài `semgrep`. Xem [semgrep/README.md](semgrep/README.md) cho
    hành trình thử CodeQL trước (thất bại, lý do cụ thể) rồi mới ra được
    Semgrep.

Tách ra từ 1 project nghiên cứu bảo mật passkey-sync độc lập rộng hơn (threat
model đầy đủ, các hướng khác đang điều tra) — project đó hiện chưa publish
nên chưa có link công khai.

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
- `check_resource_limits` (thư viện): flag archive có số entry hoặc tổng
  kích thước giải nén *khai báo* vượt ngưỡng — check tĩnh cho zip bomb, đọc
  metadata central-directory, không giải nén thật.
- `check_version_downgrade` (thư viện): flag khi `ExportResponse.version`
  thấp hơn `ExportRequest.version` — CXP cho phép Importer "MAY refuse"
  downgrade này nhưng không bắt buộc, nên phần lớn implementation sẽ âm
  thầm chấp nhận nếu không tự thêm check.
- `scan-source` / `scan_source()` (thư viện): quét **source code** bạn tự
  viết (không phải archive) tìm pattern zip-slip kinh điển, dùng tree-sitter
  để hiểu cú pháp thật (không match nhầm trong comment/string như regex
  thô):
  - **Rust**: gọi `.by_index(`/`.by_name(` trực tiếp trên `ZipArchive` — API
    thô, severity hạ xuống Info nếu file có tham chiếu `cxf_audit`, lọc
    `Component::Normal` (kỹ thuật sanitize path chuẩn — xác nhận từ code
    thật, không suy đoán: `georust/transitfeed` dùng đúng pattern này và
    an toàn thật), hoặc check `.contains("..")` (heuristic cùng-file, không
    phải phân tích luồng dữ liệu thật). Cùng lúc, nếu file
    có gọi `by_index`/`by_name` mà không thấy tham chiếu
    `assert_within_limits`/`check_resource_limits`/`ZipLimits` ở đâu, thêm
    1 finding riêng cảnh báo thiếu check zip-bomb (§2.4). Ngoài ra flag việc
    dựng `HpkeMode::Base`/`HpkeMode::Psk` — không xác thực người gửi ở tầng
    KEM (RFC 9180), an toàn phụ thuộc hoàn toàn vào chữ ký challenge riêng
    (§2.3 threat model).
  - **Kotlin**: `File(dir, entry.name)` / `File(dir, entry.entryName)` —
    antipattern zip-slip kinh điển trong tài liệu OWASP. Hạ severity nếu
    file có check containment kiểu `canonicalPath`/`canonicalFile` +
    `startsWith` (xác nhận cả 2 biến thể từ 2 codebase Kotlin thật độc lập).
  - **Swift**: gọi `.extract(` (kiểu ZIPFoundation `Archive.extract`). Hạ
    severity nếu file có `isContained(in:` — chính API containment-check
    ZIPFoundation dùng nội bộ trong `unzipItem()` của họ.
  - `--format sarif`: xuất SARIF 2.1.0 thay vì text — nạp thẳng vào tab
    Security của GitHub qua `github/codeql-action/upload-sarif`, xem mục
    Tích hợp bên dưới.
- [`semgrep/zip-slip-taint.yaml`](semgrep/): cùng 3 pattern trên nhưng bằng
  **taint analysis thật** (Semgrep) — track dữ liệu xuyên biến/method chain,
  không báo nhầm code đã có guard clause đúng (`if name.contains("..") { continue }`).
  Yêu cầu cài `semgrep` riêng, không phải 1 phần của binary `cxf-audit`.
- Chạy `cxf-audit` không kèm subcommand → **menu tương tác**, khỏi cần nhớ
  flag nào. `cxf-audit completions <bash|zsh|fish|...>` → in tab-completion
  script cho shell.

## Giới hạn — đọc trước khi dùng

- Nội dung bên trong archive PoC là **JSON dạng plaintext**, không phải JWE
  đã mã hoá HPKE thật như một export hợp lệ theo spec. Tool này chỉ nhắm vào
  **tầng giải nén archive**, không mô phỏng toàn bộ giao thức CXP.
- Kết quả `scan` chỉ nói lên "tên entry đáng ngờ" — **không** tự chứng minh
  1 importer cụ thể (Bitwarden, 1Password...) thực sự bị exploit. Muốn xác
  nhận cần thử `gen-poc` với 1 importer thật trong môi trường test/lab của
  bạn — phase test thực nghiệm trên thiết bị thật chưa chạy.
- Chỉ dùng trên hệ thống/tài khoản bạn được phép test. Không dùng để tấn
  công người dùng thật.

**Riêng `scan-source`:** đây là **pattern matching theo cú pháp, không phải
data-flow/taint analysis thật**. Cụ thể:
- Rule chỉ nhìn *tên hàm được gọi* (Rust: `by_index`/`by_name`; Swift:
  `extract`) — **không kiểm tra kiểu của receiver**, nên 1 hàm tên trùng
  ngẫu nhiên trên type khác (không liên quan zip) cũng bị flag (false
  positive).
- Rule Kotlin check "argument có chứa `.name`" bằng so khớp text trong span
  của lời gọi `File(...)` — không phải phân tích xem biến đó thực sự đến từ
  đâu, nên `File(dir, someOtherThing.name)` không liên quan zip vẫn có thể
  bị flag.
- Heuristic "hạ severity nếu file có `cxf_audit`" (rule Rust) chỉ xét *toàn
  file*, không xét scope/thứ tự gọi trước-sau — gọi guard ở 1 hàm khác trong
  cùng file vẫn hạ severity dù hàm chứa `by_index` không hề được guard.
- Không có rule nào track được lời gọi qua nhiều file/hàm (cross-function).
- **Không phân biệt "đọc để kiểm tra" với "đọc để ghi ra đĩa".** Ví dụ thật,
  không phải giả định: `cxf-audit scan-source src/` tự flag chính
  `src/archive.rs` (nơi `scan_archive()` gọi `by_index()` để *đọc tên entry
  và kiểm tra*, không hề ghi file nào ra đĩa) — vì rule chỉ nhìn thấy lời
  gọi `by_index`, không biết giá trị trả về có bao giờ chạm tới
  `File::create`/tương đương hay không. Đây chính xác là giới hạn mà lớp
  taint analysis (`semgrep/`) giải quyết được còn `scan-source` thì không.

Coi kết quả `scan-source` là **gợi ý cần xem lại bằng mắt**, không phải kết
luận cuối cùng.

## Dùng thử (CLI)

CLI dùng [clap](https://crates.io/crates/clap) — có sẵn `--help`/`--version`,
error message chuẩn khi thiếu argument.

```sh
cargo run -- gen-poc poc.zip                 # dùng entry name mặc định
cargo run -- gen-poc poc.zip "../../etc/foo" # tuỳ chỉnh entry name
cargo run -- scan poc.zip other.zip ...      # scan archive, exit code != 0 nếu có finding
cargo run -- scan-source src/ Importer.kt    # scan source code (file hoặc thư mục, đệ quy)
cargo run -- --help                          # xem tất cả subcommand
```

**Không nhớ subcommand nào, hoặc không muốn tự gõ đường dẫn?** Chạy
`cxf-audit` không kèm gì — vào menu tương tác, chọn số. Chọn scan archive
hoặc scan source sẽ mở **trình duyệt file/thư mục ngay trong terminal**
(cũng chọn bằng số, không cần gõ path tay) — đã verify thật qua terminal
thật, không chỉ test giả lập:

```
$ cxf-audit

cxf-audit — chọn 1 việc:
  1) Scan archive zip tìm path traversal
  2) Scan source code (Rust/Kotlin/Swift)
  3) Tạo archive PoC zip-slip
  q) Thoát
> 2

Thư mục: /Users/you/my-project
  1) ..
  2) [chọn thư mục này]
  3) src/
  4) Cargo.toml
  0) Huỷ, quay lại menu chính
>
```

Điều hướng bằng số: gõ số thư mục để đi vào, `1` để lùi lại thư mục cha,
hoặc chọn `[chọn thư mục này]` để quét cả thư mục hiện tại (scan-source
chấp nhận cả file lẫn thư mục). `scan` archive dùng cùng trình duyệt nhưng
không có tuỳ chọn "chọn thư mục" — phải chọn tới 1 file cụ thể vì archive
luôn là 1 file.

**Dùng CLI thường xuyên?** Bật tab-completion cho shell:

```sh
cxf-audit completions bash > /etc/bash_completion.d/cxf-audit   # hoặc
cxf-audit completions zsh  > "${fpath[1]}/_cxf-audit"            # hoặc
cxf-audit completions fish > ~/.config/fish/completions/cxf-audit.fish
```

## Test

```sh
cargo test
```

64 test, bao gồm cả trường hợp biên: archive rỗng, nhiều entry (chỉ entry
độc hại bị flag), Windows-style path không có ổ đĩa, input không phải zip
hợp lệ, test khẳng định `zip` crate **không** tự sanitize tên entry khi ghi
(xác nhận thực nghiệm rằng nguy cơ zip-slip tồn tại thật ở tầng thư viện
archive, không chỉ là suy đoán từ đọc spec), test cho zip-bomb limits và
version-downgrade, 17 test cho `scan-source` (dương tính + âm tính, cả 3
ngôn ngữ + HPKE mode + zip-bomb-in-source + guard marker verify trên code
thật từ 3 repo ngoài — georust/transitfeed, blockads-android, Modern-Apps,
ZIPFoundation), 5 test cho output SARIF (schema hợp lệ, rule dedup, level
mapping), cộng 18 test cho CLI: parse mọi subcommand, `collect_files` bỏ
qua thư mục noise/không theo symlink cycle, và 12 test cho menu tương tác +
trình duyệt file/thư mục — kể cả các luồng chạy trọn vẹn qua
`std::io::Cursor` giả lập stdin (điều hướng thư mục, tạo file/tìm finding
thật, không chỉ mock riêng lẻ từng hàm).

## Tích hợp vào project của bạn

3 cách, tuỳ vào bạn đang implement CXF/CXP (cần chặn archive độc hại lúc
runtime) hay chỉ muốn CI/pre-commit tự động soát các file test/fixture.

### 1. Làm thư viện Rust — chặn ngay trong code import của bạn (khuyến nghị nếu bạn tự viết importer)

Đã publish lên crates.io — [crates.io/crates/cxf-audit](https://crates.io/crates/cxf-audit):

```sh
cargo add cxf-audit
```

Hoặc trỏ thẳng git nếu muốn bản mới nhất chưa release:

```toml
[dependencies]
cxf-audit = { git = "https://github.com/ptuan21/cxf-audit" }
```

```rust
// Trước khi giải nén archive nhận được từ Exporter:
cxf_audit::assert_safe_archive(&received_bytes)?; // Err nếu có entry đáng ngờ -> từ chối, không extract
```

`assert_safe_archive` trả `Result<(), GuardError>` — `GuardError::UnsafeEntries`
kèm danh sách finding chi tiết, `GuardError::InvalidArchive` nếu bytes không
phải zip hợp lệ. Đây là API dành riêng cho việc nhúng vào code thật (khác
`scan_archive`, vốn trả `Vec<Finding>` để tự xử lý/hiển thị).

Tương tự có `assert_within_limits(&bytes, &ZipLimits::default())` cho check
zip-bomb, và `check_version_downgrade(requested, responded)` (nhận thẳng
`cxf_audit::Version`, re-export từ `credential_exchange_protocol`) để tự gọi
sau khi nhận `ExportResponse` — 2 hàm này không tự động chạy trong
`assert_safe_archive`, gọi riêng vì ngưỡng zip-bomb tuỳ ứng dụng và version
downgrade không thuộc về archive.

### 2. Pre-commit hook — tự động soát trước khi commit

2 hook, cả hai đã verify thật bằng `pre-commit try-repo` (chạy thử trên file
sạch + file có lỗi, hook fail đúng file lỗi, bỏ qua file sạch — không chỉ
viết cho có):

```yaml
repos:
  - repo: https://github.com/ptuan21/cxf-audit
    rev: <commit-hoặc-tag-mới-nhất> # đừng dùng branch động
    hooks:
      - id: cxf-audit-zipslip       # soát file .zip/.cxf
      - id: cxf-audit-source-scan   # soát file .rs/.kt/.kts/.swift
```

(`language: rust` trong `.pre-commit-hooks.yaml` khiến pre-commit tự
`cargo install` binary — không cần cài `cxf-audit` sẵn trên máy dev.)

**Muốn taint analysis thật (không chỉ syntactic) thay vì `cxf-audit-source-scan`?**
Dùng hook chính thức của Semgrep, trỏ tới rule trong repo này — cũng đã
verify bằng `pre-commit run` thật:

```yaml
  - repo: https://github.com/semgrep/semgrep
    rev: v1.172.0
    hooks:
      - id: semgrep
        args: ["--config", "https://raw.githubusercontent.com/ptuan21/cxf-audit/main/semgrep/zip-slip-taint.yaml", "--error"]
```

Xem [semgrep/README.md](semgrep/README.md) để biết vì sao có cả 2 lớp
(syntactic + taint) thay vì chỉ 1.

### 3. CI (GitHub Actions)

Repo này có sẵn `.github/workflows/ci.yml` (fmt + build + clippy -D warnings
+ test) — đã verify **thật** trên runner GitHub Actions (không chỉ
`actionlint`/chạy local): [xanh toàn bộ 4 bước](https://github.com/ptuan21/cxf-audit/actions).

Nếu bạn dùng `cxf-audit` như dependency trong project khác (không phải fork
repo này), thêm vào workflow của bạn:

```yaml
- uses: actions/checkout@v4
- uses: dtolnay/rust-toolchain@stable
- run: cargo install --path path/to/cxf-audit
- run: cxf-audit scan path/to/fixtures/*.zip
```

### 4. GitHub Code Scanning (SARIF)

`scan-source --format sarif` xuất SARIF 2.1.0 — nạp thẳng vào tab Security
của GitHub, hiện inline trên PR, thay vì chỉ nằm trong log CI. Đã verify
thật bằng workflow riêng
([`.github/workflows/demo-sarif.yml`](.github/workflows/demo-sarif.yml),
chạy tay qua `workflow_dispatch`) — quét `semgrep/fixtures/` (có finding đã
biết trước) và xác nhận alert thật sự xuất hiện trong
[Security → Code scanning](https://github.com/ptuan21/cxf-audit/security/code-scanning).
**Cố ý không quét `src/` trong CI mặc định** — `scan-source` tự flag chính
code của mình (xem mục Giới hạn ở trên), sẽ tạo alert "vĩnh viễn" gây hiểu
lầm cho ai ghé thăm repo.

```yaml
- uses: actions/checkout@v4
- run: cargo install --path path/to/cxf-audit
- run: cxf-audit scan-source --format sarif src/ > results.sarif
  continue-on-error: true   # đừng để bước scan fail cả job trước khi kịp upload
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Đóng góp

Xem [CONTRIBUTING.md](CONTRIBUTING.md) — bao gồm cả chính sách nếu bạn tìm
được lỗ hổng thật ở 1 vendor cụ thể bằng tool này (không phải mở issue ở
đây).

## License

MIT — xem [LICENSE](LICENSE).
