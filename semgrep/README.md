# semgrep/ — taint analysis thật cho zip-slip (Rust/Kotlin/Swift)

Khác với [`scan-source`](../src/source_scan) (tree-sitter, chỉ match cú
pháp), rule ở đây dùng **taint tracking thật** của Semgrep: theo dõi dữ liệu
từ zip entry (`by_index`/`by_name`/`.name`/`.path`) xuyên qua biến, gán lại,
method chain, tới tận `File::create`/`File(...)`/`appendingPathComponent`,
và **hiểu đúng guard clause** (`if name.contains("..") { continue }` không
bị báo nhầm).

## Vì sao không dùng CodeQL

Đã thử CodeQL trước (taint tracking mature hơn, có sẵn sink/summary/sanitizer
cho path injection) nhưng **thất bại**: CodeQL Rust (GA 10/2025) không
resolve được method call qua trait dispatch trong môi trường test — không
chỉ với crate `zip`, mà cả `.clone()`/`.to_uppercase()` chuẩn std cũng vậy
(verify bằng test cô lập với struct generic tự viết, không phải third-party
crate). Model MaD (YAML) không sửa được vì nó chỉ áp dụng **sau khi** call
đã resolve — bằng chứng đọc trực tiếp từ source `FlowSummaryImpl.qll`. Kết
luận: không phải lỗi có thể vá từ bên ngoài, đây là giới hạn hiện tại của
core engine.

## Kỹ thuật mấu chốt: `by-side-effect` + `focus-metavariable`

Thử ngây thơ `pattern-sanitizers: [{pattern: $X.contains("..")}]` **không
chặn được gì** — verify bằng test chéo Rust và Python (ngôn ngữ Semgrep
taint mature nhất) đều bị y hệt, tức đây không phải giới hạn riêng ngôn ngữ
nào mà là cách match sanitizer cơ bản: nó chỉ làm sạch taint cho *chính
expression* `$X.contains("..")` (kết quả boolean, không dùng tới), không
làm sạch cho biến `$X` ở các lần dùng sau. Cách đúng:

```yaml
pattern-sanitizers:
  - patterns:
      - pattern: $X.contains("..")
      - focus-metavariable: $X
    by-side-effect: true
```

`by-side-effect: true` khiến Semgrep coi biến khớp với `$X` là đã sanitize
**tại điểm gọi**, không phải chỉ trong bản thân lời gọi đó.

## Giới hạn đã biết

- **Swift cần bind ra biến local trước khi check.** `if entry.path.contains("..")`
  (check thẳng property access) **không** được nhận diện đúng — phải viết
  `let path = entry.path; if path.contains("..")`. Rust/Kotlin không gặp vấn
  đề này (đã test cả 2 dạng). Đây là hạn chế thật của kỹ thuật, không phải
  giả thuyết — xem lịch sử thử nghiệm nếu cần tái hiện.
- `semgrep --test` (khung test built-in của Semgrep) **crash** với setup
  hiện tại (`IndexError` trong `relatively_eq`, file
  `semgrep/test.py`) khi 1 file rule gộp nhiều ngôn ngữ + fixture đặt tên
  không khớp rule ID. Dùng [`verify.sh`](verify.sh) thay thế — verify bằng
  `--json` + so khớp dòng thủ công, không phụ thuộc annotation-matching có
  bug của Semgrep.
- Rule match theo tên method/property (`by_index`, `.name`, `.path`), không
  theo kiểu resolve — cùng hạn chế đã ghi trong `scan-source`: có thể khớp
  nhầm 1 hàm trùng tên trên type không liên quan.

## Dùng thử

```sh
semgrep --config zip-slip-taint.yaml path/to/your/code
./verify.sh   # smoke test trên fixtures/, cần semgrep đã cài
```
