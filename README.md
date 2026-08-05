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

## Dùng thử

```sh
cargo run -- gen-poc poc.zip                 # dùng entry name mặc định
cargo run -- gen-poc poc.zip "../../etc/foo" # tuỳ chỉnh entry name
cargo run -- scan poc.zip
```

## Test

```sh
cargo test
```

10 test, bao gồm cả trường hợp biên: archive rỗng, nhiều entry (chỉ entry
độc hại bị flag), Windows-style path không có ổ đĩa, input không phải zip
hợp lệ, và test khẳng định `zip` crate **không** tự sanitize tên entry khi
ghi (xác nhận thực nghiệm rằng nguy cơ zip-slip tồn tại thật ở tầng thư viện
archive, không chỉ là suy đoán từ đọc spec).
