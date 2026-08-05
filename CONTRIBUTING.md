# Contributing

Cảm ơn bạn quan tâm đến `cxf-audit`. Đây là tool nhỏ, phạm vi hẹp (audit
archive/protocol CXF/CXP) — issue/PR phù hợp nhất là:

- Rule mới cho 1 vấn đề cụ thể trong spec CXF/CXP (kèm tham chiếu tới đoạn
  spec liên quan).
- Sửa false positive/false negative ở rule hiện có, kèm test tái hiện.
- Cải thiện tích hợp (pre-commit hook, CI, ergonomics của API thư viện).

Không phải hướng phù hợp: mở rộng thành scanner bảo mật tổng quát cho mọi
loại code (đã cân nhắc và cố tình không đi hướng đó — xem README).

## Chạy thử local

```sh
cargo build --all-targets
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

Cả 4 lệnh trên đều chạy trong CI (`.github/workflows/ci.yml`) — PR phải xanh
cả 4 mới được merge.

## Thêm 1 rule mới

Mỗi rule là 1 hàm trả `Vec<Finding>` (xem `src/archive.rs`, `src/limits.rs`,
`src/version.rs` làm ví dụ). Yêu cầu:

1. Trích dẫn đúng phần spec (CXF hoặc CXP) làm căn cứ cho rule — không thêm
   check dựa trên suy đoán/best-practice chung chung không liên quan CXF/CXP.
2. Test cả trường hợp dương tính lẫn "không được flag nhầm" (false positive)
   — xem `tests/zipslip.rs::does_not_flag_legitimate_nested_relative_path`
   làm ví dụ mẫu.
3. Nếu rule đủ quan trọng để chặn runtime (không chỉ báo cáo), thêm hàm
   `assert_*` tương ứng trong `src/guard.rs`.

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
