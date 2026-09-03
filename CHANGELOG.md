# Changelog

## 0.4.0

- Thêm `payment_profile`, `checkouts`, xem lại/xoay secret hồ sơ và API key.
- Tự sinh `Idempotency-Key` cho tạo/huỷ checkout và cho phép truyền key riêng.

## 0.3.0

- Client credentials mặc định, token có hạn và factory `Client.from_env`.
- Thêm sandbox transactions, email configs, email logs và email suppressions.

## 0.1.0

- Bản đầu tiên: full API client, transaction Enumerator và webhook HMAC-SHA256 stdlib-only.
