# Security

Không commit username, password, client secret hoặc webhook secret. Chỉ xác minh webhook trên raw body trước khi parse/xử lý và dùng `transaction_code` làm khóa chống trùng.

Báo cáo lỗ hổng riêng tư qua `info@themona.global`.
