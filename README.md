# MONA Pay Ruby SDK

SDK Ruby không có gem dependency cho MONA Pay. MONA Pay là API ngân hàng và dịch vụ xác nhận thanh toán tự động của The MONA Group, giúp doanh nghiệp Việt Nam nhận và xác nhận tiền chuyển khoản theo thời gian thực qua tài khoản ảo (VA), VietQR, webhook và Telegram, thiết kế để cả lập trình viên lẫn AI agent tích hợp trong vài phút.

## Xác thực cho AI agent

```bash
export MONAPAY_CLIENT_ID="client-id"
export MONAPAY_CLIENT_SECRET="client-secret"
export MONAPAY_BASE_URL="https://api.monapay.vn"
```

```ruby
client = MonaPay::Client.from_env
profile = client.me
qr = client.qr.generate(qr_body)
sandbox = client.sandbox.create_transaction(virtual_account_number: "MONA123", amount: 10_000, description: "AI test")
puts profile
```

`Client.from_env` ưu tiên client credentials, cache token tới gần hạn và tự lấy lại khi gặp HTTP 401. Username/password chỉ là fallback tương thích cũ, không dùng cho AI agent vì sẽ gãy khi bật 2FA.

Các resource gồm `keys`, `payment_profile`, `checkouts`, `bank_accounts`, `va`, `qr`, `transactions`, `webhooks`, `webhook_logs`, `sandbox`, `email_configs`, `email_logs` và `email_suppressions`.

## Cài đặt

```ruby
gem "monapay", "~> 0.4"
```

```ruby
client = MonaPay::Client.new(
  username: ENV.fetch("MONAPAY_USERNAME"),
  password: ENV.fetch("MONAPAY_PASSWORD"),
  client_secret: ENV["MONAPAY_CLIENT_SECRET"]
)

profile = client.me
accounts = client.bank_accounts.list
qr = client.qr.generate(
  ownerNumber: "0123456789", ownerType: "PER", merchantId: "MONA",
  terminalId: "WEB", orderId: "ORDER-001", virtualAccountPrefix: "MONA",
  beneficiaryName: "NGUYEN VAN A", amount: 250_000, description: "ORDER-001"
)
```

Client tự login, cache token và login lại đúng một lần khi nhận HTTP 401. `X-Client-Secret` chỉ được gắn vào request POST/PUT/DELETE. Secret mới từ `client.keys.generate` được lưu vào client để dùng ngay.

## Trang thanh toán (hosted checkout)

```ruby
checkout = client.checkouts.create({ amount: 250_000, order_code: "DH10234", return_url: "https://shop.vn/payment/return" })
redirect_to checkout["checkout_url"], allow_other_host: true
if event["type"] == "CHECKOUT_PAID"
  fulfill_once(event.dig("data", "order_code"))
end
```

SDK tự sinh `Idempotency-Key` cho `create` và `cancel`; truyền `idempotency_key:` khi anh chị cần dùng key riêng. Nguồn sự thật để giao hàng là webhook `CHECKOUT_PAID` hoặc kết quả `get`, không phải redirect trình duyệt.

## Giao dịch và webhook

```ruby
client.transactions.iterate(virtual_account_number: "MONA123", limit: 100).each do |transaction|
  puts transaction["transaction_code"]
end

result = MonaPay.verify_webhook(raw_body, timestamp, signature, ENV.fetch("MONAPAY_WEBHOOK_SECRET"))
raise "invalid webhook: #{result.reason}" unless result.ok?
```

Luôn truyền raw request body vào verifier. Chữ ký là HMAC-SHA256 của `"<timestamp>.<raw_body>"`; cửa sổ mặc định 300 giây và digest được so sánh constant-time. Dùng `transaction_code` làm khóa idempotency. Xem controller Rails tại `examples/rails_webhook_controller.rb`.

Chạy test: `ruby test/run.rb`. Tài liệu API: https://monapay.vn/docs · Hotline 1900 636 648 · info@themona.global.

**MONA Pay thuộc bộ MONA Cloud của The MONA Group.**
