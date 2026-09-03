# frozen_string_literal: true

require "json"
require "net/http"
require "openssl"
require "securerandom"
require "thread"
require "uri"

module MonaPay
  VERSION = "0.4.0"
  DEFAULT_BASE_URL = "https://api.monapay.vn"

  class APIError < StandardError
    attr_reader :status, :body

    def initialize(message, status: nil, body: nil)
      super(message)
      @status = status
      @body = body
    end
  end

  WebhookResult = Struct.new(:ok, :reason, :payload, keyword_init: true) do
    def ok?
      ok
    end
  end

  def self.verify_webhook(raw, timestamp, signature, secret, tolerance = 300)
    raise ArgumentError, "tolerance phải là số không âm" unless tolerance.is_a?(Numeric) && tolerance >= 0

    raw = raw.to_s.b
    timestamp = timestamp.to_s
    signature = signature.to_s
    return WebhookResult.new(ok: false, reason: :missing_timestamp) if timestamp.empty?
    return WebhookResult.new(ok: false, reason: :invalid_timestamp) unless timestamp.match?(/\A\d+\z/)

    drift = Time.now.to_i - timestamp.to_i
    return WebhookResult.new(ok: false, reason: :timestamp_out_of_tolerance) if drift.abs > tolerance
    return WebhookResult.new(ok: false, reason: :missing_signature) if signature.empty?

    expected = OpenSSL::HMAC.digest("SHA256", secret.to_s.b, "#{timestamp}.".b + raw)
    valid_format = signature.match?(/\Asha256=[0-9a-fA-F]{64}\z/)
    supplied = valid_format ? [signature.delete_prefix("sha256=")].pack("H*") : ("\0" * 32).b
    unless secure_compare(expected, supplied) && valid_format
      return WebhookResult.new(ok: false, reason: :invalid_signature)
    end

    begin
      WebhookResult.new(ok: true, payload: JSON.parse(raw))
    rescue JSON::ParserError
      WebhookResult.new(ok: false, reason: :invalid_json)
    end
  end

  def self.secure_compare(left, right)
    return false unless left.bytesize == right.bytesize

    different = 0
    left.bytes.zip(right.bytes) { |a, b| different |= a ^ b }
    different.zero?
  end
  private_class_method :secure_compare

  class Client
    attr_reader :base_url, :keys, :va, :bank_accounts, :payment_profile, :checkouts, :qr, :transactions, :webhooks, :webhook_logs,
                :sandbox, :email_configs, :email_logs, :email_suppressions

    def initialize(client_id: nil, username: nil, password: nil, client_secret: nil, base_url: DEFAULT_BASE_URL, transport: nil,
                   open_timeout: 10, read_timeout: 30)
      has_client_credentials = !client_id.to_s.strip.empty? && !client_secret.to_s.strip.empty?
      has_password_credentials = !username.to_s.strip.empty? && !password.to_s.empty?
      unless has_client_credentials || has_password_credentials
        raise ArgumentError, "Cần client_id + client_secret hoặc username + password; không dùng password cho AI agent vì sẽ gãy khi bật 2FA"
      end

      @client_id = client_id.to_s
      @username = username.to_s
      @password = password.to_s
      @client_secret = client_secret.to_s
      @base_url = base_url.to_s.sub(%r{/+\z}, "")
      uri = URI.parse(@base_url)
      raise ArgumentError, "base_url phải dùng http hoặc https" unless %w[http https].include?(uri.scheme) && uri.host

      @transport = transport
      @open_timeout = open_timeout
      @read_timeout = read_timeout
      @access_token = nil
      @token_expires_at = 0
      @mutex = Mutex.new

      @keys = KeysResource.new(self)
      @va = VirtualAccountsResource.new(self)
      @bank_accounts = BankAccountsResource.new(self)
      @payment_profile = PaymentProfileResource.new(self)
      @checkouts = CheckoutsResource.new(self)
      @qr = QRResource.new(self)
      @transactions = TransactionsResource.new(self)
      @webhooks = WebhooksResource.new(self)
      @webhook_logs = WebhookLogsResource.new(self)
      @sandbox = SandboxResource.new(self)
      @email_configs = EmailConfigsResource.new(self)
      @email_logs = EmailLogsResource.new(self)
      @email_suppressions = EmailSuppressionsResource.new(self)
    rescue URI::InvalidURIError => e
      raise ArgumentError, "base_url không hợp lệ: #{e.message}"
    end

    def self.from_env(env = ENV, **options)
      new(
        client_id: env["MONAPAY_CLIENT_ID"], client_secret: env["MONAPAY_CLIENT_SECRET"],
        username: env["MONAPAY_USERNAME"], password: env["MONAPAY_PASSWORD"],
        base_url: env.fetch("MONAPAY_BASE_URL", DEFAULT_BASE_URL), **options
      )
    end

    def login
      cached = @mutex.synchronize { Time.now.to_f < @token_expires_at ? @access_token : nil }
      return cached if cached && !cached.empty?

      using_client_credentials = !@client_id.empty? && !@client_secret.empty?
      data = send_request(
        "POST", using_client_credentials ? "/api/v1/oauth/token" : "/api/v1/client/login",
        body: using_client_credentials ? { grant_type: "client_credentials", client_id: @client_id, client_secret: @client_secret } : { username: @username, password: @password },
        authenticated: false
      )
      token = data.is_a?(Hash) ? data["access_token"] : nil
      raise APIError.new("Response đăng nhập không có access_token", body: data) if token.to_s.empty?

      expires_in = data["expires_in"] || (using_client_credentials ? 3600 : 86_400)
      @mutex.synchronize do
        @access_token = token
        @token_expires_at = Time.now.to_f + [expires_in.to_f - 60, 0].max
      end
      token
    end

    def me
      request("GET", "/api/v1/client/me")
    end

    def client_secret=(secret)
      @mutex.synchronize { @client_secret = secret.to_s }
    end

    def request(method, path, body: nil, query: nil, headers: nil)
      login
      token = @mutex.synchronize { @access_token }
      send_request(method, path, body: body, query: query, headers: headers, token: token)
    rescue APIError => e
      raise unless e.status == 401

      @mutex.synchronize do
        if @access_token == token
          @access_token = nil
          @token_expires_at = 0
        end
      end
      login
      refreshed = @mutex.synchronize { @access_token }
      send_request(method, path, body: body, query: query, headers: headers, token: refreshed)
    end

    private

    def send_request(method, path, body: nil, query: nil, headers: nil, token: nil, authenticated: true)
      custom_headers = headers
      uri = URI.parse(@base_url + path)
      uri.query = URI.encode_www_form(compact_query(query)) if query && !query.empty?
      headers = { "Accept" => "application/json" }
      encoded = body.nil? ? nil : JSON.generate(body)
      headers["Content-Type"] = "application/json" if encoded
      headers["Authorization"] = "Bearer #{token}" if authenticated && token && !token.empty?
      secret = @mutex.synchronize { @client_secret }
      if authenticated && method != "GET" && !secret.empty?
        headers["X-Client-Secret"] = secret
      end
      headers.merge!(custom_headers) if custom_headers

      status, raw = if @transport
                      normalize_response(@transport.call(method: method, url: uri.to_s, headers: headers, body: encoded))
                    else
                      net_http(method, uri, headers, encoded)
                    end
      parsed = raw.to_s.empty? ? {} : JSON.parse(raw.to_s)
      success_flag = parsed.is_a?(Hash) ? parsed["success"] : nil
      if status < 200 || status >= 300 || success_flag == false
        message = parsed.is_a?(Hash) && (parsed["message"] || parsed["detail"])
        message = "MONA Pay API lỗi HTTP #{status}" if message.to_s.empty?
        raise APIError.new(message, status: status, body: parsed)
      end
      parsed.is_a?(Hash) ? parsed["data"] : nil
    rescue JSON::ParserError
      raise APIError.new("MONA Pay trả response không phải JSON (HTTP #{status})", status: status, body: raw)
    rescue APIError
      raise
    rescue StandardError => e
      raise APIError.new("Không kết nối được MONA Pay: #{e.message}", body: e)
    end

    def compact_query(query)
      query.each_with_object({}) do |(key, value), clean|
        clean[key] = value unless value.nil? || value == ""
      end
    end

    def normalize_response(response)
      if response.is_a?(Array)
        [Integer(response[0]), response[1].to_s]
      elsif response.is_a?(Hash)
        [Integer(response[:status] || response["status"]), response[:body] || response["body"] || ""]
      else
        raise ArgumentError, "transport phải trả [status, body] hoặc Hash"
      end
    end

    def net_http(method, uri, headers, body)
      request_class = {
        "GET" => Net::HTTP::Get,
        "POST" => Net::HTTP::Post,
        "PUT" => Net::HTTP::Put,
        "DELETE" => Net::HTTP::Delete
      }.fetch(method)
      request = request_class.new(uri.request_uri, headers)
      request.body = body if body
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == "https"
      http.open_timeout = @open_timeout
      http.read_timeout = @read_timeout
      response = http.request(request)
      [response.code.to_i, response.body.to_s]
    end
  end

  class Resource
    def initialize(client)
      @client = client
    end

    private

    def segment(value)
      URI.encode_www_form_component(value.to_s).gsub("+", "%20")
    end
  end

  class KeysResource < Resource
    def generate(name = "Default Key")
      data = @client.request("POST", "/api/v1/client-keys/generate", body: { name: name })
      @client.client_secret = data["client_secret"] if data.is_a?(Hash) && !data["client_secret"].to_s.empty?
      data
    end

    def list
      @client.request("GET", "/api/v1/client-keys/list")
    end

    def destroy(key_id)
      @client.request("DELETE", "/api/v1/client-keys/destroy/#{segment(key_id)}")
    end

    def reveal(key_id, confirmation)
      @client.request("POST", "/api/v1/client-keys/#{segment(key_id)}/reveal", body: confirmation)
    end

    def rotate(key_id)
      data = @client.request("POST", "/api/v1/client-keys/#{segment(key_id)}/rotate", body: {})
      @client.client_secret = data["client_secret"] if data.is_a?(Hash) && !data["client_secret"].to_s.empty?
      data
    end
  end

  class VirtualAccountsResource < Resource
    def register(body)
      @client.request("POST", "/api/v1/acb/virtual-account/registration", body: body)
    end

    def verify(request_id, code)
      @client.request("POST", "/api/v1/acb/#{segment(request_id)}/virtual-account/verification",
                      body: { code: code })
    end

    def register_notification(virtual_account_id, body = {})
      @client.request("POST", "/api/v1/acb/#{segment(virtual_account_id)}/notification/registration", body: body)
    end

    def verify_notification(request_id, code)
      @client.request("POST", "/api/v1/acb/#{segment(request_id)}/notification/verification",
                      body: { code: code })
    end

    def list(bank_account_id)
      @client.request("GET", "/api/v1/acb/#{segment(bank_account_id)}/virtual-account/retrieve")
    end
  end

  class BankAccountsResource < Resource
    def list
      @client.request("GET", "/api/v1/client/bank-accounts")
    end
  end

  class PaymentProfileResource < Resource
    def get
      @client.request("GET", "/api/v1/payment-profile")
    end

    def set(body)
      @client.request("PUT", "/api/v1/payment-profile", body: body)
    end

    def rotate_return_secret
      @client.request("POST", "/api/v1/payment-profile/rotate-return-secret", body: {})
    end

    def reveal_return_secret(confirmation)
      @client.request("POST", "/api/v1/payment-profile/reveal-return-secret", body: confirmation)
    end
  end

  class CheckoutsResource < Resource
    def create(body, idempotency_key: nil)
      @client.request("POST", "/api/v1/checkouts", body: body,
                      headers: { "Idempotency-Key" => idempotency_key || SecureRandom.uuid })
    end

    def get(checkout_id)
      @client.request("GET", "/api/v1/checkouts/#{segment(checkout_id)}")
    end

    def list(status: nil, order_code: nil, from_date: nil, to_date: nil, page: nil, limit: nil)
      @client.request("GET", "/api/v1/checkouts", query: {
                        status: status, order_code: order_code, from_date: from_date,
                        to_date: to_date, page: page, limit: limit
                      })
    end

    def cancel(checkout_id, idempotency_key: nil)
      @client.request("POST", "/api/v1/checkouts/#{segment(checkout_id)}/cancel", body: {},
                      headers: { "Idempotency-Key" => idempotency_key || SecureRandom.uuid })
    end
  end

  class QRResource < Resource
    def generate(body)
      @client.request("POST", "/api/v1/acb/qr-payment/generate", body: body)
    end

    def cancel(qr_code_id, body = nil)
      @client.request("DELETE", "/api/v1/acb/qr-payment/#{segment(qr_code_id)}/cancellation", body: body)
    end
  end

  class TransactionsResource < Resource
    def list(virtual_account_number:, page: 1, limit: 100)
      raise ArgumentError, "virtual_account_number là bắt buộc" if virtual_account_number.to_s.empty?

      @client.request("GET", "/api/v1/acb/virtual-account/transactions",
                      query: { virtual_account_number: virtual_account_number, page: page, limit: limit })
    end

    def iterate(virtual_account_number:, page: 1, limit: 100, since_id: nil)
      Enumerator.new do |output|
        current_page = page.to_i.positive? ? page.to_i : 1
        page_size = limit.to_i.positive? ? limit.to_i : 100
        stopped = false
        until stopped
          response = list(virtual_account_number: virtual_account_number, page: current_page, limit: page_size)
          raise APIError, "Response giao dịch không phải object" unless response.is_a?(Hash)

          Array(response["data"]).each do |item|
            if since_id && item.is_a?(Hash) && [item["id"], item["transaction_code"]].map(&:to_s).include?(since_id.to_s)
              stopped = true
              break
            end
            output << item
          end
          break if stopped

          has_next = response.key?("has_next") ? response["has_next"] : current_page < response.fetch("last_page", current_page).to_i
          break unless has_next

          current_page += 1
        end
      end
    end

    def retry(transaction_id, target_type:, target_id: nil)
      body = { target_type: target_type }
      body[:target_id] = target_id if target_id
      @client.request("POST", "/api/v1/acb/virtual-account/transactions/#{segment(transaction_id)}/retry", body: body)
    end
  end

  class WebhooksResource < Resource
    def list
      @client.request("GET", "/api/v1/client-webhooks")
    end

    def create(body)
      @client.request("POST", "/api/v1/client-webhooks", body: body)
    end

    def update(config_id, body)
      @client.request("PUT", "/api/v1/client-webhooks/#{segment(config_id)}", body: body)
    end

    def remove(config_id)
      @client.request("DELETE", "/api/v1/client-webhooks/#{segment(config_id)}")
    end

    def test(body = { is_dummy: true })
      @client.request("POST", "/api/v1/client-webhooks/test", body: body)
    end
  end

  class WebhookLogsResource < Resource
    def list(status: nil, from_date: nil, to_date: nil, page: nil, limit: nil)
      @client.request("GET", "/api/v1/webhook-logs",
                      query: query(status, from_date, to_date, page, limit))
    end

    def stats(status: nil, from_date: nil, to_date: nil, page: nil, limit: nil)
      @client.request("GET", "/api/v1/webhook-logs/stats",
                      query: query(status, from_date, to_date, page, limit))
    end

    private

    def query(status, from_date, to_date, page, limit)
      { status: status, from_date: from_date, to_date: to_date, page: page, limit: limit }
    end
  end

  class SandboxResource < Resource
    def create_transaction(body)
      @client.request("POST", "/api/v1/sandbox/transactions", body: body)
    end
  end

  class EmailConfigsResource < Resource
    def list
      @client.request("GET", "/api/v1/email-configs")
    end

    def create(body)
      @client.request("POST", "/api/v1/email-configs", body: body)
    end

    def get(config_id)
      @client.request("GET", "/api/v1/email-configs/#{segment(config_id)}")
    end

    def update(config_id, body)
      @client.request("PUT", "/api/v1/email-configs/#{segment(config_id)}", body: body)
    end

    def remove(config_id)
      @client.request("DELETE", "/api/v1/email-configs/#{segment(config_id)}")
    end

    def verify(config_id, email:, code:)
      @client.request("POST", "/api/v1/email-configs/#{segment(config_id)}/verify", body: { email: email, code: code })
    end

    def resend_verification(config_id, email)
      @client.request("POST", "/api/v1/email-configs/#{segment(config_id)}/resend-verification", body: { email: email })
    end

    def test(config_id)
      @client.request("POST", "/api/v1/email-configs/#{segment(config_id)}/test", body: {})
    end
  end

  class EmailLogsResource < Resource
    def list(config_id: nil, status: nil, event_type: nil, from_date: nil, to_date: nil, page: nil, limit: nil)
      @client.request("GET", "/api/v1/email-logs", query: {
                        config_id: config_id, status: status, event_type: event_type, from_date: from_date,
                        to_date: to_date, page: page, limit: limit
                      })
    end

    def stats(from_date: nil, to_date: nil)
      @client.request("GET", "/api/v1/email-logs/stats", query: { from_date: from_date, to_date: to_date })
    end
  end

  class EmailSuppressionsResource < Resource
    def list
      @client.request("GET", "/api/v1/email-suppressions")
    end

    def remove(email)
      @client.request("DELETE", "/api/v1/email-suppressions/#{segment(email)}")
    end
  end
end
