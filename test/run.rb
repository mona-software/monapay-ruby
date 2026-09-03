# frozen_string_literal: true

require "minitest/autorun"
require "openssl"
require_relative "../lib/monapay"

class MonaPayTest < Minitest::Test
  def envelope(data, success: true)
    JSON.generate(success: success, message: "ok", data: data)
  end

  def test_token_cache_headers_and_refresh_once
    calls = []
    login_count = 0
    me_count = 0
    transport = lambda do |request|
      calls << request
      if request[:url].end_with?("/api/v1/oauth/token")
        login_count += 1
        body = JSON.parse(request[:body])
        assert_equal({ "grant_type" => "client_credentials", "client_id" => "client-id", "client_secret" => "secret" }, body)
        [200, envelope("access_token" => "token-#{login_count}", "expires_in" => 3600)]
      elsif request[:url].end_with?("/api/v1/client/me")
        me_count += 1
        me_count == 1 ? [401, JSON.generate(detail: "expired")] : [200, envelope("username" => "user")]
      else
        [200, envelope("id" => "hook-1")]
      end
    end
    client = MonaPay::Client.new(client_id: "client-id", client_secret: "secret",
                                 base_url: "https://example.test/", transport: transport)

    client.webhooks.create(name: "Shop", webhook_url: "https://shop.test/hook")
    assert_equal({ "username" => "user" }, client.me)
    assert_equal 2, login_count
    assert_equal "Bearer token-1", calls[1][:headers]["Authorization"]
    assert_equal "secret", calls[1][:headers]["X-Client-Secret"]
    refute calls.last[:headers].key?("X-Client-Secret")
    assert_equal "Bearer token-2", calls.last[:headers]["Authorization"]
  end

  def test_iterator_paginates_and_since_id_is_client_side
    pages = []
    transport = lambda do |request|
      if request[:url].end_with?("/api/v1/client/login")
        [200, envelope("access_token" => "token")]
      else
        uri = URI(request[:url])
        params = URI.decode_www_form(uri.query).to_h
        pages << params.fetch("page")
        refute params.key?("since_id")
        data = if params["page"] == "1"
                 [{ "id" => "tx-3" }, { "id" => "tx-2" }]
               else
                 [{ "id" => "tx-1" }]
               end
        [200, envelope("data" => data, "last_page" => 2)]
      end
    end
    client = MonaPay::Client.new(username: "user", password: "pass", base_url: "https://example.test", transport: transport)
    ids = client.transactions.iterate(virtual_account_number: "MONA 01", limit: 2, since_id: "tx-1").map { |item| item["id"] }
    assert_equal %w[tx-3 tx-2], ids
    assert_equal %w[1 2], pages
  end

  def test_webhook_signature_timestamp_and_json
    raw = '{"amount":2500000,"transaction_code":"FT1"}'
    timestamp = Time.now.to_i.to_s
    digest = OpenSSL::HMAC.hexdigest("SHA256", "test-secret", "#{timestamp}.#{raw}")
    valid = MonaPay.verify_webhook(raw, timestamp, "sha256=#{digest}", "test-secret")
    assert valid.ok?
    assert_equal "FT1", valid.payload["transaction_code"]

    invalid = MonaPay.verify_webhook(raw, timestamp, "sha256=#{"0" * 64}", "test-secret")
    refute invalid.ok?
    assert_equal :invalid_signature, invalid.reason

    old = MonaPay.verify_webhook(raw, (Time.now.to_i - 301).to_s, "sha256=#{digest}", "test-secret", 300)
    assert_equal :timestamp_out_of_tolerance, old.reason
  end

  def test_routes_and_path_escaping
    urls = []
    transport = lambda do |request|
      urls << request[:url]
      if request[:url].end_with?("/api/v1/client/login")
        [200, envelope("access_token" => "token")]
      else
        [200, envelope({})]
      end
    end
    client = MonaPay::Client.new(username: "user", password: "pass", client_secret: "secret",
                                 base_url: "https://example.test", transport: transport)
    client.va.verify("request/1", "123456")
    client.qr.cancel("qr 1")
    client.transactions.retry("tx/1", target_type: "WEBHOOK")
    assert urls.any? { |url| url.include?("request%2F1/virtual-account/verification") }
    assert urls.any? { |url| url.include?("qr%201/cancellation") }
    assert urls.any? { |url| url.include?("transactions/tx%2F1/retry") }
  end
end
