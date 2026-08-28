# frozen_string_literal: true

# Rails example. Keep request.raw_post unchanged; parsing/re-encoding JSON breaks HMAC.
class MonaPayWebhooksController < ApplicationController
  skip_before_action :verify_authenticity_token

  def create
    result = MonaPay.verify_webhook(
      request.raw_post,
      request.headers["X-Mona-Timestamp"],
      request.headers["X-Mona-Signature"],
      ENV.fetch("MONAPAY_WEBHOOK_SECRET")
    )
    return head :unauthorized unless result.ok?

    transaction = result.payload
    PaymentReceipt.find_or_create_by!(transaction_code: transaction.fetch("transaction_code")) do |receipt|
      receipt.amount = transaction.fetch("amount")
      receipt.payload = transaction
    end
    head :ok
  end
end
