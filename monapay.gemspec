# frozen_string_literal: true

require_relative "lib/monapay"

Gem::Specification.new do |spec|
  spec.name = "monapay"
  spec.version = MonaPay::VERSION
  spec.authors = ["The MONA Group"]
  spec.email = ["info@themona.global"]
  spec.summary = "SDK Ruby stdlib-only cho MONA Pay"
  spec.description = "Tích hợp tài khoản ảo, VietQR, giao dịch và webhook MONA Pay bằng Ruby."
  spec.homepage = "https://monapay.vn/docs"
  spec.license = "MIT"
  spec.required_ruby_version = Gem::Requirement.new(">= 2.6.0")
  spec.files = Dir["lib/**/*.rb", "README.md", "CHANGELOG.md", "LICENSE", "SECURITY.md", "examples/**/*.rb"]
  spec.require_paths = ["lib"]
  spec.metadata = {
    "source_code_uri" => "https://github.com/mona-software/monapay-ruby",
    "documentation_uri" => "https://monapay.vn/docs",
    "bug_tracker_uri" => "https://github.com/mona-software/monapay-ruby/issues"
  }
end
