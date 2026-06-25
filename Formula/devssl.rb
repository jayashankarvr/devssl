# typed: false
# frozen_string_literal: true

class Devssl < Formula
  desc "Zero-config local HTTPS certificates for development"
  homepage "https://github.com/jayashankarvr/devssl"
  version "0.3.0"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/jayashankarvr/devssl/releases/download/v#{version}/devssl-v#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "0827433430e9c116a02bda7cbe1035a8ab77333649f5491c03f367115ae43a44"
    else
      url "https://github.com/jayashankarvr/devssl/releases/download/v#{version}/devssl-v#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "0e472ac92950bd118412b9652a2ef8e8956064bdf65089c1cb7169448fda418a"
    end
  end

  def install
    bin.install "devssl"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/devssl --version")
  end
end
