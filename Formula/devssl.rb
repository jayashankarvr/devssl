# typed: false
# frozen_string_literal: true

class Devssl < Formula
  desc "Zero-config local HTTPS certificates for development"
  homepage "https://github.com/jayashankarvr/devssl"
  version "0.1.0"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/jayashankarvr/devssl/releases/download/v#{version}/devssl-v#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "PLACEHOLDER_ARM64"
    else
      url "https://github.com/jayashankarvr/devssl/releases/download/v#{version}/devssl-v#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "PLACEHOLDER_X86_64"
    end
  end

  def install
    bin.install "devssl"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/devssl --version")
  end
end
