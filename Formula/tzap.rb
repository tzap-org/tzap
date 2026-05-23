class Tzap < Formula
  desc "Create, list, verify, and extract encrypted recoverable tzap archives"
  homepage "https://github.com/frankmanzhu/tzap"
  version "0.1.0"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/frankmanzhu/tzap/releases/download/v0.1.0/tzap-v0.1.0-macos-aarch64.tar.gz"
      sha256 "5cb15c5349b36085c6352b3b19f8da72c5cea31ce55cf2cddc22f0560b4ac7de"
    else
      url "https://github.com/frankmanzhu/tzap/releases/download/v0.1.0/tzap-v0.1.0-macos-x86_64.tar.gz"
      sha256 "8b0a2812ec3dd694d5ebc834d638fd00cb7512e2d414b7f8ecda44677dbd9f4e"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/frankmanzhu/tzap/releases/download/v0.1.0/tzap-v0.1.0-linux-x86_64.tar.gz"
      sha256 "d77065761ce8898e32135bab0a57e032cd145a3ff92cfffeb3f84ec908f3d698"
    else
      odie "Linux aarch64 release artifacts are not published yet"
    end
  end

  def install
    bin.install "tzap"
  end

  test do
    assert_match "tzap #{version}", shell_output("#{bin}/tzap --version")
  end
end
