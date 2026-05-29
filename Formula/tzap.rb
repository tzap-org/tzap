class Tzap < Formula
  desc "Create, list, verify, and extract encrypted recoverable tzap archives"
  homepage "https://github.com/frankmanzhu/tzap"
  version "0.1.2"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/frankmanzhu/tzap/releases/download/v#{version}/tzap-v#{version}-macos-aarch64.tar.gz"
      sha256 "8a271f32f30b208de5906bf2b8c42875e8ce26fecd3845e44b5707d71cc0e1f7"
    else
      url "https://github.com/frankmanzhu/tzap/releases/download/v#{version}/tzap-v#{version}-macos-x86_64.tar.gz"
      sha256 "256a66fe531c0816ee025d2491616ef806af034287cd17ededc521b7302bc295"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/frankmanzhu/tzap/releases/download/v#{version}/tzap-v#{version}-linux-x86_64-musl.tar.gz"
      sha256 "d01b9c2264f8b55cd1c0bb0f32645e74c7e7a61136522850376c3788b4905b06"
    else
      url "https://github.com/frankmanzhu/tzap/releases/download/v#{version}/tzap-v#{version}-linux-aarch64-musl.tar.gz"
      sha256 "2c16d063ea6a9b3b03b1876e97cfaecc79902bc61d1556bb0cf65e623ff02115"
    end
  end

  def install
    bin.install "tzap"
  end

  test do
    assert_match "tzap #{version}", shell_output("#{bin}/tzap --version")

    (testpath/"input.txt").write "homebrew smoke payload\n"
    archive = testpath/"smoke.tzap"
    outdir = testpath/"out"
    passphrase = "homebrew-smoke-passphrase\n"

    pipe_output(
      "#{bin}/tzap create --password-stdin --argon2-t-cost 1 --argon2-m-cost-kib 8 " \
      "--argon2-parallelism 1 -o #{archive} #{testpath/"input.txt"}",
      passphrase,
    )
    assert_match "input.txt", pipe_output("#{bin}/tzap list --password-stdin #{archive}", passphrase)
    assert_match "OK", pipe_output("#{bin}/tzap verify --password-stdin #{archive}", passphrase)
    pipe_output("#{bin}/tzap extract --password-stdin --directory #{outdir} #{archive} input.txt", passphrase)
    assert_equal "homebrew smoke payload\n", (outdir/"input.txt").read
  end
end
