class Tzap < Formula
  desc "Create, list, verify, and extract encrypted recoverable tzap archives"
  homepage "https://github.com/frankmanzhu/tzap"
  version "0.1.3"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/frankmanzhu/tzap/releases/download/v#{version}/tzap-v#{version}-macos-aarch64.tar.gz"
      sha256 "10c0dbce0dc46d4e42d2a4e9840c810620ab9b9587c114b800c24ce015ea1450"
    else
      url "https://github.com/frankmanzhu/tzap/releases/download/v#{version}/tzap-v#{version}-macos-x86_64.tar.gz"
      sha256 "58cabe8f2a43b799971cc5a628fcf1b55932b84f4b8635e9eaf6e0fda8570aff"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/frankmanzhu/tzap/releases/download/v#{version}/tzap-v#{version}-linux-x86_64-musl.tar.gz"
      sha256 "af488afdc142e91231eb02314ce4c5c94df6bd8fd8dcd271555f69e4c2507078"
    else
      url "https://github.com/frankmanzhu/tzap/releases/download/v#{version}/tzap-v#{version}-linux-aarch64-musl.tar.gz"
      sha256 "b990679c57829445e30d642a03b2ddf959f7fc8ea440481b67aa57df23f4cc4b"
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
