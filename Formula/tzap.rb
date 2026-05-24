class Tzap < Formula
  desc "Create, list, verify, and extract encrypted recoverable tzap archives"
  homepage "https://github.com/frankmanzhu/tzap"
  version "0.1.1"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/frankmanzhu/tzap/releases/download/v#{version}/tzap-v#{version}-macos-aarch64.tar.gz"
      sha256 "d92f6a005ebada34869157555161d25663e88df8cfd9d9b6832d6511d2d90b36"
    else
      url "https://github.com/frankmanzhu/tzap/releases/download/v#{version}/tzap-v#{version}-macos-x86_64.tar.gz"
      sha256 "bb065264811e39f43fe2b50d1fdcf64273dc57b37b7a7e3f4ae7061df6324064"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/frankmanzhu/tzap/releases/download/v#{version}/tzap-v#{version}-linux-x86_64-musl.tar.gz"
      sha256 "03867e9b538bdff74c442e11a2c9484cfe8f9e840589495d5cf35cabd2d9a793"
    else
      odie "Linux aarch64 release artifacts are not published yet"
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
