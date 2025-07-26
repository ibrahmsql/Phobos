class Phobos < Formula
  desc "Blazingly fast Rust-based port scanner with advanced stealth capabilities"
  homepage "https://github.com/ibrahim/phobos"
  url "https://github.com/ibrahim/phobos/archive/refs/tags/v1.0.0.tar.gz"
  sha256 "83b0a46bec699bb9d194c58792ee5f8ef6984e7cc52808ed110312682c0ca7b9"
  license "MIT"
  head "https://github.com/ibrahim/phobos.git", branch: "main"

  depends_on "rust" => :build

  def install
    system "cargo", "install", "--locked", "--root", prefix, "--path", "."
  end

  def caveats
    <<~EOS
      Phobos requires appropriate network permissions to perform port scanning.
      Some features may require running with elevated privileges (sudo).
      
      Quick start:
        phobos example.com
        phobos -p 80,443,8080 example.com
        phobos --help
    EOS
  end

  test do
    # Test that the binary runs and shows help
    assert_match "Phobos", shell_output("#{bin}/phobos --help")
    
    # Test version command
    assert_match "phobos", shell_output("#{bin}/phobos --version")
    
    # Test basic functionality (scan localhost)
    system bin/"phobos", "--help"
  end
end