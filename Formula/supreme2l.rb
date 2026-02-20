class Supreme2l < Formula
  include Language::Python::Virtualenv

  desc "The 42-Headed Security Guardian - Universal security scanner"
  homepage "https://silenceai.net"
  url "https://files.pythonhosted.org/packages/source/m/supreme2l/supreme2l-0.9.2.1-py3-none-any.whl"
  sha256 "NEEDS_TO_BE_CALCULATED"
  license "MIT"

  depends_on "python@3.11"

  def install
    virtualenv_install_with_resources
  end

  test do
    system "#{bin}/supreme2l", "--version"
  end
end
