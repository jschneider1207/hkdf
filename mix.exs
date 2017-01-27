defmodule HKDF.Mixfile do
  use Mix.Project

  def project do
    [app: :hkdf,
     version: "0.1.0",
     build_path: "../../_build",
     config_path: "../../config/config.exs",
     deps_path: "../../deps",
     lockfile: "../../mix.lock",
     elixir: "~> 1.4",
     build_embedded: Mix.env == :prod,
     start_permanent: Mix.env == :prod,
     description: description(),
     package: package(),
     deps: deps()]
  end

  def application do
    [extra_applications: [:logger]]
  end

  defp deps do
    []
  end

  defp description do
    """
    HMAC-based key derivation function.
    """
  end

  defp package do
    [name: :hkdf,
     files: ["lib", "mix.exs", "README*", "LICENSE*"],
     maintainers: ["Sam Schneider"],
     licenses: ["MIT"],
     links: %{"GitHub" => "https://github.com/sschneider1207/hkdf"}]
  end
end
