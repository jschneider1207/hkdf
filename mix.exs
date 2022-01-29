defmodule HKDF.Mixfile do
  use Mix.Project

  def project do
    [app: :hkdf,
     version: "0.2.0",
     build_path: "_build",
     config_path: "config/config.exs",
     deps_path: "deps",
     lockfile: "mix.lock",
     elixir: "~> 1.13",
     build_embedded: Mix.env == :prod,
     start_permanent: Mix.env == :prod,
     description: description(),
     package: package(),
     deps: deps()]
  end

  def application do
    [extra_applications: [:logger, :crypto]]
  end

  defp deps do
    [{:ex_doc, ">= 0.0.0", only: :dev, runtime: false}]
  end

  defp description do
    """
    HMAC-based key derivation function.
    """
  end

  defp package do
    [name: :hkdf,
     files: ["lib", "mix.exs", "README*", "LICENSE*"],
     maintainers: ["Jessica Schneider"],
     licenses: ["MIT"],
     links: %{"GitHub" => "https://github.com/jschneider1207/hkdf"}]
  end
end
