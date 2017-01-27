# HKDF

Provides a simple Hashed Message Authentication Code (HMAC)-based
key derivation function (HKDF).

Based on algorithm defined in [rfc 5859](https://tools.ietf.org/html/rfc5869).

## Usage

Derive Key:
```elixir
HKDF.derive(:sha256, "some input", 42, "optional salt", "optional secret message")
```

Extract output key material:
```elixir
HKDF.extract(:sha256, "some input", "optional salt")
```

Expand pseudorandom key:
```elixir
prk = HKDF.extract(:sha256, "some input", "optional salt")
HKDF.expand(:sha256, prk, 16, "optional secret message")
```

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed
by adding `hkdf` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [{:hkdf, "~> 0.1.0"}]
end
```

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at [https://hexdocs.pm/hkdf](https://hexdocs.pm/hkdf).
