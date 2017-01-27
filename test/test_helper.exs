ExUnit.start()
defmodule Utils do
  @hash_funs ~w(md5 sha sha224 sha256 sha384 sha512)a

  defmacro test_all_hash_funs(name, [do: block]) do
    for fun <- @hash_funs do
      quote do
        test "[#{unquote(fun)}] #{unquote(name)}" do
          var!(fun) = unquote(fun)
          unquote(block)
        end
      end
    end
  end
end
