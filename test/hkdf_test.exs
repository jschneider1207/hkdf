defmodule HKDFTest do
  use ExUnit.Case
  doctest HKDF
  import Utils

  describe "extract keys of correct size" do
    test_all_hash_funs "with default salt" do
      expected =
        :crypto.hash(fun, "")
        |> byte_size()

      key = HKDF.extract(fun, "secret")

      assert byte_size(key) === expected
    end

    test_all_hash_funs "with provided salt" do
      expected =
        :crypto.hash(fun, "")
        |> byte_size()

      salt = :crypto.strong_rand_bytes(expected)
      key = HKDF.extract(fun, "secret", salt)

      assert byte_size(key) === expected
    end
  end

  describe "expand keys to correct size" do
    test_all_hash_funs "with default info" do
      len = 16
      key = HKDF.extract(fun, "secret")
      output = HKDF.expand(fun, key, len)

      assert byte_size(output) === len
    end

    test_all_hash_funs "with provided info" do
      len = 16
      key = HKDF.extract(fun, "secret")
      output = HKDF.expand(fun, key, len, "message")

      assert byte_size(output) === len
    end
  end

  describe "rfc 5869 test cases" do
    test "basic sha-256" do
      hash = :sha256
      ikm = <<0x0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B::unit(8)-size(22)>>
      salt = <<0x000102030405060708090A0B0C::unit(8)-size(13)>>
      info = <<0xF0F1F2F3F4F5F6F7F8F9::unit(8)-size(10)>>
      l = 42

      prk =
        <<0x077709362C2E32DF0DDC3F0DC47BBA6390B6C73BB50F9C3122EC844AD7C2B3E5::unit(8)-size(32)>>

      okm =
        <<0x3CB25F25FAACD57A90434F64D0362F2A2D2D0A90CF1A5A4C5DB02D56ECC4C5BF34007208D5B887185865::unit(
            8
          )-size(l)>>

      test_case(hash, ikm, salt, info, l, prk, okm)
    end

    test "sha-256 with longer input/ouputs" do
      hash = :sha256

      ikm =
        <<0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F::unit(
            8
          )-size(80)>>

      salt =
        <<0x606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAF::unit(
            8
          )-size(80)>>

      info =
        <<0xB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF::unit(
            8
          )-size(80)>>

      l = 82

      prk =
        <<0x06A6B88C5853361A06104C9CEB35B45CEF760014904671014A193F40C15FC244::unit(8)-size(32)>>

      okm =
        <<0xB11E398DC80327A1C8E7F78C596A49344F012EDA2D4EFAD8A050CC4C19AFA97C59045A99CAC7827271CB41C65E590E09DA3275600C2F09B8367793A9ACA3DB71CC30C58179EC3E87C14C01D5C1F3434F1D87::unit(
            8
          )-size(l)>>

      test_case(hash, ikm, salt, info, l, prk, okm)
    end

    test "sha-256 with zero length salt/info" do
      hash = :sha256
      ikm = <<0x0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B::unit(8)-size(22)>>
      salt = ""
      info = ""
      l = 42

      prk =
        <<0x19EF24A32C717B167F33A91D6F648BDF96596776AFDB6377AC434C1C293CCB04::unit(8)-size(32)>>

      okm =
        <<0x8DA4E775A563C18F715F802A063C5A31B8A11F5C5EE1879EC3454E5F3C738D2D9D201395FAA4B61A96C8::unit(
            8
          )-size(l)>>

      test_case(hash, ikm, salt, info, l, prk, okm)
    end

    test "basic sha-1" do
      hash = :sha
      ikm = <<0x0B0B0B0B0B0B0B0B0B0B0B::unit(8)-size(11)>>
      salt = <<0x000102030405060708090A0B0C::unit(8)-size(13)>>
      info = <<0xF0F1F2F3F4F5F6F7F8F9::unit(8)-size(10)>>
      l = 42
      prk = <<0x9B6C18C432A7BF8F0E71C8EB88F4B30BAA2BA243::unit(8)-size(20)>>

      okm =
        <<0x085A01EA1B10F36933068B56EFA5AD81A4F14B822F5B091568A9CDD4F155FDA2C22E422478D305F3F896::unit(
            8
          )-size(l)>>

      test_case(hash, ikm, salt, info, l, prk, okm)
    end

    test "sha-1 with longer input/ouputs" do
      hash = :sha

      ikm =
        <<0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F::unit(
            8
          )-size(80)>>

      salt =
        <<0x606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAF::unit(
            8
          )-size(80)>>

      info =
        <<0xB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF::unit(
            8
          )-size(80)>>

      l = 82
      prk = <<0x8ADAE09A2A307059478D309B26C4115A224CFAF6::unit(8)-size(20)>>

      okm =
        <<0x0BD770A74D1160F7C9F12CD5912A06EBFF6ADCAE899D92191FE4305673BA2FFE8FA3F1A4E5AD79F3F334B3B202B2173C486EA37CE3D397ED034C7F9DFEB15C5E927336D0441F4C4300E2CFF0D0900B52D3B4::unit(
            8
          )-size(l)>>

      test_case(hash, ikm, salt, info, l, prk, okm)
    end

    test "sha-1 with zero length salt/info" do
      hash = :sha
      ikm = <<0x0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B::unit(8)-size(22)>>
      salt = ""
      info = ""
      l = 42
      prk = <<0xDA8C8A73C7FA77288EC6F5E7C297786AA0D32D01::unit(8)-size(20)>>

      okm =
        <<0x0AC1AF7002B3D761D1E55298DA9D0506B9AE52057220A306E07B6B87E8DF21D0EA00033DE03984D34918::unit(
            8
          )-size(l)>>

      test_case(hash, ikm, salt, info, l, prk, okm)
    end

    defp test_case(hash, ikm, salt, info, l, prk, okm) do
      key = HKDF.extract(hash, ikm, salt)
      assert key === prk

      output = HKDF.expand(hash, prk, l, info)
      assert output === okm
    end
  end
end
