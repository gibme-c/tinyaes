// Copyright (c) 2025-2026, Brandon Lehmann
// BSD 3-Clause License (see LICENSE)

#include "test_harness.h"
#include "tinyaes/cbc.h"

#include "vectors/aes_cbc_vectors.inl"

#define VEC(arr) std::vector<uint8_t>(arr, arr + sizeof(arr))

TEST(cbc_aes128_encrypt)
{
    std::vector<uint8_t> ct;
    auto result = tinyaes::cbc_encrypt(VEC(cbc_128_key), VEC(cbc_128_iv), VEC(cbc_128_plain), ct);
    ASSERT_TRUE(result == tinyaes::Result::Success);
    ASSERT_EQ(ct, VEC(cbc_128_cipher));
}

TEST(cbc_aes128_decrypt)
{
    std::vector<uint8_t> pt;
    auto result = tinyaes::cbc_decrypt(VEC(cbc_128_key), VEC(cbc_128_iv), VEC(cbc_128_cipher), pt);
    ASSERT_TRUE(result == tinyaes::Result::Success);
    ASSERT_EQ(pt, VEC(cbc_128_plain));
}

TEST(cbc_aes192_encrypt)
{
    std::vector<uint8_t> ct;
    auto result = tinyaes::cbc_encrypt(VEC(cbc_192_key), VEC(cbc_192_iv), VEC(cbc_192_plain), ct);
    ASSERT_TRUE(result == tinyaes::Result::Success);
    ASSERT_EQ(ct, VEC(cbc_192_cipher));
}

TEST(cbc_aes192_decrypt)
{
    std::vector<uint8_t> pt;
    auto result = tinyaes::cbc_decrypt(VEC(cbc_192_key), VEC(cbc_192_iv), VEC(cbc_192_cipher), pt);
    ASSERT_TRUE(result == tinyaes::Result::Success);
    ASSERT_EQ(pt, VEC(cbc_192_plain));
}

TEST(cbc_aes256_encrypt)
{
    std::vector<uint8_t> ct;
    auto result = tinyaes::cbc_encrypt(VEC(cbc_256_key), VEC(cbc_256_iv), VEC(cbc_256_plain), ct);
    ASSERT_TRUE(result == tinyaes::Result::Success);
    ASSERT_EQ(ct, VEC(cbc_256_cipher));
}

TEST(cbc_aes256_decrypt)
{
    std::vector<uint8_t> pt;
    auto result = tinyaes::cbc_decrypt(VEC(cbc_256_key), VEC(cbc_256_iv), VEC(cbc_256_cipher), pt);
    ASSERT_TRUE(result == tinyaes::Result::Success);
    ASSERT_EQ(pt, VEC(cbc_256_plain));
}

TEST(cbc_roundtrip_pkcs7)
{
    std::vector<uint8_t> key(16, 0x42);
    std::vector<uint8_t> iv(16, 0x00);
    std::vector<uint8_t> plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f}; // "Hello"
    std::vector<uint8_t> ct, pt;

    auto result = tinyaes::cbc_encrypt_pkcs7(key, iv, plaintext, ct);
    ASSERT_TRUE(result == tinyaes::Result::Success);
    ASSERT_TRUE(ct.size() == 16); // 5 bytes + 11 padding = 16

    result = tinyaes::cbc_decrypt_pkcs7(key, iv, ct, pt);
    ASSERT_TRUE(result == tinyaes::Result::Success);
    ASSERT_EQ(pt, plaintext);
}

TEST(cbc_invalid_iv_size)
{
    std::vector<uint8_t> key(16, 0), iv(15, 0), pt(16, 0), ct;
    ASSERT_TRUE(tinyaes::cbc_encrypt(key, iv, pt, ct) == tinyaes::Result::InvalidInput);
}

#undef VEC
