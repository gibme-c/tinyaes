// Copyright (c) 2025-2026, Brandon Lehmann
// BSD 3-Clause License (see LICENSE)

#include "test_harness.h"
#include "tinyaes/ctr.h"

#include "vectors/aes_ctr_vectors.inl"

#define VEC(arr) std::vector<uint8_t>(arr, arr + sizeof(arr))

TEST(ctr_aes128_encrypt)
{
    std::vector<uint8_t> ct;
    auto result = tinyaes::ctr_crypt(VEC(ctr_128_key), VEC(ctr_128_iv), VEC(ctr_128_plain), ct);
    ASSERT_TRUE(result == tinyaes::Result::Success);
    ASSERT_EQ(ct, VEC(ctr_128_cipher));
}

TEST(ctr_aes128_decrypt)
{
    std::vector<uint8_t> pt;
    auto result = tinyaes::ctr_crypt(VEC(ctr_128_key), VEC(ctr_128_iv), VEC(ctr_128_cipher), pt);
    ASSERT_TRUE(result == tinyaes::Result::Success);
    ASSERT_EQ(pt, VEC(ctr_128_plain));
}

TEST(ctr_aes192_encrypt)
{
    std::vector<uint8_t> ct;
    auto result = tinyaes::ctr_crypt(VEC(ctr_192_key), VEC(ctr_192_iv), VEC(ctr_192_plain), ct);
    ASSERT_TRUE(result == tinyaes::Result::Success);
    ASSERT_EQ(ct, VEC(ctr_192_cipher));
}

TEST(ctr_aes256_encrypt)
{
    std::vector<uint8_t> ct;
    auto result = tinyaes::ctr_crypt(VEC(ctr_256_key), VEC(ctr_256_iv), VEC(ctr_256_plain), ct);
    ASSERT_TRUE(result == tinyaes::Result::Success);
    ASSERT_EQ(ct, VEC(ctr_256_cipher));
}

TEST(ctr_partial_block)
{
    // Encrypt 7 bytes with CTR — should handle partial block
    std::vector<uint8_t> key(16, 0x42);
    std::vector<uint8_t> iv(16, 0x00);
    std::vector<uint8_t> plaintext = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    std::vector<uint8_t> ct, pt;

    auto result = tinyaes::ctr_crypt(key, iv, plaintext, ct);
    ASSERT_TRUE(result == tinyaes::Result::Success);
    ASSERT_TRUE(ct.size() == 7);

    // Decrypt should recover original
    result = tinyaes::ctr_crypt(key, iv, ct, pt);
    ASSERT_TRUE(result == tinyaes::Result::Success);
    ASSERT_EQ(pt, plaintext);
}

TEST(ctr_roundtrip_multi_block)
{
    std::vector<uint8_t> key(32, 0xAB);
    std::vector<uint8_t> iv(16, 0x01);
    std::vector<uint8_t> plaintext(100, 0x55); // 6 full blocks + 4 remainder
    std::vector<uint8_t> ct, pt;

    auto result = tinyaes::ctr_crypt(key, iv, plaintext, ct);
    ASSERT_TRUE(result == tinyaes::Result::Success);
    ASSERT_TRUE(ct.size() == 100);

    result = tinyaes::ctr_crypt(key, iv, ct, pt);
    ASSERT_TRUE(result == tinyaes::Result::Success);
    ASSERT_EQ(pt, plaintext);
}

#undef VEC
