// Copyright (c) 2025-2026, Brandon Lehmann
// BSD 3-Clause License (see LICENSE)

#include "test_harness.h"
#include "tinyaes/gcm.h"

#include "vectors/aes_gcm_vectors.inl"

#define VEC(arr) std::vector<uint8_t>(arr, arr + sizeof(arr))
#define EMPTY_VEC std::vector<uint8_t>()

TEST(gcm_tc1_aes128_no_plaintext_no_aad)
{
    std::vector<uint8_t> ct, tag;
    auto result = tinyaes::gcm_encrypt(VEC(gcm_tc1_key), VEC(gcm_tc1_iv), EMPTY_VEC, EMPTY_VEC, ct, tag);
    ASSERT_TRUE(result == tinyaes::Result::Success);
    ASSERT_TRUE(ct.empty());
    ASSERT_EQ(tag, VEC(gcm_tc1_tag));
}

TEST(gcm_tc2_aes128_16byte_plaintext)
{
    std::vector<uint8_t> ct, tag;
    auto result = tinyaes::gcm_encrypt(VEC(gcm_tc2_key), VEC(gcm_tc2_iv), EMPTY_VEC, VEC(gcm_tc2_plain), ct, tag);
    ASSERT_TRUE(result == tinyaes::Result::Success);
    ASSERT_EQ(ct, VEC(gcm_tc2_cipher));
    ASSERT_EQ(tag, VEC(gcm_tc2_tag));
}

TEST(gcm_tc3_aes128_64byte_plaintext)
{
    std::vector<uint8_t> ct, tag;
    auto result = tinyaes::gcm_encrypt(VEC(gcm_tc3_key), VEC(gcm_tc3_iv), EMPTY_VEC, VEC(gcm_tc3_plain), ct, tag);
    ASSERT_TRUE(result == tinyaes::Result::Success);
    ASSERT_EQ(ct, VEC(gcm_tc3_cipher));
    ASSERT_EQ(tag, VEC(gcm_tc3_tag));
}

TEST(gcm_tc4_aes128_with_aad)
{
    std::vector<uint8_t> ct, tag;
    auto result =
        tinyaes::gcm_encrypt(VEC(gcm_tc4_key), VEC(gcm_tc4_iv), VEC(gcm_tc4_aad), VEC(gcm_tc4_plain), ct, tag);
    ASSERT_TRUE(result == tinyaes::Result::Success);
    ASSERT_EQ(ct, VEC(gcm_tc4_cipher));
    ASSERT_EQ(tag, VEC(gcm_tc4_tag));
}

TEST(gcm_tc13_aes256_no_plaintext_no_aad)
{
    std::vector<uint8_t> ct, tag;
    auto result = tinyaes::gcm_encrypt(VEC(gcm_tc13_key), VEC(gcm_tc13_iv), EMPTY_VEC, EMPTY_VEC, ct, tag);
    ASSERT_TRUE(result == tinyaes::Result::Success);
    ASSERT_TRUE(ct.empty());
    ASSERT_EQ(tag, VEC(gcm_tc13_tag));
}

TEST(gcm_tc14_aes256_16byte_plaintext)
{
    std::vector<uint8_t> ct, tag;
    auto result = tinyaes::gcm_encrypt(VEC(gcm_tc14_key), VEC(gcm_tc14_iv), EMPTY_VEC, VEC(gcm_tc14_plain), ct, tag);
    ASSERT_TRUE(result == tinyaes::Result::Success);
    ASSERT_EQ(ct, VEC(gcm_tc14_cipher));
    ASSERT_EQ(tag, VEC(gcm_tc14_tag));
}

TEST(gcm_tc2_decrypt_verify)
{
    std::vector<uint8_t> pt;
    auto result =
        tinyaes::gcm_decrypt(VEC(gcm_tc2_key), VEC(gcm_tc2_iv), EMPTY_VEC, VEC(gcm_tc2_cipher), VEC(gcm_tc2_tag), pt);
    ASSERT_TRUE(result == tinyaes::Result::Success);
    ASSERT_EQ(pt, VEC(gcm_tc2_plain));
}

TEST(gcm_tc3_decrypt_verify)
{
    std::vector<uint8_t> pt;
    auto result =
        tinyaes::gcm_decrypt(VEC(gcm_tc3_key), VEC(gcm_tc3_iv), EMPTY_VEC, VEC(gcm_tc3_cipher), VEC(gcm_tc3_tag), pt);
    ASSERT_TRUE(result == tinyaes::Result::Success);
    ASSERT_EQ(pt, VEC(gcm_tc3_plain));
}

TEST(gcm_tc4_decrypt_verify)
{
    std::vector<uint8_t> pt;
    auto result = tinyaes::gcm_decrypt(VEC(gcm_tc4_key), VEC(gcm_tc4_iv), VEC(gcm_tc4_aad), VEC(gcm_tc4_cipher),
                                       VEC(gcm_tc4_tag), pt);
    ASSERT_TRUE(result == tinyaes::Result::Success);
    ASSERT_EQ(pt, VEC(gcm_tc4_plain));
}

TEST(gcm_roundtrip)
{
    std::vector<uint8_t> key(16, 0x42);
    std::vector<uint8_t> iv(12, 0x01);
    std::vector<uint8_t> aad = {0xAA, 0xBB, 0xCC};
    std::vector<uint8_t> plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f}; // "Hello"
    std::vector<uint8_t> ct, tag, pt;

    auto result = tinyaes::gcm_encrypt(key, iv, aad, plaintext, ct, tag);
    ASSERT_TRUE(result == tinyaes::Result::Success);

    result = tinyaes::gcm_decrypt(key, iv, aad, ct, tag, pt);
    ASSERT_TRUE(result == tinyaes::Result::Success);
    ASSERT_EQ(pt, plaintext);
}

#undef VEC
#undef EMPTY_VEC
