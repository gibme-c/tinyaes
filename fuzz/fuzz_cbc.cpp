// Copyright (c) 2025-2026, Brandon Lehmann
// BSD 3-Clause License (see LICENSE)

#include "tinyaes/cbc.h"
#include <cassert>
#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 32)
        return 0;

    // First 16 bytes = key, next 16 bytes = IV, rest = plaintext
    std::vector<uint8_t> key(data, data + 16);
    std::vector<uint8_t> iv(data + 16, data + 32);

    size_t remaining = size - 32;
    if (remaining == 0)
        return 0;

    // Use PKCS#7 which accepts any length
    std::vector<uint8_t> plaintext(data + 32, data + size);
    std::vector<uint8_t> ct, pt;

    auto result = tinyaes::cbc_encrypt_pkcs7(key, iv, plaintext, ct);
    if (result != tinyaes::Result::Success)
        return 0;

    result = tinyaes::cbc_decrypt_pkcs7(key, iv, ct, pt);
    assert(result == tinyaes::Result::Success);
    assert(pt == plaintext);

    return 0;
}
