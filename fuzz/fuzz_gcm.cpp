// Copyright (c) 2025-2026, Brandon Lehmann
// BSD 3-Clause License (see LICENSE)

#include "tinyaes/gcm.h"
#include <cassert>
#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 29)
        return 0;

    // First 16 bytes = key, next 12 bytes = IV, 1 byte = AAD length, rest split
    std::vector<uint8_t> key(data, data + 16);
    std::vector<uint8_t> iv(data + 16, data + 28);
    size_t aad_len = data[28] % (size - 29 + 1);
    if (29 + aad_len > size)
        aad_len = 0;

    std::vector<uint8_t> aad(data + 29, data + 29 + aad_len);
    std::vector<uint8_t> plaintext(data + 29 + aad_len, data + size);

    std::vector<uint8_t> ct, tag, pt;

    auto result = tinyaes::gcm_encrypt(key, iv, aad, plaintext, ct, tag);
    if (result != tinyaes::Result::Success)
        return 0;

    result = tinyaes::gcm_decrypt(key, iv, aad, ct, tag, pt);
    assert(result == tinyaes::Result::Success);
    assert(pt == plaintext);

    return 0;
}
