// Copyright (c) 2025-2026, Brandon Lehmann
// BSD 3-Clause License (see LICENSE)

#include "tinyaes/ecb.h"
#include <cassert>
#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 16)
        return 0;

    // Use first 16 bytes as key, rest as plaintext (block-aligned)
    std::vector<uint8_t> key(data, data + 16);
    size_t pt_len = ((size - 16) / 16) * 16;
    if (pt_len == 0)
        return 0;

    std::vector<uint8_t> plaintext(data + 16, data + 16 + pt_len);
    std::vector<uint8_t> ct, pt;

    auto result = tinyaes::ecb_encrypt(key, plaintext, ct);
    if (result != tinyaes::Result::Success)
        return 0;

    result = tinyaes::ecb_decrypt(key, ct, pt);
    assert(result == tinyaes::Result::Success);
    assert(pt == plaintext);

    return 0;
}
