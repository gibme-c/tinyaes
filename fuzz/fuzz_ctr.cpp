// Copyright (c) 2025-2026, Brandon Lehmann
// BSD 3-Clause License (see LICENSE)

#include "tinyaes/ctr.h"
#include <cassert>
#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 33)
        return 0;

    // First 16 bytes = key, next 16 bytes = IV, rest = plaintext
    std::vector<uint8_t> key(data, data + 16);
    std::vector<uint8_t> iv(data + 16, data + 32);
    std::vector<uint8_t> plaintext(data + 32, data + size);
    std::vector<uint8_t> ct, pt;

    auto result = tinyaes::ctr_crypt(key, iv, plaintext, ct);
    if (result != tinyaes::Result::Success)
        return 0;

    result = tinyaes::ctr_crypt(key, iv, ct, pt);
    assert(result == tinyaes::Result::Success);
    assert(pt == plaintext);

    return 0;
}
