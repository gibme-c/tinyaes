// Copyright (c) 2025-2026, Brandon Lehmann
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "tinyaes/ctr.h"
#include "internal/aes_impl.h"
#include "internal/endian.h"

#include <cstring>

namespace tinyaes
{

    Result ctr_crypt(
        const std::vector<uint8_t> &key,
        const std::vector<uint8_t> &iv,
        const std::vector<uint8_t> &input,
        std::vector<uint8_t> &output)
    {
        int rounds = internal::aes_rounds(key.size());
        if (rounds == 0)
            return Result::InvalidKeySize;
        if (iv.size() != 16)
            return Result::InvalidInput;
        if (input.empty())
            return Result::InvalidInput;

        uint32_t rk[internal::AES_MAX_RK_WORDS];
        auto key_expand = internal::get_key_expand();
        key_expand(key.data(), key.size(), rk);

        output.resize(input.size());

        uint8_t ctr[16];
        std::memcpy(ctr, iv.data(), 16);

        // Process full blocks via pipeline
        size_t full_blocks = input.size() / 16;
        size_t remainder = input.size() % 16;

        if (full_blocks > 0)
        {
            auto ctr_pipeline = internal::get_ctr_pipeline();
            ctr_pipeline(rk, rounds, input.data(), output.data(), full_blocks, ctr);
        }

        // Handle final partial block
        if (remainder > 0)
        {
            uint8_t keystream[16];
            auto encrypt_block = internal::get_encrypt_block();
            encrypt_block(rk, rounds, ctr, keystream);

            size_t offset = full_blocks * 16;
            for (size_t i = 0; i < remainder; ++i)
            {
                output[offset + i] = input[offset + i] ^ keystream[i];
            }
            secure_zero(keystream, sizeof(keystream));
        }

        secure_zero(rk, sizeof(rk));
        secure_zero(ctr, sizeof(ctr));
        return Result::Success;
    }

} // namespace tinyaes

extern "C" int tinyaes_ctr_crypt(
    const uint8_t *key,
    size_t key_len,
    const uint8_t iv[16],
    const uint8_t *input,
    size_t input_len,
    uint8_t *output,
    size_t output_len)
{
    if (!key || !iv || !input || !output)
        return TINYAES_ERROR_INVALID_INPUT;
    if (output_len < input_len)
        return TINYAES_ERROR_BUFFER_TOO_SMALL;

    std::vector<uint8_t> k(key, key + key_len);
    std::vector<uint8_t> v(iv, iv + 16);
    std::vector<uint8_t> in(input, input + input_len);
    std::vector<uint8_t> out;

    auto result = tinyaes::ctr_crypt(k, v, in, out);
    tinyaes::secure_zero(k.data(), k.size());

    if (result != tinyaes::Result::Success)
        return static_cast<int>(result);

    std::memcpy(output, out.data(), out.size());
    return TINYAES_SUCCESS;
}
