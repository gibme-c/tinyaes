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
            return Result::InvalidIVSize;
        if (input.empty())
            return Result::InvalidInputSize;

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
        return Result::Ok;
    }

    // Build a 16-byte IV from 12-byte nonce + 4-byte counter starting at 1
    static std::vector<uint8_t> nonce_to_iv(const std::vector<uint8_t> &nonce)
    {
        std::vector<uint8_t> iv(16, 0);
        std::memcpy(iv.data(), nonce.data(), 12);
        iv[15] = 1; // big-endian counter = 1
        return iv;
    }

    Result ctr_encrypt(
        const std::vector<uint8_t> &key,
        const std::vector<uint8_t> &nonce,
        const std::vector<uint8_t> &plaintext,
        std::vector<uint8_t> &ciphertext)
    {
        if (nonce.size() != 12)
            return Result::InvalidNonceSize;
        auto iv = nonce_to_iv(nonce);
        return ctr_crypt(key, iv, plaintext, ciphertext);
    }

    Result ctr_encrypt(
        const std::vector<uint8_t> &key,
        const std::vector<uint8_t> &plaintext,
        std::vector<uint8_t> &nonce_and_ciphertext)
    {
        auto nonce = generate_nonce();
        if (nonce.empty())
            return Result::InternalError;

        std::vector<uint8_t> ct;
        auto result = ctr_encrypt(key, nonce, plaintext, ct);
        if (result != Result::Ok)
            return result;

        nonce_and_ciphertext.resize(12 + ct.size());
        std::memcpy(nonce_and_ciphertext.data(), nonce.data(), 12);
        std::memcpy(nonce_and_ciphertext.data() + 12, ct.data(), ct.size());
        return Result::Ok;
    }

    Result ctr_decrypt(
        const std::vector<uint8_t> &key,
        const std::vector<uint8_t> &nonce,
        const std::vector<uint8_t> &ciphertext,
        std::vector<uint8_t> &plaintext)
    {
        if (nonce.size() != 12)
            return Result::InvalidNonceSize;
        auto iv = nonce_to_iv(nonce);
        return ctr_crypt(key, iv, ciphertext, plaintext);
    }

    Result ctr_decrypt(
        const std::vector<uint8_t> &key,
        const std::vector<uint8_t> &nonce_and_ciphertext,
        std::vector<uint8_t> &plaintext)
    {
        if (nonce_and_ciphertext.size() < 13)
            return Result::InvalidInputSize;

        std::vector<uint8_t> nonce(nonce_and_ciphertext.begin(), nonce_and_ciphertext.begin() + 12);
        std::vector<uint8_t> ct(nonce_and_ciphertext.begin() + 12, nonce_and_ciphertext.end());
        return ctr_decrypt(key, nonce, ct, plaintext);
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
        return TINYAES_INVALID_INPUT_SIZE;
    if (output_len < input_len)
        return TINYAES_INVALID_INPUT_SIZE;

    std::vector<uint8_t> k(key, key + key_len);
    std::vector<uint8_t> v(iv, iv + 16);
    std::vector<uint8_t> in(input, input + input_len);
    std::vector<uint8_t> out;

    auto result = tinyaes::ctr_crypt(k, v, in, out);
    tinyaes::secure_zero(k.data(), k.size());
    tinyaes::secure_zero(in.data(), in.size());

    if (result != tinyaes::Result::Ok)
        return static_cast<int>(result);

    std::memcpy(output, out.data(), out.size());
    return TINYAES_OK;
}

extern "C" int tinyaes_ctr_encrypt(
    const uint8_t *key,
    size_t key_len,
    const uint8_t *nonce,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *ciphertext,
    size_t ciphertext_len)
{
    if (!key || !nonce || !plaintext || !ciphertext)
        return TINYAES_INVALID_INPUT_SIZE;
    if (ciphertext_len < plaintext_len)
        return TINYAES_INVALID_INPUT_SIZE;

    std::vector<uint8_t> k(key, key + key_len);
    std::vector<uint8_t> n(nonce, nonce + 12);
    std::vector<uint8_t> pt(plaintext, plaintext + plaintext_len);
    std::vector<uint8_t> ct;

    auto result = tinyaes::ctr_encrypt(k, n, pt, ct);
    tinyaes::secure_zero(k.data(), k.size());
    tinyaes::secure_zero(pt.data(), pt.size());

    if (result != tinyaes::Result::Ok)
        return static_cast<int>(result);

    std::memcpy(ciphertext, ct.data(), ct.size());
    return TINYAES_OK;
}

extern "C" int tinyaes_ctr_decrypt(
    const uint8_t *key,
    size_t key_len,
    const uint8_t *nonce,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    uint8_t *plaintext,
    size_t plaintext_len)
{
    if (!key || !nonce || !ciphertext || !plaintext)
        return TINYAES_INVALID_INPUT_SIZE;
    if (plaintext_len < ciphertext_len)
        return TINYAES_INVALID_INPUT_SIZE;

    std::vector<uint8_t> k(key, key + key_len);
    std::vector<uint8_t> n(nonce, nonce + 12);
    std::vector<uint8_t> ct(ciphertext, ciphertext + ciphertext_len);
    std::vector<uint8_t> pt;

    auto result = tinyaes::ctr_decrypt(k, n, ct, pt);
    tinyaes::secure_zero(k.data(), k.size());

    if (result != tinyaes::Result::Ok)
    {
        tinyaes::secure_zero(pt.data(), pt.size());
        return static_cast<int>(result);
    }

    std::memcpy(plaintext, pt.data(), pt.size());
    tinyaes::secure_zero(pt.data(), pt.size());
    return TINYAES_OK;
}
