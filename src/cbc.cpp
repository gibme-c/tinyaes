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

#include "tinyaes/cbc.h"
#include "internal/aes_impl.h"

#include <cstring>

namespace tinyaes
{

    Result cbc_encrypt(
        const std::vector<uint8_t> &key,
        const std::vector<uint8_t> &iv,
        const std::vector<uint8_t> &plaintext,
        std::vector<uint8_t> &ciphertext)
    {
        int rounds = internal::aes_rounds(key.size());
        if (rounds == 0)
            return Result::InvalidKeySize;
        if (iv.size() != 16)
            return Result::InvalidInput;
        if (plaintext.empty() || (plaintext.size() % 16) != 0)
            return Result::InvalidInput;

        uint32_t rk[internal::AES_MAX_RK_WORDS];
        auto key_expand = internal::get_key_expand();
        key_expand(key.data(), key.size(), rk);

        auto encrypt_block = internal::get_encrypt_block();
        ciphertext.resize(plaintext.size());

        uint8_t block[16];
        std::memcpy(block, iv.data(), 16);

        for (size_t i = 0; i < plaintext.size(); i += 16)
        {
            // XOR plaintext block with previous ciphertext (or IV)
            for (int j = 0; j < 16; ++j)
            {
                block[j] ^= plaintext[i + static_cast<size_t>(j)];
            }
            encrypt_block(rk, rounds, block, ciphertext.data() + i);
            std::memcpy(block, ciphertext.data() + i, 16);
        }

        secure_zero(rk, sizeof(rk));
        secure_zero(block, sizeof(block));
        return Result::Success;
    }

    Result cbc_decrypt(
        const std::vector<uint8_t> &key,
        const std::vector<uint8_t> &iv,
        const std::vector<uint8_t> &ciphertext,
        std::vector<uint8_t> &plaintext)
    {
        int rounds = internal::aes_rounds(key.size());
        if (rounds == 0)
            return Result::InvalidKeySize;
        if (iv.size() != 16)
            return Result::InvalidInput;
        if (ciphertext.empty() || (ciphertext.size() % 16) != 0)
            return Result::InvalidInput;

        uint32_t rk[internal::AES_MAX_RK_WORDS];
        auto key_expand = internal::get_key_expand();
        key_expand(key.data(), key.size(), rk);

        auto decrypt_block = internal::get_decrypt_block();
        plaintext.resize(ciphertext.size());

        const uint8_t *prev = iv.data();

        for (size_t i = 0; i < ciphertext.size(); i += 16)
        {
            decrypt_block(rk, rounds, ciphertext.data() + i, plaintext.data() + i);
            // XOR with previous ciphertext block (or IV)
            for (int j = 0; j < 16; ++j)
            {
                plaintext[i + static_cast<size_t>(j)] ^= prev[j];
            }
            prev = ciphertext.data() + i;
        }

        secure_zero(rk, sizeof(rk));
        return Result::Success;
    }

    // PKCS#7 padding: append N bytes of value N where N = 16 - (len % 16)
    // If input is already block-aligned, a full padding block is added.
    Result cbc_encrypt_pkcs7(
        const std::vector<uint8_t> &key,
        const std::vector<uint8_t> &iv,
        const std::vector<uint8_t> &plaintext,
        std::vector<uint8_t> &ciphertext)
    {
        size_t pad_len = 16 - (plaintext.size() % 16);
        std::vector<uint8_t> padded(plaintext.size() + pad_len);
        std::memcpy(padded.data(), plaintext.data(), plaintext.size());
        std::memset(padded.data() + plaintext.size(), static_cast<int>(pad_len), pad_len);

        auto result = cbc_encrypt(key, iv, padded, ciphertext);
        secure_zero(padded.data(), padded.size());
        return result;
    }

    // Constant-time PKCS#7 unpadding
    Result cbc_decrypt_pkcs7(
        const std::vector<uint8_t> &key,
        const std::vector<uint8_t> &iv,
        const std::vector<uint8_t> &ciphertext,
        std::vector<uint8_t> &plaintext)
    {
        std::vector<uint8_t> decrypted;
        auto result = cbc_decrypt(key, iv, ciphertext, decrypted);
        if (result != Result::Success)
            return result;

        if (decrypted.empty())
            return Result::InvalidPadding;

        // Constant-time PKCS#7 validation: scan entire last block
        uint8_t pad_val = decrypted.back();
        if (pad_val == 0 || pad_val > 16)
            return Result::InvalidPadding;

        // Verify all padding bytes match (constant-time)
        volatile uint8_t bad = 0;
        size_t start = decrypted.size() - pad_val;
        for (size_t i = start; i < decrypted.size(); ++i)
        {
            bad |= static_cast<uint8_t>(decrypted[i] ^ pad_val);
        }

        if (bad != 0)
        {
            secure_zero(decrypted.data(), decrypted.size());
            return Result::InvalidPadding;
        }

        plaintext.assign(decrypted.begin(), decrypted.begin() + static_cast<ptrdiff_t>(start));
        secure_zero(decrypted.data(), decrypted.size());
        return Result::Success;
    }

} // namespace tinyaes

// C API implementations
extern "C" int tinyaes_cbc_encrypt(
    const uint8_t *key,
    size_t key_len,
    const uint8_t iv[16],
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *ciphertext,
    size_t ciphertext_len)
{
    if (!key || !iv || !plaintext || !ciphertext)
        return TINYAES_ERROR_INVALID_INPUT;
    if (ciphertext_len < plaintext_len)
        return TINYAES_ERROR_BUFFER_TOO_SMALL;

    std::vector<uint8_t> k(key, key + key_len);
    std::vector<uint8_t> v(iv, iv + 16);
    std::vector<uint8_t> pt(plaintext, plaintext + plaintext_len);
    std::vector<uint8_t> ct;

    auto result = tinyaes::cbc_encrypt(k, v, pt, ct);
    tinyaes::secure_zero(k.data(), k.size());

    if (result != tinyaes::Result::Success)
        return static_cast<int>(result);

    std::memcpy(ciphertext, ct.data(), ct.size());
    return TINYAES_SUCCESS;
}

extern "C" int tinyaes_cbc_decrypt(
    const uint8_t *key,
    size_t key_len,
    const uint8_t iv[16],
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    uint8_t *plaintext,
    size_t plaintext_len)
{
    if (!key || !iv || !ciphertext || !plaintext)
        return TINYAES_ERROR_INVALID_INPUT;
    if (plaintext_len < ciphertext_len)
        return TINYAES_ERROR_BUFFER_TOO_SMALL;

    std::vector<uint8_t> k(key, key + key_len);
    std::vector<uint8_t> v(iv, iv + 16);
    std::vector<uint8_t> ct(ciphertext, ciphertext + ciphertext_len);
    std::vector<uint8_t> pt;

    auto result = tinyaes::cbc_decrypt(k, v, ct, pt);
    tinyaes::secure_zero(k.data(), k.size());

    if (result != tinyaes::Result::Success)
        return static_cast<int>(result);

    std::memcpy(plaintext, pt.data(), pt.size());
    return TINYAES_SUCCESS;
}

extern "C" int tinyaes_cbc_encrypt_pkcs7(
    const uint8_t *key,
    size_t key_len,
    const uint8_t iv[16],
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *ciphertext,
    size_t *ciphertext_len)
{
    if (!key || !iv || !plaintext || !ciphertext || !ciphertext_len)
        return TINYAES_ERROR_INVALID_INPUT;

    size_t padded_len = plaintext_len + (16 - (plaintext_len % 16));
    if (*ciphertext_len < padded_len)
    {
        *ciphertext_len = padded_len;
        return TINYAES_ERROR_BUFFER_TOO_SMALL;
    }

    std::vector<uint8_t> k(key, key + key_len);
    std::vector<uint8_t> v(iv, iv + 16);
    std::vector<uint8_t> pt(plaintext, plaintext + plaintext_len);
    std::vector<uint8_t> ct;

    auto result = tinyaes::cbc_encrypt_pkcs7(k, v, pt, ct);
    tinyaes::secure_zero(k.data(), k.size());

    if (result != tinyaes::Result::Success)
        return static_cast<int>(result);

    std::memcpy(ciphertext, ct.data(), ct.size());
    *ciphertext_len = ct.size();
    return TINYAES_SUCCESS;
}

extern "C" int tinyaes_cbc_decrypt_pkcs7(
    const uint8_t *key,
    size_t key_len,
    const uint8_t iv[16],
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    uint8_t *plaintext,
    size_t *plaintext_len)
{
    if (!key || !iv || !ciphertext || !plaintext || !plaintext_len)
        return TINYAES_ERROR_INVALID_INPUT;

    std::vector<uint8_t> k(key, key + key_len);
    std::vector<uint8_t> v(iv, iv + 16);
    std::vector<uint8_t> ct(ciphertext, ciphertext + ciphertext_len);
    std::vector<uint8_t> pt;

    auto result = tinyaes::cbc_decrypt_pkcs7(k, v, ct, pt);
    tinyaes::secure_zero(k.data(), k.size());

    if (result != tinyaes::Result::Success)
        return static_cast<int>(result);

    if (*plaintext_len < pt.size())
    {
        *plaintext_len = pt.size();
        tinyaes::secure_zero(pt.data(), pt.size());
        return TINYAES_ERROR_BUFFER_TOO_SMALL;
    }

    std::memcpy(plaintext, pt.data(), pt.size());
    *plaintext_len = pt.size();
    tinyaes::secure_zero(pt.data(), pt.size());
    return TINYAES_SUCCESS;
}
