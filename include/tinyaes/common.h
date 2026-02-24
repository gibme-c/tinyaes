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

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

// Symbol visibility for shared library builds
#if defined(TINYAES_SHARED)
#if defined(_WIN32) || defined(__CYGWIN__)
#if defined(TINYAES_BUILDING)
#define TINYAES_EXPORT __declspec(dllexport)
#else
#define TINYAES_EXPORT __declspec(dllimport)
#endif
#elif defined(__GNUC__) || defined(__clang__)
#define TINYAES_EXPORT __attribute__((visibility("default")))
#else
#define TINYAES_EXPORT
#endif
#else
#define TINYAES_EXPORT
#endif

// AES key sizes
#define TINYAES_KEY_128 16
#define TINYAES_KEY_192 24
#define TINYAES_KEY_256 32
#define TINYAES_BLOCK_SIZE 16
#define TINYAES_GCM_TAG_SIZE 16
#define TINYAES_GCM_IV_SIZE 12

// C error codes
#define TINYAES_SUCCESS 0
#define TINYAES_ERROR_INVALID_KEY_SIZE (-1)
#define TINYAES_ERROR_INVALID_INPUT (-2)
#define TINYAES_ERROR_INVALID_PADDING (-3)
#define TINYAES_ERROR_AUTH_FAILED (-4)
#define TINYAES_ERROR_BUFFER_TOO_SMALL (-5)

#ifdef __cplusplus
extern "C"
{
#endif

    TINYAES_EXPORT int tinyaes_constant_time_equal(const uint8_t *a, const uint8_t *b, size_t len);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus

namespace tinyaes
{

    enum class Result
    {
        Success = 0,
        InvalidKeySize = -1,
        InvalidInput = -2,
        InvalidPadding = -3,
        AuthFailed = -4,
        BufferTooSmall = -5
    };

    void secure_zero(void *ptr, size_t len);

    bool constant_time_equal(const uint8_t *a, const uint8_t *b, size_t len);

    inline bool constant_time_equal(const std::vector<uint8_t> &a, const std::vector<uint8_t> &b)
    {
        if (a.size() != b.size())
            return false;
        return constant_time_equal(a.data(), b.data(), a.size());
    }

    int generate_iv(uint8_t *out, size_t len);

} // namespace tinyaes

#endif
