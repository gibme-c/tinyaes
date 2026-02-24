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

// ARM PMULL GHASH implementation (vmull_p64)

#if defined(__aarch64__) || defined(_M_ARM64)

#include "internal/ghash.h"

#include <cstring>

#if defined(_MSC_VER)
#include <arm64_neon.h>
#else
#include <arm_neon.h>
#endif

namespace tinyaes
{
    namespace internal
    {

        // GF(2^128) multiplication using PMULL (carry-less multiply)
        static inline uint8x16_t gf128_mul_pmull(uint8x16_t a, uint8x16_t b)
        {
            // Reflect byte order for GCM convention
            poly64_t a_lo = vgetq_lane_p64(vreinterpretq_p64_u8(a), 0);
            poly64_t a_hi = vgetq_lane_p64(vreinterpretq_p64_u8(a), 1);
            poly64_t b_lo = vgetq_lane_p64(vreinterpretq_p64_u8(b), 0);
            poly64_t b_hi = vgetq_lane_p64(vreinterpretq_p64_u8(b), 1);

            // Karatsuba multiplication
            poly128_t lo = vmull_p64(a_lo, b_lo);
            poly128_t hi = vmull_p64(a_hi, b_hi);
            poly128_t mid0 = vmull_p64(a_lo, b_hi);
            poly128_t mid1 = vmull_p64(a_hi, b_lo);

            uint8x16_t lo_v = vreinterpretq_u8_p128(lo);
            uint8x16_t hi_v = vreinterpretq_u8_p128(hi);
            uint8x16_t mid = veorq_u8(vreinterpretq_u8_p128(mid0), vreinterpretq_u8_p128(mid1));

            // Combine: shift mid and XOR into lo/hi
            uint8x16_t mid_lo = vextq_u8(vdupq_n_u8(0), mid, 8);
            uint8x16_t mid_hi = vextq_u8(mid, vdupq_n_u8(0), 8);
            lo_v = veorq_u8(lo_v, mid_lo);
            hi_v = veorq_u8(hi_v, mid_hi);

            // Reduction modulo x^128 + x^7 + x^2 + x + 1
            // Using the reflected reduction polynomial 0xC2...01
            poly64_t r = (poly64_t)0xC200000000000000ULL;
            poly128_t t1 = vmull_p64(vgetq_lane_p64(vreinterpretq_p64_u8(hi_v), 0), r);
            uint8x16_t f = veorq_u8(lo_v, vreinterpretq_u8_p128(t1));
            uint8x16_t f_swap = vextq_u8(f, f, 8);
            poly128_t t2 = vmull_p64(vgetq_lane_p64(vreinterpretq_p64_u8(f_swap), 0), r);

            return veorq_u8(veorq_u8(f_swap, vreinterpretq_u8_p128(t2)), hi_v);
        }

        void ghash_arm_ce(const uint8_t H[16], const uint8_t *data, size_t data_len, uint8_t Y[16])
        {
            // GCM uses big-endian bit reflection; ARM PMULL operates on reflected bits
            // The byte reversal handles the endianness conversion
            uint8x16_t rev_mask = {15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0};
            uint8x16_t h = vqtbl1q_u8(vld1q_u8(H), rev_mask);
            uint8x16_t y = vqtbl1q_u8(vld1q_u8(Y), rev_mask);

            size_t full_blocks = data_len / 16;
            for (size_t i = 0; i < full_blocks; ++i)
            {
                uint8x16_t d = vqtbl1q_u8(vld1q_u8(data + i * 16), rev_mask);
                y = veorq_u8(y, d);
                y = gf128_mul_pmull(y, h);
            }

            size_t remainder = data_len % 16;
            if (remainder > 0)
            {
                uint8_t padded[16] = {0};
                std::memcpy(padded, data + full_blocks * 16, remainder);
                uint8x16_t d = vqtbl1q_u8(vld1q_u8(padded), rev_mask);
                y = veorq_u8(y, d);
                y = gf128_mul_pmull(y, h);
            }

            vst1q_u8(Y, vqtbl1q_u8(y, rev_mask));
        }

    } // namespace internal
} // namespace tinyaes

#endif // aarch64
