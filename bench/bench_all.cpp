// Copyright (c) 2025-2026, Brandon Lehmann
// BSD 3-Clause License (see LICENSE)

#include "tinyaes.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <vector>

static constexpr size_t BENCH_SIZE = 1024 * 1024; // 1 MiB
static constexpr int ITERATIONS = 100;

template<typename Fn> static double bench(const char *name, Fn &&fn)
{
    // Warmup
    fn();

    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < ITERATIONS; ++i)
    {
        fn();
    }
    auto end = std::chrono::high_resolution_clock::now();
    double ms = std::chrono::duration<double, std::milli>(end - start).count();
    double total_bytes = static_cast<double>(BENCH_SIZE) * ITERATIONS;
    double mib_per_sec = (total_bytes / (1024.0 * 1024.0)) / (ms / 1000.0);
    std::printf("%-30s %8.2f MiB/s  (%6.2f ms total)\n", name, mib_per_sec, ms);
    return mib_per_sec;
}

int main()
{
    std::vector<uint8_t> key_128(16, 0x42);
    std::vector<uint8_t> key_256(32, 0x42);
    std::vector<uint8_t> iv_16(16, 0x01);
    std::vector<uint8_t> iv_12(12, 0x01);
    std::vector<uint8_t> plaintext(BENCH_SIZE, 0x55);
    std::vector<uint8_t> aad = {0xAA, 0xBB, 0xCC, 0xDD};

    std::printf("TinyAES Benchmarks (%zu bytes x %d iterations)\n", BENCH_SIZE, ITERATIONS);
    std::printf("================================================================\n");

    // ECB
    bench("ECB-128 encrypt", [&]() {
        std::vector<uint8_t> ct;
        tinyaes::ecb_encrypt(key_128, plaintext, ct);
    });
    bench("ECB-256 encrypt", [&]() {
        std::vector<uint8_t> ct;
        tinyaes::ecb_encrypt(key_256, plaintext, ct);
    });

    // CBC
    bench("CBC-128 encrypt", [&]() {
        std::vector<uint8_t> ct;
        tinyaes::cbc_encrypt(key_128, iv_16, plaintext, ct);
    });
    bench("CBC-256 encrypt", [&]() {
        std::vector<uint8_t> ct;
        tinyaes::cbc_encrypt(key_256, iv_16, plaintext, ct);
    });

    // CTR
    bench("CTR-128 encrypt", [&]() {
        std::vector<uint8_t> ct;
        tinyaes::ctr_crypt(key_128, iv_16, plaintext, ct);
    });
    bench("CTR-256 encrypt", [&]() {
        std::vector<uint8_t> ct;
        tinyaes::ctr_crypt(key_256, iv_16, plaintext, ct);
    });

    // GCM
    bench("GCM-128 encrypt", [&]() {
        std::vector<uint8_t> ct, tag;
        tinyaes::gcm_encrypt(key_128, iv_12, aad, plaintext, ct, tag);
    });
    bench("GCM-256 encrypt", [&]() {
        std::vector<uint8_t> ct, tag;
        tinyaes::gcm_encrypt(key_256, iv_12, aad, plaintext, ct, tag);
    });

    return 0;
}
