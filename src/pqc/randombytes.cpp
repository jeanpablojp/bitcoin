// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Both vendored reference implementations call randombytes(), and both ship
// their own definition of it, so exactly one has to be kept: this one.
// Dilithium draws in key generation, SPHINCS+ in signing, and this Dilithium
// copy also draws while signing because its config.h enables randomized
// signing.
//
// Verification, the only path consensus takes, draws nothing. Rather than
// pull an RNG into the consensus library for a path it never reaches, this
// aborts if it is ever reached with no entropy installed, which only tests
// and vector generation install. The entry points in pqc_verify.h check for
// it first, so the abort is left for vendored code drawing randomness
// nobody arranged for, not for ordinary misuse. The state is a plain
// global: nothing that touches it runs on more than one thread.

#include <pqc/pqc_verify.h>

#include <crypto/sha256.h>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <vector>

namespace {
std::vector<unsigned char> g_seed;
uint64_t g_counter{0};
} // namespace

namespace pqc {

void SetDeterministicEntropy(const unsigned char* seed, size_t seed_len)
{
    g_seed.assign(seed, seed + seed_len);
    g_counter = 0;
}

bool HasDeterministicEntropy()
{
    return !g_seed.empty();
}

} // namespace pqc

extern "C" void randombytes(uint8_t* out, size_t outlen)
{
    // Reaching this without installed entropy means something tried to
    // generate a key or sign, which no production path here does.
    assert(!g_seed.empty());
    while (outlen > 0) {
        unsigned char block[CSHA256::OUTPUT_SIZE];
        unsigned char counter[8];
        for (int i = 0; i < 8; ++i) counter[i] = (g_counter >> (8 * i)) & 0xff;
        CSHA256().Write(g_seed.data(), g_seed.size()).Write(counter, sizeof(counter)).Finalize(block);
        ++g_counter;
        const size_t take{std::min(outlen, sizeof(block))};
        std::memcpy(out, block, take);
        out += take;
        outlen -= take;
    }
}
