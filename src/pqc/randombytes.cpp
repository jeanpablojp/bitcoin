// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// The vendored Dilithium calls randombytes() and ships its own definition of
// it, which is dropped for this one. It draws in key generation, and this
// copy also draws while signing because its config.h enables randomized
// signing. The vendored SLH-DSA draws nothing: it takes its key seeds as
// arguments and signs deterministically, so nothing below is on its path.
//
// Verification, the only path consensus takes, draws nothing. Rather than
// pull an RNG into the consensus library for a path it never reaches, this
// aborts if it is ever reached with no entropy installed, which only tests
// and vector generation install. The entry points in pqc_verify.h check for
// it first, so the abort is left for vendored code drawing randomness
// nobody arranged for, not for ordinary misuse.
//
// The state is a single global, so a caller reachable from more than one
// thread has to hold EntropyLock across the whole install-generate-sign
// sequence. Locking each access would not help: the sequence is what needs
// to be atomic, since another thread reinstalling or wiping between the
// install and the draw would either change the result or trip the guard.

#include <pqc/pqc_verify.h>

#include <crypto/sha256.h>
#include <support/cleanse.h>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <vector>

namespace {
std::vector<unsigned char> g_seed;
uint64_t g_counter{0};
std::mutex g_entropy_mutex;
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

void ClearDeterministicEntropy()
{
    // Nothing installed is the ordinary case now that only Dilithium draws
    // from here, and an empty vector has no buffer to hand to memset.
    if (g_seed.empty()) return;
    memory_cleanse(g_seed.data(), g_seed.size());
    g_seed.clear();
    g_counter = 0;
}

EntropyLock::EntropyLock() { g_entropy_mutex.lock(); }

EntropyLock::~EntropyLock()
{
    ClearDeterministicEntropy();
    g_entropy_mutex.unlock();
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
