// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Cost of one passing OP_CHECKPQSIG against one passing tapscript
// OP_CHECKSIG, which is what calibrates the validation weight the
// interpreter charges: BIP 342 prices a passing Schnorr check at 50 units,
// so a scheme costing N times as much should cost around 50*N.
//
// Each benchmark covers the work its opcode repeats per check and nothing
// else. On the Schnorr side that is the public key parse and the
// verification, both inside VerifySchnorr. On the PQ side it is the tagged
// hash of the public key and the verification. The sighash is left out of
// both, which is not neutral: adding the same term to both sides of a
// ratio above one pulls it toward one, so leaving it out reads the ratio
// high, and the constant with it.
//
// The pubkey hash belongs in the per-check cost even though the public key
// is already paid for by the witness size term of the budget. A leaf that
// repeats the check carries the key once and hashes it once per check, so
// that work scales with checks rather than with witness bytes, which is
// exactly what the constant has to cover.

#include <bench/bench.h>
#include <hash.h>
#include <key.h>
#include <pqc/pqc_verify.h>
#include <pubkey.h>
#include <uint256.h>

#include <cassert>
#include <cstddef>
#include <vector>

namespace {

void PQCCheckBench(benchmark::Bench& bench, pqc::Scheme scheme)
{
    // Any seed works; SLH-DSA needs its exact length and ML-DSA takes a
    // prefix of the stream, so one buffer serves both schemes. Measured
    // across four keys, the spread is the same size as the run-to-run
    // noise, so a fixed key is representative.
    const std::vector<unsigned char> seed(pqc::SLH_DSA_SHA2_128S_SEED_SIZE, 0x2a);
    const size_t seckey_size{scheme == pqc::Scheme::ML_DSA_44 ? pqc::ML_DSA_44_SECKEY_SIZE : pqc::SLH_DSA_SHA2_128S_SECKEY_SIZE};

    std::vector<unsigned char> pubkey(pqc::PubKeySize(scheme));
    std::vector<unsigned char> seckey(seckey_size);
    std::vector<unsigned char> sig(pqc::SigSize(scheme));
    const uint256 msg{uint256::ONE};

    {
        const pqc::EntropyLock entropy_lock;
        bool ok{pqc::SeedKeypair(scheme, pubkey.data(), seckey.data(), seed.data(), seed.size())};
        assert(ok);
        size_t sig_len{0};
        ok = pqc::Sign(scheme, sig.data(), &sig_len, msg.begin(), seckey.data());
        assert(ok && sig_len == sig.size());
    }

    // The interpreter keeps the tagged midstate in a static and copies it
    // per check, so the bench does the same. The signature verified is a
    // valid one, which is the worst case: an invalid signature can be
    // rejected before the verifier has done all its work.
    const HashWriter hasher{TaggedHash("PQPubKeyHash")};
    bench.unit("check").run([&] {
        HashWriter ss{hasher};
        ss.write(MakeByteSpan(pubkey));
        const uint256 pubkey_hash{ss.GetSHA256()};
        assert(pubkey_hash != uint256::ZERO);
        const bool ok{pqc::Verify(scheme, pubkey.data(), pubkey.size(), msg.begin(), sig.data(), sig.size())};
        assert(ok);
    });
}

} // namespace

static void PQCCheckSLHDSA(benchmark::Bench& bench) { PQCCheckBench(bench, pqc::Scheme::SLH_DSA_SHA2_128S); }
static void PQCCheckMLDSA(benchmark::Bench& bench) { PQCCheckBench(bench, pqc::Scheme::ML_DSA_44); }

// The baseline the 50-unit sigop cost comes from: one passing tapscript
// OP_CHECKSIG over the same 32-byte message.
static void PQCCheckSchnorrBaseline(benchmark::Bench& bench)
{
    ECC_Context ecc_context{};

    CKey privkey;
    privkey.Set(uint256::ONE.begin(), uint256::ONE.end(), /*fCompressedIn=*/true);
    const XOnlyPubKey xonly_pubkey{privkey.GetPubKey()};

    const uint256 msg{uint256::ONE};
    std::vector<unsigned char> sig(64);
    const bool ok{privkey.SignSchnorr(msg, sig, /*merkle_root=*/nullptr, /*aux=*/uint256::ZERO)};
    assert(ok);

    bench.unit("check").run([&] {
        assert(xonly_pubkey.VerifySchnorr(msg, sig));
    });
}

BENCHMARK(PQCCheckSLHDSA);
BENCHMARK(PQCCheckMLDSA);
BENCHMARK(PQCCheckSchnorrBaseline);
