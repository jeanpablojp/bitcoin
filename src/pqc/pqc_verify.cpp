// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pqc/pqc_verify.h>

#include <pqc/pqc_backends.h>

#include <cassert>

namespace pqc {

bool IsKnownScheme(uint8_t scheme_byte)
{
    return scheme_byte == static_cast<uint8_t>(Scheme::ML_DSA_44) ||
           scheme_byte == static_cast<uint8_t>(Scheme::SLH_DSA_SHA2_128S);
}

size_t PubKeySize(Scheme scheme)
{
    switch (scheme) {
    case Scheme::ML_DSA_44: return ML_DSA_44_PUBKEY_SIZE;
    case Scheme::SLH_DSA_SHA2_128S: return SLH_DSA_SHA2_128S_PUBKEY_SIZE;
    }
    assert(false);
}

size_t SigSize(Scheme scheme)
{
    switch (scheme) {
    case Scheme::ML_DSA_44: return ML_DSA_44_SIG_SIZE;
    case Scheme::SLH_DSA_SHA2_128S: return SLH_DSA_SHA2_128S_SIG_SIZE;
    }
    assert(false);
}

bool SeedKeypair(Scheme scheme, unsigned char* pk, unsigned char* sk, const unsigned char* seed, size_t seed_len)
{
    // Both checks run before the ML-DSA path installs anything, so a
    // rejected call leaves no entropy state behind. An empty seed would
    // install nothing and leave Dilithium to trip the guard in
    // randombytes() instead.
    if (seed_len == 0) return false;
    if (scheme == Scheme::SLH_DSA_SHA2_128S && seed_len != SLH_DSA_SHA2_128S_SEED_SIZE) return false;

    switch (scheme) {
    case Scheme::SLH_DSA_SHA2_128S:
        // SLH-DSA takes the seed as its three key seeds and draws nothing
        // else, in key generation or in signing, so the hook stays out of it.
        return backend::SlhDsaSeedKeypair(pk, sk, seed);
    case Scheme::ML_DSA_44:
        // Dilithium has no seeded key generation entry point upstream, and
        // this copy also draws while signing, so the seed reaches it only
        // through the hook. Installing it here is what makes key-to-signature
        // reproducible.
        SetDeterministicEntropy(seed, seed_len);
        return backend::MlDsaKeypair(pk, sk);
    }
    return false;
}

bool Sign(Scheme scheme, unsigned char* sig, size_t* sig_len, const unsigned char* msg32, const unsigned char* sk)
{
    switch (scheme) {
    case Scheme::SLH_DSA_SHA2_128S:
        // Deterministic under FIPS 205, so there is no entropy to require.
        return backend::SlhDsaSign(sig, sig_len, msg32, sk);
    case Scheme::ML_DSA_44:
        // This copy randomizes the signature, so signing with nothing
        // installed is a caller mistake rather than something to abort over.
        if (!HasDeterministicEntropy()) return false;
        return backend::MlDsaSign(sig, sig_len, msg32, sk);
    }
    return false;
}

bool Verify(Scheme scheme,
            const unsigned char* pubkey, size_t pubkey_len,
            const unsigned char* msg32,
            const unsigned char* sig, size_t sig_len)
{
    if (pubkey_len != PubKeySize(scheme) || sig_len != SigSize(scheme)) return false;
    switch (scheme) {
    case Scheme::SLH_DSA_SHA2_128S:
        return backend::SlhDsaVerify(sig, sig_len, msg32, pubkey);
    case Scheme::ML_DSA_44:
        return backend::MlDsaVerify(sig, sig_len, msg32, pubkey);
    }
    return false;
}

} // namespace pqc
