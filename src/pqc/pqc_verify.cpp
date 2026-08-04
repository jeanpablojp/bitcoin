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
    // Reject before touching the entropy state, so a failed call leaves
    // nothing behind. An empty seed would install nothing and leave the
    // vendored code to trip the guard in randombytes() instead.
    if (seed_len == 0) return false;
    if (scheme == Scheme::SLH_DSA_SHA2_128S && seed_len != SLH_DSA_SHA2_128S_SEED_SIZE) return false;

    // Both schemes draw from randombytes() while signing, and Dilithium also
    // draws during key generation. Installing the seed here covers every
    // path, which is what makes key-to-signature reproducible.
    SetDeterministicEntropy(seed, seed_len);
    switch (scheme) {
    case Scheme::SLH_DSA_SHA2_128S:
        // SPHINCS+ derives the key pair from the seed directly.
        return backend::SlhDsaSeedKeypair(pk, sk, seed);
    case Scheme::ML_DSA_44:
        // Dilithium has no seeded key generation entry point upstream, so
        // the seed only reaches it through the hook installed above.
        return backend::MlDsaKeypair(pk, sk);
    }
    return false;
}

bool Sign(Scheme scheme, unsigned char* sig, size_t* sig_len, const unsigned char* msg32, const unsigned char* sk)
{
    // Both schemes randomize part of the signature, so signing without
    // entropy is a caller mistake rather than something to abort over.
    if (!HasDeterministicEntropy()) return false;
    switch (scheme) {
    case Scheme::SLH_DSA_SHA2_128S:
        return backend::SlhDsaSign(sig, sig_len, msg32, sk);
    case Scheme::ML_DSA_44:
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
