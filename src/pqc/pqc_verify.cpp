// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pqc/pqc_verify.h>

extern "C" {
#include <pqc/sphincsplus/api.h>
}

#include <cassert>

namespace pqc {

bool IsKnownScheme(uint8_t scheme_byte)
{
    // ML-DSA-44 is not wired up yet: its byte is known to the design but
    // not verifiable by this build, so Verify() fails it.
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

bool SeedKeypair(Scheme scheme, unsigned char* pk, unsigned char* sk, const unsigned char* seed)
{
    switch (scheme) {
    case Scheme::SLH_DSA_SHA2_128S:
        return crypto_sign_seed_keypair(pk, sk, seed) == 0;
    case Scheme::ML_DSA_44:
        return false; // not wired up yet
    }
    return false;
}

bool Sign(Scheme scheme, unsigned char* sig, size_t* sig_len, const unsigned char* msg32, const unsigned char* sk)
{
    switch (scheme) {
    case Scheme::SLH_DSA_SHA2_128S:
        return crypto_sign_signature(sig, sig_len, msg32, 32, sk) == 0;
    case Scheme::ML_DSA_44:
        return false; // not wired up yet
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
        return crypto_sign_verify(sig, sig_len, msg32, 32, pubkey) == 0;
    case Scheme::ML_DSA_44:
        return false; // not wired up yet
    }
    return false;
}

} // namespace pqc
