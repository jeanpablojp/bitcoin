// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ML-DSA-44 backend, in its own translation unit for the reason given at the
// top of slh_dsa.cpp: including sign.h drags in params.h, whose macros
// would rewrite identifiers in any file that shares it.

#include <pqc/pqc_backends.h>

extern "C" {
#include <pqc/dilithium/sign.h>
}

namespace pqc::backend {

bool MlDsaKeypair(unsigned char* pk, unsigned char* sk)
{
    return crypto_sign_keypair(pk, sk) == 0;
}

bool MlDsaSign(unsigned char* sig, size_t* sig_len, const unsigned char* msg32, const unsigned char* sk)
{
    // No context string, matching the plain FIPS 204 signature the opcode
    // verifies. This copy ships config.h with DILITHIUM_RANDOMIZED_SIGNING
    // defined, so signing draws from the entropy hook and repeats only when
    // the seed is reinstalled.
    return crypto_sign_signature(sig, sig_len, msg32, 32, nullptr, 0, sk) == 0;
}

bool MlDsaVerify(const unsigned char* sig, size_t sig_len, const unsigned char* msg32, const unsigned char* pk)
{
    return crypto_sign_verify(sig, sig_len, msg32, 32, nullptr, 0, pk) == 0;
}

} // namespace pqc::backend
