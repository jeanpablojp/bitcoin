// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// SLH-DSA-SHA2-128s backend. Kept in its own translation unit because the
// vendored reference implementations disagree about symbol naming: SPHINCS+
// declares plain crypto_sign_* names while Dilithium macro-renames the same
// names onto its own namespace. Including both headers in one file would let
// Dilithium's macros rewrite the calls meant for SPHINCS+.

#include <pqc/pqc_backends.h>

extern "C" {
#include <pqc/sphincsplus/api.h>
}

namespace pqc::backend {

bool SlhDsaSeedKeypair(unsigned char* pk, unsigned char* sk, const unsigned char* seed)
{
    return crypto_sign_seed_keypair(pk, sk, seed) == 0;
}

bool SlhDsaSign(unsigned char* sig, size_t* sig_len, const unsigned char* msg32, const unsigned char* sk)
{
    return crypto_sign_signature(sig, sig_len, msg32, 32, sk) == 0;
}

bool SlhDsaVerify(const unsigned char* sig, size_t sig_len, const unsigned char* msg32, const unsigned char* pk)
{
    return crypto_sign_verify(sig, sig_len, msg32, 32, pk) == 0;
}

} // namespace pqc::backend
