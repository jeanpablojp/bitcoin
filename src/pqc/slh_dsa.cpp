// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// SLH-DSA-SHA2-128s backend, over slhdsa-c. Kept in its own translation unit
// because the vendored Dilithium macro-renames plain crypto_sign_* names onto
// its own namespace, and including both headers in one file would let those
// macros rewrite the calls meant for this one.
//
// Nothing here draws randomness. Key generation goes through the internal
// entry point, which derives everything from the three seeds it is handed,
// and signing passes a null addrnd, which FIPS 205 defines as the
// deterministic variant. Consensus only ever verifies, which needs no
// randomness under any implementation.

#include <pqc/pqc_backends.h>

#include <pqc/pqc_verify.h>

extern "C" {
#include <pqc/slhdsa/slh_dsa.h>
}

namespace {
//! FIPS 205 signs the message prefixed with a domain separator and a context.
//! The opcode uses the pure variant with an empty context, so what gets signed
//! is 0x00 || 0x00 || sighash. A length of zero still reaches memcpy with this
//! pointer, hence an empty array rather than nullptr.
const unsigned char EMPTY_CONTEXT[1]{};
constexpr size_t EMPTY_CONTEXT_LEN{0};

//! The seed is SK.seed || SK.prf || PK.seed, each one n bytes wide.
constexpr size_t SEED_PART{pqc::SLH_DSA_SHA2_128S_SEED_SIZE / 3};

//! The message is always a 32-byte tapscript sighash.
constexpr size_t MSG_SIZE{32};
} // namespace

namespace pqc::backend {

bool SlhDsaSeedKeypair(unsigned char* pk, unsigned char* sk, const unsigned char* seed)
{
    return slh_keygen_internal(sk, pk, seed, seed + SEED_PART, seed + 2 * SEED_PART,
                               &slh_dsa_sha2_128s) == 0;
}

bool SlhDsaSign(unsigned char* sig, size_t* sig_len, const unsigned char* msg32, const unsigned char* sk)
{
    const size_t written{slh_sign(sig, msg32, MSG_SIZE, EMPTY_CONTEXT, EMPTY_CONTEXT_LEN,
                                  sk, /*addrnd=*/nullptr, &slh_dsa_sha2_128s)};
    if (written != SLH_DSA_SHA2_128S_SIG_SIZE) return false;
    *sig_len = written;
    return true;
}

bool SlhDsaVerify(const unsigned char* sig, size_t sig_len, const unsigned char* msg32, const unsigned char* pk)
{
    return slh_verify(msg32, MSG_SIZE, sig, sig_len, EMPTY_CONTEXT, EMPTY_CONTEXT_LEN,
                      pk, &slh_dsa_sha2_128s) == 1;
}

} // namespace pqc::backend
