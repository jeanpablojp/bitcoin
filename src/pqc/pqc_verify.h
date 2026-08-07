// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PQC_PQC_VERIFY_H
#define BITCOIN_PQC_PQC_VERIFY_H

#include <cstddef>
#include <cstdint>

namespace pqc {

//! Scheme ids as committed in the leaf script, matching the
//! libbitcoinpqc enum (0 is secp256k1 there and is not exposed here).
enum class Scheme : uint8_t {
    ML_DSA_44 = 1,
    SLH_DSA_SHA2_128S = 2,
};

//! Exact object sizes per scheme (FIPS 205 / FIPS 204 parameter sets).
static constexpr size_t SLH_DSA_SHA2_128S_PUBKEY_SIZE{32};
static constexpr size_t SLH_DSA_SHA2_128S_SIG_SIZE{7856};
static constexpr size_t ML_DSA_44_PUBKEY_SIZE{1312};
static constexpr size_t ML_DSA_44_SIG_SIZE{2420};

//! True if the scheme byte maps to a scheme this build can verify.
bool IsKnownScheme(uint8_t scheme_byte);

//! Exact pubkey/signature sizes for a known scheme.
size_t PubKeySize(Scheme scheme);
size_t SigSize(Scheme scheme);

/** Verify a detached signature over a 32-byte message (the tapscript
 *  sighash). Returns false on any failure. No malleability concern is
 *  handled here; callers enforce exact sizes before calling. */
bool Verify(Scheme scheme,
            const unsigned char* pubkey, size_t pubkey_len,
            const unsigned char* msg32,
            const unsigned char* sig, size_t sig_len);

// Key generation and signing. Consensus code never calls these; they exist
// for tests and vector generation.
static constexpr size_t SLH_DSA_SHA2_128S_SECKEY_SIZE{64};
static constexpr size_t SLH_DSA_SHA2_128S_SEED_SIZE{48};
static constexpr size_t ML_DSA_44_SECKEY_SIZE{2560};

//! Install the entropy the vendored Dilithium draws from while generating
//! keys and signing. Nothing in consensus calls this; without it
//! randombytes() aborts rather than inventing randomness. An empty seed
//! installs nothing. SLH-DSA reaches none of this, being deterministic in
//! both operations.
void SetDeterministicEntropy(const unsigned char* seed, size_t seed_len);

//! Whether entropy is currently installed. SeedKeypair and Sign check this so
//! that misuse returns false instead of tripping the guard in randombytes().
bool HasDeterministicEntropy();

//! Wipe the installed entropy. Callers that hand in a secret seed should do
//! this when they are done with it, since the state outlives the call.
void ClearDeterministicEntropy();

/** Serializes the install-generate-sign-wipe sequence and wipes on the way
 *  out. The entropy state is a single global, so anything reachable from
 *  more than one thread, an RPC handler for instance, has to hold this for
 *  the whole sequence rather than for each access. */
class EntropyLock
{
public:
    EntropyLock();
    ~EntropyLock();
    EntropyLock(const EntropyLock&) = delete;
    EntropyLock& operator=(const EntropyLock&) = delete;
};

//! Deterministic keypair from a seed. Buffers must have the scheme's exact
//! pubkey/seckey sizes. SLH-DSA requires exactly SLH_DSA_SHA2_128S_SEED_SIZE
//! bytes, which it splits into its three key seeds. ML-DSA accepts any
//! length, since the seed only feeds the hook, which this installs for it.
bool SeedKeypair(Scheme scheme, unsigned char* pk, unsigned char* sk, const unsigned char* seed, size_t seed_len);

//! Detached signature over a 32-byte message. `sig` must have SigSize(scheme)
//! bytes of space; `sig_len` returns the written length. ML-DSA randomizes
//! the signature, so entropy has to be installed first, which SeedKeypair
//! does; SLH-DSA signing is deterministic and needs none.
bool Sign(Scheme scheme, unsigned char* sig, size_t* sig_len, const unsigned char* msg32, const unsigned char* sk);

} // namespace pqc

#endif // BITCOIN_PQC_PQC_VERIFY_H
