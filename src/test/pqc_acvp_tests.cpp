// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Conformance of the vendored SLH-DSA against NIST's own ACVP cases. The
// vendored code is reached directly here rather than through pqc_verify.h,
// because these cases exercise arbitrary messages and signing contexts while
// the consensus wrapper fixes both: a 32-byte sighash and an empty context.
// The last test ties the two together.

#include <pqc/pqc_verify.h>

#include <test/data/slh_dsa_acvp.json.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <univalue.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <optional>
#include <string>
#include <vector>

extern "C" {
#include <pqc/slhdsa/slh_dsa.h>
}

BOOST_FIXTURE_TEST_SUITE(pqc_acvp_tests, BasicTestingSetup)

namespace {
//! Hex to bytes, with a pointer that stays valid when the string is empty:
//! a zero length still reaches memcpy inside the vendored code. Malformed
//! hex fails here rather than silently becoming an empty value, which would
//! leave a case looking like it passed.
struct Blob {
    std::vector<unsigned char> bytes;
    explicit Blob(const UniValue& v)
    {
        const auto parsed{TryParseHex<unsigned char>(v.get_str())};
        BOOST_REQUIRE(parsed.has_value());
        bytes = *parsed;
        bytes.push_back(0);
    }
    const unsigned char* data() const { return bytes.data(); }
    size_t size() const { return bytes.size() - 1; }
};

UniValue LoadCases()
{
    UniValue root;
    BOOST_REQUIRE(root.read(json_tests::slh_dsa_acvp));
    return root;
}
} // namespace

//! Key generation, which also pins how the wrapper reads its 48-byte seed.
//! NIST hands the three key seeds separately; the wrapper takes them
//! concatenated, so a case passing here fixes both the derivation and the
//! order and offsets it splits at. Nothing else covers that: the spend
//! vectors carry published keys rather than deriving them, and everything
//! in script_tests signs and verifies through the same seed either way.
BOOST_AUTO_TEST_CASE(slh_dsa_acvp_keygen)
{
    const UniValue cases{LoadCases()["keyGen"]};
    BOOST_REQUIRE_EQUAL(cases.size(), 10U);

    for (size_t i = 0; i < cases.size(); ++i) {
        const UniValue& c{cases[i]};
        const Blob sk_seed{c["skSeed"]}, sk_prf{c["skPrf"]}, pk_seed{c["pkSeed"]};
        const Blob expected_pk{c["pk"]}, expected_sk{c["sk"]};

        std::vector<unsigned char> seed;
        seed.insert(seed.end(), sk_seed.data(), sk_seed.data() + sk_seed.size());
        seed.insert(seed.end(), sk_prf.data(), sk_prf.data() + sk_prf.size());
        seed.insert(seed.end(), pk_seed.data(), pk_seed.data() + pk_seed.size());
        BOOST_REQUIRE_EQUAL(seed.size(), pqc::SLH_DSA_SHA2_128S_SEED_SIZE);

        std::vector<unsigned char> pk(pqc::SLH_DSA_SHA2_128S_PUBKEY_SIZE);
        std::vector<unsigned char> sk(pqc::SLH_DSA_SHA2_128S_SECKEY_SIZE);
        BOOST_REQUIRE(pqc::SeedKeypair(pqc::Scheme::SLH_DSA_SHA2_128S, pk.data(), sk.data(), seed.data(), seed.size()));

        const std::string why{strprintf("tcId %i", c["tcId"].getInt<int>())};
        BOOST_REQUIRE_EQUAL(expected_pk.size(), pk.size());
        BOOST_REQUIRE_EQUAL(expected_sk.size(), sk.size());
        BOOST_CHECK_MESSAGE(std::equal(pk.begin(), pk.end(), expected_pk.data()), why + " public key");
        BOOST_CHECK_MESSAGE(std::equal(sk.begin(), sk.end(), expected_sk.data()), why + " secret key");
    }
}

//! The sizes the wrapper declares have to be the ones this parameter set
//! actually uses, since the seed split above divides one of them by three.
BOOST_AUTO_TEST_CASE(slh_dsa_sizes_match_the_parameter_set)
{
    BOOST_CHECK_EQUAL(slh_pk_sz(&slh_dsa_sha2_128s), pqc::SLH_DSA_SHA2_128S_PUBKEY_SIZE);
    BOOST_CHECK_EQUAL(slh_sk_sz(&slh_dsa_sha2_128s), pqc::SLH_DSA_SHA2_128S_SECKEY_SIZE);
    BOOST_CHECK_EQUAL(slh_sig_sz(&slh_dsa_sha2_128s), pqc::SLH_DSA_SHA2_128S_SIG_SIZE);
    BOOST_CHECK_EQUAL(std::string{slh_alg_id(&slh_dsa_sha2_128s)}, "SLH-DSA-SHA2-128s");
}

BOOST_AUTO_TEST_CASE(slh_dsa_acvp_sigver)
{
    const UniValue cases{LoadCases()["sigVer"]};
    BOOST_REQUIRE_EQUAL(cases.size(), 14U);

    unsigned accepted{0};
    for (size_t i = 0; i < cases.size(); ++i) {
        const UniValue& c{cases[i]};
        const Blob pk{c["pk"]}, ctx{c["context"]}, msg{c["message"]}, sig{c["signature"]};
        BOOST_REQUIRE_EQUAL(pk.size(), pqc::SLH_DSA_SHA2_128S_PUBKEY_SIZE);

        const bool ok{slh_verify(msg.data(), msg.size(), sig.data(), sig.size(),
                                 ctx.data(), ctx.size(), pk.data(), &slh_dsa_sha2_128s) == 1};
        const std::string why{strprintf("tcId %i (%s)", c["tcId"].getInt<int>(), c["reason"].get_str())};
        BOOST_CHECK_MESSAGE(ok == c["testPassed"].get_bool(), why);
        accepted += ok;
    }
    // NIST supplies two valid signatures and twelve tampered ones, and a
    // verifier that rejected everything would otherwise score twelve.
    BOOST_CHECK_EQUAL(accepted, 2U);
}

BOOST_AUTO_TEST_CASE(slh_dsa_acvp_siggen)
{
    const UniValue cases{LoadCases()["sigGen"]};
    BOOST_REQUIRE_EQUAL(cases.size(), 14U);

    unsigned deterministic{0};
    for (size_t i = 0; i < cases.size(); ++i) {
        const UniValue& c{cases[i]};
        const Blob sk{c["sk"]}, ctx{c["context"]}, msg{c["message"]}, expected{c["signature"]};
        BOOST_REQUIRE_EQUAL(sk.size(), pqc::SLH_DSA_SHA2_128S_SECKEY_SIZE);
        BOOST_REQUIRE_EQUAL(expected.size(), pqc::SLH_DSA_SHA2_128S_SIG_SIZE);

        // FIPS 205 takes the extra randomness as an argument; passing none
        // selects the deterministic variant, which uses PK.seed instead.
        const bool is_deterministic{c["deterministic"].get_bool()};
        deterministic += is_deterministic;
        BOOST_REQUIRE_EQUAL(is_deterministic, !c.exists("additionalRandomness"));
        const unsigned char* addrnd{nullptr};
        std::optional<Blob> rnd;
        if (!is_deterministic) {
            rnd.emplace(c["additionalRandomness"]);
            addrnd = rnd->data();
        }

        std::vector<unsigned char> sig(pqc::SLH_DSA_SHA2_128S_SIG_SIZE);
        const size_t written{slh_sign(sig.data(), msg.data(), msg.size(), ctx.data(), ctx.size(),
                                      sk.data(), addrnd, &slh_dsa_sha2_128s)};
        BOOST_REQUIRE_EQUAL(written, sig.size());
        BOOST_CHECK_MESSAGE(std::equal(sig.begin(), sig.end(), expected.data()),
                            strprintf("tcId %i signature mismatch", c["tcId"].getInt<int>()));
    }
    BOOST_CHECK_EQUAL(deterministic, 7U);
}

//! What consensus calls has to be the same function these cases pin down: the
//! pure variant with an empty context, over the 32-byte sighash.
BOOST_AUTO_TEST_CASE(slh_dsa_wrapper_matches_pure_empty_context)
{
    const std::vector<unsigned char> seed(pqc::SLH_DSA_SHA2_128S_SEED_SIZE, 0x2b);
    std::vector<unsigned char> pk(pqc::SLH_DSA_SHA2_128S_PUBKEY_SIZE);
    std::vector<unsigned char> sk(pqc::SLH_DSA_SHA2_128S_SECKEY_SIZE);
    BOOST_REQUIRE(pqc::SeedKeypair(pqc::Scheme::SLH_DSA_SHA2_128S, pk.data(), sk.data(), seed.data(), seed.size()));

    const std::vector<unsigned char> msg(32, 0x7c);
    std::vector<unsigned char> sig(pqc::SLH_DSA_SHA2_128S_SIG_SIZE);
    size_t sig_len{0};
    BOOST_REQUIRE(pqc::Sign(pqc::Scheme::SLH_DSA_SHA2_128S, sig.data(), &sig_len, msg.data(), sk.data()));
    BOOST_CHECK_EQUAL(sig_len, pqc::SLH_DSA_SHA2_128S_SIG_SIZE);
    BOOST_CHECK(pqc::Verify(pqc::Scheme::SLH_DSA_SHA2_128S, pk.data(), pk.size(), msg.data(), sig.data(), sig_len));

    // The same signature under FIPS 205 called directly, empty context.
    const unsigned char empty[1]{};
    BOOST_CHECK_EQUAL(slh_verify(msg.data(), msg.size(), sig.data(), sig_len,
                                 empty, 0, pk.data(), &slh_dsa_sha2_128s), 1);

    // A context of one byte is a different message under FIPS 205, so the
    // same signature must not verify: this is what pins the wrapper to the
    // empty-context variant rather than to any context at all.
    const unsigned char one[1]{0x00};
    BOOST_CHECK_EQUAL(slh_verify(msg.data(), msg.size(), sig.data(), sig_len,
                                 one, 1, pk.data(), &slh_dsa_sha2_128s), 0);

    // Signing is deterministic, so a second run reproduces it exactly.
    std::vector<unsigned char> again(pqc::SLH_DSA_SHA2_128S_SIG_SIZE);
    size_t again_len{0};
    BOOST_REQUIRE(pqc::Sign(pqc::Scheme::SLH_DSA_SHA2_128S, again.data(), &again_len, msg.data(), sk.data()));
    BOOST_CHECK(again == sig);
}

BOOST_AUTO_TEST_SUITE_END()
