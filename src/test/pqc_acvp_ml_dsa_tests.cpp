// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Conformance of the vendored ML-DSA against NIST's own ACVP cases, the
// counterpart of pqc_acvp_tests.cpp for the other scheme. It sits in its own
// translation unit for the reason the backends do: Dilithium's headers define
// N, K, L, Q and D as macros, which leak into anything that includes them.

#include <pqc/pqc_verify.h>

#include <test/data/ml_dsa_acvp.json.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <univalue.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

extern "C" {
#include <pqc/dilithium/sign.h>
}

BOOST_FIXTURE_TEST_SUITE(pqc_acvp_ml_dsa_tests, BasicTestingSetup)

namespace {
//! Hex to bytes. Malformed hex fails here rather than silently becoming an
//! empty value, which would leave a case looking like it passed.
std::vector<unsigned char> Bytes(const UniValue& v)
{
    const auto parsed{TryParseHex<unsigned char>(v.get_str())};
    BOOST_REQUIRE(parsed.has_value());
    return *parsed;
}

//! Dilithium copies the context with a loop rather than memcpy, so a null
//! pointer with a zero length is never read. An empty vector gives exactly
//! that, and the cases with a context give a real pointer.
const unsigned char* ContextPtr(const std::vector<unsigned char>& ctx)
{
    return ctx.empty() ? nullptr : ctx.data();
}
} // namespace

BOOST_AUTO_TEST_CASE(ml_dsa_acvp_sigver)
{
    UniValue root;
    BOOST_REQUIRE(root.read(json_tests::ml_dsa_acvp));
    const UniValue cases{root["sigVer"]};
    BOOST_REQUIRE_EQUAL(cases.size(), 15U);

    unsigned accepted{0};
    for (size_t i = 0; i < cases.size(); ++i) {
        const UniValue& c{cases[i]};
        const std::vector<unsigned char> pk{Bytes(c["pk"])}, ctx{Bytes(c["context"])};
        const std::vector<unsigned char> msg{Bytes(c["message"])}, sig{Bytes(c["signature"])};
        BOOST_REQUIRE_EQUAL(pk.size(), pqc::ML_DSA_44_PUBKEY_SIZE);
        BOOST_REQUIRE_EQUAL(sig.size(), pqc::ML_DSA_44_SIG_SIZE);

        const bool ok{crypto_sign_verify(sig.data(), sig.size(), msg.data(), msg.size(),
                                         ContextPtr(ctx), ctx.size(), pk.data()) == 0};
        const std::string why{strprintf("tcId %i (%s)", c["tcId"].getInt<int>(), c["reason"].get_str())};
        BOOST_CHECK_MESSAGE(ok == c["testPassed"].get_bool(), why);
        accepted += ok;
    }
    // NIST supplies three valid signatures and twelve tampered ones, and a
    // verifier that rejected everything would otherwise score twelve.
    BOOST_CHECK_EQUAL(accepted, 3U);
}

//! What consensus calls has to be the same function those cases pin down: the
//! FIPS 204 signature with an empty context, over the 32-byte sighash.
BOOST_AUTO_TEST_CASE(ml_dsa_wrapper_matches_empty_context)
{
    const std::vector<unsigned char> seed(32, 0x2b);
    std::vector<unsigned char> pk(pqc::ML_DSA_44_PUBKEY_SIZE);
    std::vector<unsigned char> sk(pqc::ML_DSA_44_SECKEY_SIZE);
    std::vector<unsigned char> sig(pqc::ML_DSA_44_SIG_SIZE);
    const std::vector<unsigned char> msg(32, 0x7c);
    size_t sig_len{0};
    {
        // ML-DSA randomizes its signature, so signing needs the hook.
        const pqc::EntropyLock entropy_lock;
        BOOST_REQUIRE(pqc::SeedKeypair(pqc::Scheme::ML_DSA_44, pk.data(), sk.data(), seed.data(), seed.size()));
        BOOST_REQUIRE(pqc::Sign(pqc::Scheme::ML_DSA_44, sig.data(), &sig_len, msg.data(), sk.data()));
    }
    BOOST_CHECK_EQUAL(sig_len, pqc::ML_DSA_44_SIG_SIZE);
    BOOST_CHECK(pqc::Verify(pqc::Scheme::ML_DSA_44, pk.data(), pk.size(), msg.data(), sig.data(), sig_len));

    // The same signature under FIPS 204 called directly, empty context.
    BOOST_CHECK_EQUAL(crypto_sign_verify(sig.data(), sig_len, msg.data(), msg.size(),
                                         nullptr, 0, pk.data()), 0);

    // A context of one byte is a different message under FIPS 204, so the
    // same signature must not verify. This is what pins the wrapper to the
    // empty-context variant rather than to any context at all.
    const unsigned char one[1]{0x00};
    BOOST_CHECK_NE(crypto_sign_verify(sig.data(), sig_len, msg.data(), msg.size(),
                                      one, 1, pk.data()), 0);
}

BOOST_AUTO_TEST_SUITE_END()
