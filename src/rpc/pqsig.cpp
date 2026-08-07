// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Experimental RPCs for the draft PQ signature opcode. The functional test
// builds its own sighashes, witnesses and blocks in Python, which is where a
// misreading of BIP 341/342 would show; what Python cannot do is produce a
// post-quantum signature, so these expose that primitive and nothing else.
// Seeds are supplied per call and never stored.

#include <chainparams.h>
#include <pqc/pqc_verify.h>
#include <rpc/protocol.h>
#include <rpc/request.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <support/cleanse.h>
#include <tinyformat.h>
#include <univalue.h>
#include <util/chaintype.h>
#include <util/strencodings.h>

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace {

//! The opcode only carries meaning where its rules are enforced, which is
//! regtest. Elsewhere these would hand out signatures for outputs that are
//! anyone-can-spend in practice.
void RequireRegtest(std::string_view name)
{
    if (Params().GetChainType() != ChainType::REGTEST) {
        throw std::runtime_error(tfm::format("%s is for regression testing (-regtest mode) only: the PQ signature opcode is a draft and its rules apply on regtest alone", name));
    }
}

pqc::Scheme SchemeFromName(const std::string& name)
{
    if (name == "ml-dsa-44") return pqc::Scheme::ML_DSA_44;
    if (name == "slh-dsa-sha2-128s") return pqc::Scheme::SLH_DSA_SHA2_128S;
    throw JSONRPCError(RPC_INVALID_PARAMETER, "scheme must be \"ml-dsa-44\" or \"slh-dsa-sha2-128s\"");
}

//! A seed is only entropy, and no scheme here draws more than 48 bytes of
//! it. Bounding both ends keeps a caller from weakening a key by accident
//! and from making the node hash megabytes while holding the entropy lock.
constexpr size_t MIN_PQ_RPC_SEED_SIZE{32};
constexpr size_t MAX_PQ_RPC_SEED_SIZE{64};

//! SLH-DSA takes the seed directly and needs its exact length; ML-DSA has no
//! seeded entry point upstream and reaches it through the entropy hook, so
//! any length within the bounds above will do.
std::vector<unsigned char> ParseSeed(const UniValue& v, pqc::Scheme scheme)
{
    const auto seed{TryParseHex<unsigned char>(v.get_str())};
    if (!seed) throw JSONRPCError(RPC_INVALID_PARAMETER, "seed must be hex");
    if (scheme == pqc::Scheme::SLH_DSA_SHA2_128S) {
        if (seed->size() != pqc::SLH_DSA_SHA2_128S_SEED_SIZE) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("slh-dsa-sha2-128s needs a %u-byte seed", pqc::SLH_DSA_SHA2_128S_SEED_SIZE));
        }
    } else if (seed->size() < MIN_PQ_RPC_SEED_SIZE || seed->size() > MAX_PQ_RPC_SEED_SIZE) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("seed must be between %u and %u bytes", MIN_PQ_RPC_SEED_SIZE, MAX_PQ_RPC_SEED_SIZE));
    }
    return *seed;
}

size_t SecKeySize(pqc::Scheme scheme)
{
    return scheme == pqc::Scheme::ML_DSA_44 ? pqc::ML_DSA_44_SECKEY_SIZE : pqc::SLH_DSA_SHA2_128S_SECKEY_SIZE;
}

} // namespace

static RPCMethod pqpubkey()
{
    return RPCMethod{
        "pqpubkey",
        "Derives the public key a seed produces for a post-quantum signature\n"
        "scheme, so a caller can build the leaf script that commits to it.\n"
        "The seed is supplied per call; nothing is stored.\n"
        "Experimental, for regtest use.\n",
        {
            {"scheme", RPCArg::Type::STR, RPCArg::Optional::NO, "\"ml-dsa-44\" or \"slh-dsa-sha2-128s\""},
            {"seed", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The seed the key pair is derived from: 48 bytes for slh-dsa-sha2-128s, 32 to 64 for ml-dsa-44"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "pubkey", "The public key"},
            }
        },
        RPCExamples{
            HelpExampleCli("pqpubkey", "\"slh-dsa-sha2-128s\" \"00112233...\"")
            + HelpExampleRpc("pqpubkey", "\"slh-dsa-sha2-128s\", \"00112233...\"")
        },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
        {
            RequireRegtest("pqpubkey");

            const pqc::Scheme scheme{SchemeFromName(request.params[0].get_str())};
            std::vector<unsigned char> seed{ParseSeed(request.params[1], scheme)};
            const pqc::EntropyLock entropy_lock;

            std::vector<unsigned char> pubkey(pqc::PubKeySize(scheme));
            std::vector<unsigned char> seckey(SecKeySize(scheme));
            const bool ok{pqc::SeedKeypair(scheme, pubkey.data(), seckey.data(), seed.data(), seed.size())};
            memory_cleanse(seckey.data(), seckey.size());
            memory_cleanse(seed.data(), seed.size());
            if (!ok) throw JSONRPCError(RPC_INTERNAL_ERROR, "key generation failed");

            UniValue result{UniValue::VOBJ};
            result.pushKV("pubkey", HexStr(pubkey));
            return result;
        },
    };
}

static RPCMethod pqsignhash()
{
    return RPCMethod{
        "pqsignhash",
        "Signs a 32-byte message with the key a seed produces. The message is\n"
        "whatever the caller computed, so the caller stays responsible for the\n"
        "sighash: this signs bytes and checks nothing about them.\n"
        "The same seed and message give the same signature back. SLH-DSA is\n"
        "deterministic in itself; ML-DSA randomizes part of its signature, and\n"
        "the seed seeds that too.\n"
        "The seed is supplied per call; nothing is stored.\n"
        "Experimental, for regtest use.\n",
        {
            {"scheme", RPCArg::Type::STR, RPCArg::Optional::NO, "\"ml-dsa-44\" or \"slh-dsa-sha2-128s\""},
            {"seed", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The seed the key pair is derived from: 48 bytes for slh-dsa-sha2-128s, 32 to 64 for ml-dsa-44"},
            {"hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The 32-byte message to sign"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "signature", "The signature"},
                {RPCResult::Type::STR_HEX, "pubkey", "The public key that verifies it"},
            }
        },
        RPCExamples{
            HelpExampleCli("pqsignhash", "\"slh-dsa-sha2-128s\" \"00112233...\" \"aabbcc...\"")
            + HelpExampleRpc("pqsignhash", "\"slh-dsa-sha2-128s\", \"00112233...\", \"aabbcc...\"")
        },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
        {
            RequireRegtest("pqsignhash");

            const pqc::Scheme scheme{SchemeFromName(request.params[0].get_str())};
            std::vector<unsigned char> seed{ParseSeed(request.params[1], scheme)};

            const auto msg{TryParseHex<unsigned char>(request.params[2].get_str())};
            if (!msg || msg->size() != 32) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "hash must be 32 bytes of hex");
            }
            const pqc::EntropyLock entropy_lock;

            std::vector<unsigned char> pubkey(pqc::PubKeySize(scheme));
            std::vector<unsigned char> seckey(SecKeySize(scheme));
            if (!pqc::SeedKeypair(scheme, pubkey.data(), seckey.data(), seed.data(), seed.size())) {
                memory_cleanse(seckey.data(), seckey.size());
                memory_cleanse(seed.data(), seed.size());
                throw JSONRPCError(RPC_INTERNAL_ERROR, "key generation failed");
            }

            // Key generation consumed part of the stream the seed installed,
            // so rewind it: the signature should be a function of the seed
            // and the message, nothing else.
            pqc::SetDeterministicEntropy(seed.data(), seed.size());
            memory_cleanse(seed.data(), seed.size());

            std::vector<unsigned char> sig(pqc::SigSize(scheme));
            size_t sig_len{0};
            const bool signed_ok{pqc::Sign(scheme, sig.data(), &sig_len, msg->data(), seckey.data())};
            memory_cleanse(seckey.data(), seckey.size());
            if (!signed_ok || sig_len != pqc::SigSize(scheme)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "signing failed");
            }

            UniValue result{UniValue::VOBJ};
            result.pushKV("signature", HexStr(sig));
            result.pushKV("pubkey", HexStr(pubkey));
            return result;
        },
    };
}

void RegisterPQSigRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"hidden", &pqpubkey},
        {"hidden", &pqsignhash},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
