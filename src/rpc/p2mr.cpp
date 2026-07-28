// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Experimental RPCs for building and spending BIP 360 P2MR outputs.
// Regtest tooling for the bitcoin-p2mr project: keys are supplied per
// call and never stored.

#include <addresstype.h>
#include <chainparams.h>
#include <consensus/amount.h>
#include <core_io.h>
#include <key.h>
#include <key_io.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <rpc/protocol.h>
#include <rpc/request.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <support/cleanse.h>
#include <tinyformat.h>
#include <uint256.h>
#include <univalue.h>
#include <util/chaintype.h>
#include <util/check.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cstddef>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

//! P2MR consensus rules are only applied to blocks on regtest, so these RPCs
//! would otherwise hand out addresses that are anyone-can-spend in practice.
void RequireRegtest(std::string_view name)
{
    if (Params().GetChainType() != ChainType::REGTEST) {
        throw std::runtime_error(tfm::format("%s is for regression testing (-regtest mode) only: BIP 360 is a draft, and witness v2 outputs are anyone-can-spend on other chains", name));
    }
}

//! Keeps a request from building a tree large enough to exhaust memory.
constexpr size_t MAX_P2MR_RPC_LEAVES{128};
//! Arbitrary per-leaf ceiling for this tool. Tapscript itself has no script
//! size limit; leaves are only bounded by the block weight limit.
constexpr size_t MAX_P2MR_RPC_LEAF_SIZE{10000};

//! Depths of a balanced tree with n leaves, in depth-first order.
void BalancedDepths(size_t n, int depth, std::vector<int>& out)
{
    if (n == 0) return;
    if (n == 1) {
        out.push_back(depth);
        return;
    }
    BalancedDepths((n + 1) / 2, depth + 1, out);
    BalancedDepths(n / 2, depth + 1, out);
}

} // namespace

static RPCMethod createp2mraddress()
{
    return RPCMethod{
        "createp2mraddress",
        "Builds a BIP 360 P2MR output from tapscript leaves and returns the\n"
        "address, Merkle root and per-leaf control blocks. A 32-byte leaf is\n"
        "read as an x-only public key and wrapped as <key> OP_CHECKSIG; any\n"
        "other length is used as a raw tapscript. At least two leaves are\n"
        "required: under BIP 360 a\n"
        "single-leaf (depth-0) tree is anyone-can-spend. Leaves must be\n"
        "distinct and use tapscript (leaf version 0xc0).\n"
        "Experimental, for regtest use.\n",
        {
            {"leaves", RPCArg::Type::ARR, RPCArg::Optional::NO, "The tapscript leaves.",
                {
                    {"leaf", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "A 32-byte x-only public key or a raw tapscript, hex-encoded"},
                }},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "address", "The P2MR address"},
                {RPCResult::Type::STR_HEX, "scriptPubKey", "The output script"},
                {RPCResult::Type::STR_HEX, "merkle_root", "The Merkle root of the script tree"},
                {RPCResult::Type::ARR, "leaves", "One entry per leaf, in the order given",
                {
                    {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "script", "The leaf script"},
                        {RPCResult::Type::STR_HEX, "control_block", "The control block for spending through this leaf"},
                    }},
                }},
            }
        },
        RPCExamples{
            HelpExampleCli("createp2mraddress", "\"[\\\"72ea6adcf1d371dea8fba1035a09f3d24ed5a059799bae114084130ee5898e69\\\",\\\"2352d137f2f3ab38d1eaa976758873377fa5ebb817372c71e2c542313d4abda8\\\"]\"")
            + HelpExampleRpc("createp2mraddress", "[\"72ea6adcf1d371dea8fba1035a09f3d24ed5a059799bae114084130ee5898e69\",\"2352d137f2f3ab38d1eaa976758873377fa5ebb817372c71e2c542313d4abda8\"]")
        },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
        {
            RequireRegtest("createp2mraddress");

            const UniValue& leaves{request.params[0].get_array()};
            if (leaves.size() < 2) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "P2MR requires at least two leaves: a single-leaf tree is anyone-can-spend under BIP 360");
            }
            if (leaves.size() > MAX_P2MR_RPC_LEAVES) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, tfm::format("too many leaves (max %d)", MAX_P2MR_RPC_LEAVES));
            }

            std::vector<CScript> scripts;
            scripts.reserve(leaves.size());
            for (size_t i{0}; i < leaves.size(); ++i) {
                const std::vector<unsigned char> data{ParseHexV(leaves[i], "leaf")};
                if (data.size() > MAX_P2MR_RPC_LEAF_SIZE) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, tfm::format("leaf %d is too large (max %d bytes)", i, MAX_P2MR_RPC_LEAF_SIZE));
                }
                if (data.size() == 32) {
                    // Treat as an x-only pubkey and wrap it in a CHECKSIG leaf.
                    if (!XOnlyPubKey{data}.IsFullyValid()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, tfm::format("leaf %d is not a valid x-only public key", i));
                    }
                    scripts.emplace_back(CScript{} << data << OP_CHECKSIG);
                } else {
                    scripts.emplace_back(data.begin(), data.end());
                }
            }

            // Identical leaves share one entry in the builder's spend data, so
            // the per-leaf control blocks below would not be per-position.
            for (size_t i{0}; i < scripts.size(); ++i) {
                for (size_t j{i + 1}; j < scripts.size(); ++j) {
                    if (scripts[i] == scripts[j]) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, tfm::format("leaves %d and %d are identical", i, j));
                    }
                }
            }

            std::vector<int> depths;
            depths.reserve(scripts.size());
            BalancedDepths(scripts.size(), 0, depths);
            CHECK_NONFATAL(TaprootBuilder::ValidDepths(depths));

            TaprootBuilder builder;
            for (size_t i{0}; i < scripts.size(); ++i) {
                builder.Add(depths[i], scripts[i], TAPROOT_LEAF_TAPSCRIPT);
            }
            CHECK_NONFATAL(builder.IsComplete());
            // The internal key is irrelevant here: P2MR commits to the Merkle
            // root alone, so only the tree hashes are used.
            builder.Finalize(XOnlyPubKey::NUMS_H);
            const TaprootSpendData spend_data{builder.GetSpendData()};

            const WitnessV2P2MR dest{spend_data.merkle_root};
            UniValue result(UniValue::VOBJ);
            result.pushKV("address", EncodeDestination(dest));
            result.pushKV("scriptPubKey", HexStr(GetScriptForDestination(dest)));
            result.pushKV("merkle_root", HexStr(spend_data.merkle_root));

            UniValue leaves_out(UniValue::VARR);
            for (const CScript& script : scripts) {
                const auto it{spend_data.scripts.find({{script.begin(), script.end()}, TAPROOT_LEAF_TAPSCRIPT})};
                CHECK_NONFATAL(it != spend_data.scripts.end() && !it->second.empty());
                // Turn the taproot control block (control byte, internal key,
                // path) into a P2MR one: the control byte with the low bit
                // set, followed by the path alone.
                const std::vector<unsigned char>& taproot_control{*it->second.begin()};
                std::vector<unsigned char> control{static_cast<unsigned char>(TAPROOT_LEAF_TAPSCRIPT | 1)};
                control.insert(control.end(), taproot_control.begin() + TAPROOT_CONTROL_BASE_SIZE, taproot_control.end());

                UniValue leaf(UniValue::VOBJ);
                leaf.pushKV("script", HexStr(script));
                leaf.pushKV("control_block", HexStr(control));
                leaves_out.push_back(std::move(leaf));
            }
            result.pushKV("leaves", std::move(leaves_out));
            return result;
        },
    };
}

static RPCMethod signp2mrspend()
{
    return RPCMethod{
        "signp2mrspend",
        "Signs one P2MR input of a raw transaction through a <key> OP_CHECKSIG\n"
        "tapscript leaf and attaches the witness [signature, script, control\n"
        "block]. All spent outputs must be provided, since BIP 341 signatures\n"
        "commit to them. The private key is supplied per call; nothing is\n"
        "stored.\n"
        "Signs with SIGHASH_DEFAULT, without an annex, and assumes the leaf\n"
        "contains no OP_CODESEPARATOR.\n"
        "Experimental, for regtest use.\n",
        {
            {"hexstring", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The raw transaction"},
            {"input_index", RPCArg::Type::NUM, RPCArg::Optional::NO, "The input to sign"},
            {"prevouts", RPCArg::Type::ARR, RPCArg::Optional::NO, "The outputs spent by the transaction, one per input, in input order.",
                {
                    {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                    {
                        {"scriptPubKey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The output script"},
                        {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The output amount"},
                    }},
                }},
            {"script", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The leaf script being spent"},
            {"control_block", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The control block for that leaf"},
            {"privkey", RPCArg::Type::STR, RPCArg::Optional::NO, "The private key (WIF or 32-byte hex) matching the leaf's public key"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "hex", "The signed raw transaction"},
            }
        },
        RPCExamples{
            HelpExampleCli("signp2mrspend", "\"myrawtx\" 0 \"[{\\\"scriptPubKey\\\":\\\"myspk\\\",\\\"amount\\\":1.0}]\" \"myleafscript\" \"mycontrolblock\" \"myprivkey\"")
            + HelpExampleRpc("signp2mrspend", "\"myrawtx\", 0, [{\"scriptPubKey\":\"myspk\",\"amount\":1.0}], \"myleafscript\", \"mycontrolblock\", \"myprivkey\"")
        },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
        {
            RequireRegtest("signp2mrspend");

            CMutableTransaction mtx;
            if (!DecodeHexTx(mtx, request.params[0].get_str())) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
            }
            const size_t input_index{static_cast<size_t>(request.params[1].getInt<int>())};
            if (input_index >= mtx.vin.size()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "input_index out of range");
            }

            const UniValue& prevouts{request.params[2].get_array()};
            if (prevouts.size() != mtx.vin.size()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "prevouts must have one entry per transaction input");
            }
            std::vector<CTxOut> spent_outputs;
            spent_outputs.reserve(prevouts.size());
            for (size_t i{0}; i < prevouts.size(); ++i) {
                const UniValue& prevout{prevouts[i].get_obj()};
                const std::vector<unsigned char> spk{ParseHexV(prevout.find_value("scriptPubKey"), "scriptPubKey")};
                const CAmount amount{AmountFromValue(prevout.find_value("amount"))};
                spent_outputs.emplace_back(amount, CScript(spk.begin(), spk.end()));
            }

            const std::vector<unsigned char> script_bytes{ParseHexV(request.params[3], "script")};
            const std::vector<unsigned char> control{ParseHexV(request.params[4], "control_block")};
            if (control.size() < P2MR_CONTROL_BASE_SIZE || control.size() > P2MR_CONTROL_MAX_SIZE ||
                (control.size() - P2MR_CONTROL_BASE_SIZE) % TAPROOT_CONTROL_NODE_SIZE != 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "control block must be 1 + 32*m bytes, with m between 0 and 128");
            }
            if ((control[0] & 1) == 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "the low bit of the control byte must be set");
            }
            // A one-byte control block is a depth-zero tree, which spends
            // without executing the script: signing it would be misleading.
            if (control.size() == P2MR_CONTROL_BASE_SIZE) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "depth-zero trees are anyone-can-spend and are not signed here");
            }

            const std::string key_str{request.params[5].get_str()};
            CKey key{DecodeSecret(key_str)};
            if (!key.IsValid() && IsHex(key_str)) {
                std::vector<unsigned char> raw{ParseHex(key_str)};
                if (raw.size() == 32) key.Set(raw.begin(), raw.end(), /*fCompressedIn=*/true);
                memory_cleanse(raw.data(), raw.size());
            }
            if (!key.IsValid()) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "privkey must be WIF or 32-byte hex");
            }

            const uint256 tapleaf_hash{ComputeTapleafHash(control[0] & TAPROOT_LEAF_MASK, script_bytes)};
            const CScript& prev_spk{spent_outputs[input_index].scriptPubKey};
            int witversion{};
            std::vector<unsigned char> program;
            if (!prev_spk.IsWitnessProgram(witversion, program) || witversion != 2 || program.size() != WITNESS_V2_P2MR_SIZE) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "the spent output is not a P2MR output");
            }
            if (!std::equal(program.begin(), program.end(), ComputeP2MRMerkleRoot(control, tapleaf_hash).begin())) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "script and control block do not reconstruct the spent output's Merkle root");
            }

            PrecomputedTransactionData txdata;
            txdata.Init(mtx, std::move(spent_outputs), /*force=*/true);

            ScriptExecutionData execdata;
            execdata.m_annex_init = true;
            execdata.m_annex_present = false;
            execdata.m_tapleaf_hash_init = true;
            execdata.m_tapleaf_hash = tapleaf_hash;
            execdata.m_codeseparator_pos_init = true;
            execdata.m_codeseparator_pos = 0xFFFFFFFFUL;

            uint256 sighash;
            if (!SignatureHashSchnorr(sighash, execdata, mtx, input_index, SIGHASH_DEFAULT, SigVersion::TAPSCRIPT, txdata, MissingDataBehavior::FAIL)) {
                throw JSONRPCError(RPC_MISC_ERROR, "sighash computation failed");
            }
            std::vector<unsigned char> sig(64);
            if (!key.SignSchnorr(sighash, sig, /*merkle_root=*/nullptr, uint256())) {
                throw JSONRPCError(RPC_MISC_ERROR, "schnorr signing failed");
            }

            mtx.vin[input_index].scriptWitness.stack = {sig, script_bytes, control};

            UniValue result(UniValue::VOBJ);
            result.pushKV("hex", EncodeHexTx(CTransaction(mtx)));
            return result;
        },
    };
}

void RegisterP2MRRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"hidden", &createp2mraddress},
        {"hidden", &signp2mrspend},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
