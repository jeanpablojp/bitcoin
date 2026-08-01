// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <key_io.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>
#include <streams.h>
#include <test/data/p2mr_construction.json.h>
#include <test/data/p2mr_pqc_construction.json.h>
#include <test/data/p2mr_spending.json.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/strencodings.h>
#include <util/string.h>

#include <boost/test/unit_test.hpp>

#include <univalue.h>

#include <algorithm>
#include <map>
#include <string>
#include <vector>

// BIP 360 test vectors. The construction files come from the bitcoin/bips
// repository at the pinned commit b31410ca587cec1cfd880b6617cc6b7cb036e6d7
// (bip-0360/ref-impl/common/tests/data/): script tree in; leaf hashes,
// Merkle root, scriptPubKey, address and control blocks out. The spending
// file (p2mr_spending.json) is generated locally by
// test/functional/tool_p2mr_spend_vectors.py and carries full transactions,
// verified here through VerifyScript. Further spend-path coverage lives in
// script_tests.cpp (script_p2mr) and in the functional tests.

BOOST_FIXTURE_TEST_SUITE(p2mr_vector_tests, BasicTestingSetup)

namespace {

struct VectorLeaf {
    int id;
    uint8_t version;
    uint256 hash;
    //! Merkle path to this leaf, deepest sibling first.
    std::vector<unsigned char> path;
};

//! Compute the hash of a scriptTree node (leaf object or two-element array)
//! using the consensus hashing functions, collecting per-leaf info.
uint256 WalkTree(const UniValue& node, std::vector<VectorLeaf>& leaves)
{
    if (node.isArray()) {
        BOOST_REQUIRE_EQUAL(node.size(), 2U);
        std::vector<VectorLeaf> left, right;
        const uint256 l{WalkTree(node[0], left)};
        const uint256 r{WalkTree(node[1], right)};
        for (auto& leaf : left) leaf.path.insert(leaf.path.end(), r.begin(), r.end());
        for (auto& leaf : right) leaf.path.insert(leaf.path.end(), l.begin(), l.end());
        leaves.insert(leaves.end(), left.begin(), left.end());
        leaves.insert(leaves.end(), right.begin(), right.end());
        return ComputeTapbranchHash(l, r);
    }
    BOOST_REQUIRE(node.isObject());
    const std::vector<unsigned char> script{ParseHex(node["script"].get_str())};
    VectorLeaf leaf;
    leaf.id = node["id"].getInt<int>();
    leaf.version = static_cast<uint8_t>(node["leafVersion"].getInt<int>());
    leaf.hash = ComputeTapleafHash(leaf.version, script);
    leaves.push_back(leaf);
    return leaf.hash;
}

void CheckConstructionVectors(std::string_view json_raw, size_t num_vectors)
{
    // Not read_json(): these files carry a top-level object, not an array.
    UniValue root;
    BOOST_REQUIRE(root.read(json_raw));
    BOOST_REQUIRE(root.isObject());
    BOOST_REQUIRE_EQUAL(root["version"].getInt<int>(), 1);
    const UniValue& tvs{root["test_vectors"]};
    BOOST_REQUIRE(tvs.isArray());
    // Guard against a silently empty or truncated file: the counts are fixed
    // at the pinned vector commit.
    BOOST_REQUIRE_EQUAL(tvs.size(), num_vectors);

    for (size_t i{0}; i < tvs.size(); ++i) {
        const UniValue& tv{tvs[i]};
        const std::string id{tv["id"].get_str()};
        const UniValue& given{tv["given"]};
        const UniValue& expected{tv["expected"]};

        // The vector files use both spellings for the tree key.
        const std::string tree_key{given.exists("scriptTree") ? "scriptTree" : "script_tree"};
        const UniValue& tree{given.exists(tree_key) ? given[tree_key] : NullUniValue};

        // Failure vectors: a P2MR output cannot be built from an internal
        // pubkey (there is none) or without a script tree. The files encode
        // the missing tree as null or as an empty string.
        if (given.exists("internalPubkey") || (!tree.isObject() && !tree.isArray())) {
            BOOST_CHECK_MESSAGE(expected.exists("error"), id + ": expected an error field");
            continue;
        }

        std::vector<VectorLeaf> leaves;
        const uint256 merkle_root{WalkTree(tree, leaves)};

        const UniValue& inter{tv["intermediary"]};
        const UniValue& leaf_hashes{inter["leafHashes"]};
        BOOST_REQUIRE_MESSAGE(leaf_hashes.size() == leaves.size(), id + ": leaf count");
        for (size_t k{0}; k < leaves.size(); ++k) {
            // Leaves are listed in depth-first order and ids follow it.
            BOOST_CHECK_MESSAGE(leaves[k].id == static_cast<int>(k), id + ": leaf id order");
            BOOST_CHECK_MESSAGE(HexStr(leaves[k].hash) == leaf_hashes[k].get_str(),
                                id + ": leaf hash " + util::ToString(k));
        }
        BOOST_CHECK_MESSAGE(HexStr(merkle_root) == inter["merkleRoot"].get_str(), id + ": merkle root");

        const CScript spk{CScript() << OP_2 << ToByteVector(merkle_root)};
        BOOST_CHECK_MESSAGE(HexStr(spk) == expected["scriptPubKey"].get_str(), id + ": scriptPubKey");

        const std::string address{EncodeDestination(WitnessV2P2MR{merkle_root})};
        BOOST_CHECK_MESSAGE(address == expected["bip350Address"].get_str(), id + ": address");

        // Round-trip: the address must decode to the dedicated destination
        // type and back to the same scriptPubKey.
        const CTxDestination dest{DecodeDestination(address)};
        BOOST_CHECK_MESSAGE(std::holds_alternative<WitnessV2P2MR>(dest), id + ": decoded type");
        BOOST_CHECK_MESSAGE(GetScriptForDestination(dest) == spk, id + ": script round-trip");

        const UniValue& cbs{expected["scriptPathControlBlocks"]};
        BOOST_REQUIRE_MESSAGE(cbs.size() == leaves.size(), id + ": control block count");
        for (size_t k{0}; k < leaves.size(); ++k) {
            std::vector<unsigned char> control{static_cast<unsigned char>(leaves[k].version | 1)};
            control.insert(control.end(), leaves[k].path.begin(), leaves[k].path.end());
            BOOST_CHECK_MESSAGE(HexStr(control) == cbs[k].get_str(),
                                id + ": control block " + util::ToString(k));

            // Tie the vector to the consensus code: walking this control
            // block's path from the leaf hash must reproduce the root.
            BOOST_CHECK_MESSAGE(ComputeP2MRMerkleRoot(control, leaves[k].hash) == merkle_root,
                                id + ": consensus path walk " + util::ToString(k));
        }
    }
}

} // namespace

BOOST_AUTO_TEST_CASE(p2mr_construction)
{
    CheckConstructionVectors(json_tests::p2mr_construction, /*num_vectors=*/9);
}

BOOST_AUTO_TEST_CASE(p2mr_pqc_construction)
{
    CheckConstructionVectors(json_tests::p2mr_pqc_construction, /*num_vectors=*/7);
}

BOOST_AUTO_TEST_CASE(p2mr_spending)
{
    // Spend-path vectors (p2mr_spending.json, generated by
    // test/functional/tool_p2mr_spend_vectors.py). Every witness is run
    // through VerifyScript, so this checks the actual consensus code, not a
    // reimplementation of it.
    const script_verify_flags flags{SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS |
                                    SCRIPT_VERIFY_TAPROOT | SCRIPT_VERIFY_P2MR};

    UniValue root;
    BOOST_REQUIRE(root.read(json_tests::p2mr_spending));
    BOOST_REQUIRE_EQUAL(root["version"].getInt<int>(), 1);

    const auto decode_tx{[](const std::string& hex) {
        CMutableTransaction mtx;
        const std::vector<unsigned char> raw{ParseHex(hex)};
        SpanReader{raw} >> TX_WITH_WITNESS(mtx);
        return mtx;
    }};

    // ---- valid spends ----------------------------------------------------
    const UniValue& groups{root["scriptPathSpending"]};
    BOOST_REQUIRE(groups.isArray());
    for (size_t gi{0}; gi < groups.size(); ++gi) {
        const UniValue& group{groups[gi]};
        const CMutableTransaction mtx{decode_tx(group["auxiliary"]["fullySignedTx"].get_str())};

        std::vector<CTxOut> spent;
        const UniValue& utxos{group["given"]["utxosSpent"]};
        for (size_t i{0}; i < utxos.size(); ++i) {
            const std::vector<unsigned char> spk{ParseHex(utxos[i]["scriptPubKey"].get_str())};
            spent.emplace_back(utxos[i]["amountSats"].getInt<int64_t>(),
                               CScript(spk.begin(), spk.end()));
        }
        BOOST_REQUIRE_EQUAL(spent.size(), mtx.vin.size());

        // The unsigned tx must be the signed one minus its witnesses.
        CMutableTransaction stripped{mtx};
        for (auto& in : stripped.vin) in.scriptWitness.stack.clear();
        DataStream unsigned_ser;
        unsigned_ser << TX_NO_WITNESS(stripped);
        BOOST_CHECK_EQUAL(HexStr(unsigned_ser), group["given"]["rawUnsignedTx"].get_str());

        const CTransaction tx{mtx};
        PrecomputedTransactionData txdata;
        txdata.Init(tx, std::vector<CTxOut>{spent});
        BOOST_REQUIRE(txdata.m_bip341_taproot_ready);

        // The published sighash midstate pieces.
        const UniValue& inter{group["intermediary"]};
        BOOST_CHECK_EQUAL(HexStr(txdata.m_prevouts_single_hash), inter["hashPrevouts"].get_str());
        BOOST_CHECK_EQUAL(HexStr(txdata.m_sequences_single_hash), inter["hashSequences"].get_str());
        BOOST_CHECK_EQUAL(HexStr(txdata.m_outputs_single_hash), inter["hashOutputs"].get_str());
        BOOST_CHECK_EQUAL(HexStr(txdata.m_spent_amounts_single_hash), inter["hashAmounts"].get_str());
        BOOST_CHECK_EQUAL(HexStr(txdata.m_spent_scripts_single_hash), inter["hashScriptPubkeys"].get_str());

        const UniValue& inputs{group["inputSpending"]};
        BOOST_REQUIRE_EQUAL(inputs.size(), mtx.vin.size());
        for (size_t i{0}; i < inputs.size(); ++i) {
            const UniValue& in{inputs[i]};
            const size_t idx(in["given"]["txinIndex"].getInt<int>());
            BOOST_REQUIRE(idx < mtx.vin.size());

            // Re-derive everything an implementer would derive from the
            // published tree: Merkle root, spent scriptPubKey, leaf hash and
            // control block must match both the intermediary fields and the
            // witness.
            std::vector<VectorLeaf> leaves;
            const uint256 derived_root{WalkTree(in["given"]["scriptTree"], leaves)};
            const UniValue& in_inter{in["intermediary"]};
            BOOST_CHECK_EQUAL(HexStr(derived_root), in_inter["merkleRoot"].get_str());
            const CScript derived_spk{CScript() << OP_2 << ToByteVector(derived_root)};
            BOOST_CHECK_EQUAL(HexStr(derived_spk), HexStr(spent[idx].scriptPubKey));
            const int leaf_id{in["given"]["leafId"].getInt<int>()};
            const auto leaf_it{std::find_if(leaves.begin(), leaves.end(),
                                            [&](const auto& l) { return l.id == leaf_id; })};
            BOOST_REQUIRE(leaf_it != leaves.end());
            BOOST_CHECK_EQUAL(HexStr(leaf_it->hash), in_inter["leafHash"].get_str());
            std::vector<unsigned char> derived_control{
                static_cast<unsigned char>(leaf_it->version | 1)};
            derived_control.insert(derived_control.end(), leaf_it->path.begin(),
                                   leaf_it->path.end());
            BOOST_CHECK_EQUAL(HexStr(derived_control), in_inter["controlBlock"].get_str());

            // The witness in the signed tx matches the published one.
            const UniValue& wit_expected{in["expected"]["witness"]};
            const CScriptWitness& wit{tx.vin[idx].scriptWitness};
            BOOST_REQUIRE_EQUAL(wit.stack.size(), wit_expected.size());
            for (size_t k{0}; k < wit.stack.size(); ++k) {
                BOOST_CHECK_EQUAL(HexStr(wit.stack[k]), wit_expected[k].get_str());
            }

            ScriptError serror;
            const bool ok{VerifyScript(
                tx.vin[idx].scriptSig, spent[idx].scriptPubKey, &wit, flags,
                TransactionSignatureChecker(&tx, idx, spent[idx].nValue, txdata,
                                            MissingDataBehavior::ASSERT_FAIL),
                &serror)};
            BOOST_CHECK_MESSAGE(ok, "input " + util::ToString(idx) + ": " +
                                        ScriptErrorString(serror));
        }
    }

    // ---- invalid spends --------------------------------------------------
    // The vectors describe failures in spec terms; this maps each published
    // error string onto the script error our implementation reports. Several
    // spec-level errors intentionally collapse onto one ScriptError.
    const std::map<std::string, ScriptError> expected_errors{
        {"invalid signature", SCRIPT_ERR_SCHNORR_SIG},
        {"witness program mismatch", SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH},
        {"invalid control byte", SCRIPT_ERR_P2MR_WRONG_CONTROL_BYTE},
        {"fewer than two witness elements", SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH},
        {"annex with fewer than two remaining witness elements", SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH},
        {"invalid control block size", SCRIPT_ERR_TAPROOT_WRONG_CONTROL_SIZE},
        {"empty witness", SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY},
    };

    const UniValue& invalid{root["invalidSpending"]};
    BOOST_REQUIRE(invalid.isArray());
    BOOST_REQUIRE_EQUAL(invalid.size(), 9U);
    for (size_t i{0}; i < invalid.size(); ++i) {
        const UniValue& tv{invalid[i]};
        const std::string id{tv["id"].get_str()};
        const CMutableTransaction mtx{decode_tx(tv["given"]["rawTx"].get_str())};
        const UniValue& utxo{tv["given"]["utxoSpent"]};
        const std::vector<unsigned char> spk{ParseHex(utxo["scriptPubKey"].get_str())};
        std::vector<CTxOut> spent{
            {utxo["amountSats"].getInt<int64_t>(), CScript(spk.begin(), spk.end())}};

        const CTransaction tx{mtx};
        PrecomputedTransactionData txdata;
        txdata.Init(tx, std::vector<CTxOut>{spent});

        ScriptError serror;
        const bool ok{VerifyScript(
            tx.vin[0].scriptSig, spent[0].scriptPubKey, &tx.vin[0].scriptWitness,
            flags,
            TransactionSignatureChecker(&tx, 0, spent[0].nValue, txdata,
                                        MissingDataBehavior::ASSERT_FAIL),
            &serror)};
        BOOST_CHECK_MESSAGE(!ok, id + ": accepted but must fail");
        const std::string error{tv["expected"]["error"].get_str()};
        const auto it{expected_errors.find(error)};
        BOOST_REQUIRE_MESSAGE(it != expected_errors.end(),
                              id + ": unmapped error \"" + error + "\"");
        BOOST_CHECK_MESSAGE(serror == it->second,
                            id + ": got \"" + ScriptErrorString(serror) + "\"");
    }
}

BOOST_AUTO_TEST_CASE(p2mr_address_boundaries)
{
    // A v2 address with a program size other than 32 bytes is not P2MR and
    // stays WitnessUnknown in both directions.
    const WitnessUnknown unk{2, std::vector<unsigned char>(33, 0x42)};
    const std::string addr{EncodeDestination(unk)};
    const CTxDestination back{DecodeDestination(addr)};
    BOOST_CHECK(std::holds_alternative<WitnessUnknown>(back));
    BOOST_CHECK(std::get<WitnessUnknown>(back) == unk);
}

BOOST_AUTO_TEST_SUITE_END()
