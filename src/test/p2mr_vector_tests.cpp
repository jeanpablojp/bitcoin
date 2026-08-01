// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <key_io.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <test/data/p2mr_construction.json.h>
#include <test/data/p2mr_pqc_construction.json.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/strencodings.h>
#include <util/string.h>

#include <boost/test/unit_test.hpp>

#include <univalue.h>

#include <string>
#include <vector>

// BIP 360 construction test vectors, from the bitcoin/bips repository at the
// pinned commit b31410ca587cec1cfd880b6617cc6b7cb036e6d7
// (bip-0360/ref-impl/common/tests/data/). They are construction-only: script
// tree in; leaf hashes, Merkle root, scriptPubKey, address and control blocks
// out. Spend-path coverage lives in script_tests.cpp (script_p2mr) and in the
// functional tests.

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
