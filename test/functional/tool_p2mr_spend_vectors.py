#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Generate BIP 360 P2MR spend-path test vectors (p2mr_spending.json).

Deterministic: private keys are sha256("p2mr_spending/key/<n>"), prevout
txids are sha256("p2mr_spending/prevout/<n>"), and signatures use BIP 340
signing with an all-zero aux. Running this tool twice produces identical
output. The schema mirrors bip-0341/wallet-test-vectors.json, adapted to
an output type whose only spend path is the script path.

Two inputs reuse trees published in p2mr_construction.json (pinned
upstream commit), so the construction and spending files cross-check
each other:
 - p2mr_single_leaf_script_tree: a depth-0 output, spendable by anyone
   who knows the leaf script, with no signature. This demonstrates the
   anyone-can-spend rule of v0.12.0.
 - p2mr_different_version_leaves: spent through its 0xfa leaf, which is
   an unknown leaf version and therefore unencumbered.

Usage: test/functional/tool_p2mr_spend_vectors.py [output.json]
"""

import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_framework.key import compute_xonly_pubkey, sign_schnorr
from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    uint256_from_str,
)
from test_framework.script import (
    ANNEX_TAG,
    BIP341_sha_amounts,
    BIP341_sha_outputs,
    BIP341_sha_prevouts,
    BIP341_sha_scriptpubkeys,
    BIP341_sha_sequences,
    CScript,
    LEAF_VERSION_TAPSCRIPT,
    OP_2,
    OP_CHECKSIG,
    TaggedHash,
    TaprootSignatureMsg,
    ser_string,
)

SIGHASH_DEFAULT = 0
SIGHASH_ALL = 1


def sha256(b):
    return hashlib.sha256(b).digest()


def privkey(n):
    return sha256(f"p2mr_spending/key/{n}".encode())


def prevout_txid(n):
    return sha256(f"p2mr_spending/prevout/{n}".encode())


def tapleaf_hash(script, version=LEAF_VERSION_TAPSCRIPT):
    return TaggedHash("TapLeaf", bytes([version]) + ser_string(script))


def tapbranch_hash(a, b):
    return TaggedHash("TapBranch", b"".join(sorted([a, b])))


class Tree:
    """Merkle tree over a nested scriptTree structure, BIP 360 hashing.

    `node` is either a leaf dict {"id", "script", "leafVersion"} or a
    two-element list of nodes, exactly as in p2mr_construction.json.
    Each leaf's Merkle path is collected closest-sibling first, which is
    the control block order.
    """

    def __init__(self, node):
        self.leaves = []
        self.merkle_root = self._walk(node)

    def _walk(self, node):
        if isinstance(node, list):
            assert len(node) == 2
            start = len(self.leaves)
            left = self._walk(node[0])
            mid = len(self.leaves)
            right = self._walk(node[1])
            for leaf in self.leaves[start:mid]:
                leaf["path"].append(right)
            for leaf in self.leaves[mid:]:
                leaf["path"].append(left)
            return tapbranch_hash(left, right)
        script = bytes.fromhex(node["script"])
        # Required, not defaulted: the C++ reader rejects a leaf without a
        # version, and the generator must not emit what the reader refuses.
        version = node["leafVersion"]
        self.leaves.append({"id": node["id"], "script": script,
                            "version": version, "path": []})
        return tapleaf_hash(script, version)

    def _leaf(self, leaf_id):
        for leaf in self.leaves:
            if leaf["id"] == leaf_id:
                return leaf
        raise KeyError(leaf_id)

    def control_block(self, leaf_id):
        leaf = self._leaf(leaf_id)
        return bytes([leaf["version"] | 1]) + b"".join(leaf["path"])

    def leaf_script(self, leaf_id):
        leaf = self._leaf(leaf_id)
        return leaf["script"], leaf["version"]

    @property
    def script_pubkey(self):
        return CScript([OP_2, self.merkle_root])


def checksig_leaf(leaf_id, key):
    x = compute_xonly_pubkey(key)[0]
    return {"id": leaf_id, "script": CScript([x, OP_CHECKSIG]).hex(),
            "leafVersion": LEAF_VERSION_TAPSCRIPT}


def load_construction_vector(vector_id):
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "..", "..", "src", "test", "data",
                        "p2mr_construction.json")
    with open(path) as f:
        data = json.load(f)
    for v in data["test_vectors"]:
        if v["id"] == vector_id:
            return v
    raise KeyError(vector_id)


def build_tx(n_inputs, outputs):
    tx = CTransaction()
    tx.version = 2
    tx.nLockTime = 0
    tx.vin = [CTxIn(COutPoint(uint256_from_str(prevout_txid(i)), i), b"",
                    0xfffffffd) for i in range(n_inputs)]
    tx.vout = [CTxOut(amount, script) for amount, script in outputs]
    tx.wit.vtxinwit = [CTxInWitness() for _ in range(n_inputs)]
    return tx


def main():
    out_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..", "..", "src", "test", "data", "p2mr_spending.json")

    # ---- trees ------------------------------------------------------------
    key = [privkey(n) for n in range(4)]

    two_leaf = [checksig_leaf(0, key[0]), checksig_leaf(1, key[1])]
    three_leaf = [checksig_leaf(0, key[2]),
                  [checksig_leaf(1, key[3]), checksig_leaf(2, key[0])]]

    t_two = Tree(two_leaf)
    t_three = Tree(three_leaf)

    single_vec = load_construction_vector("p2mr_single_leaf_script_tree")
    single_tree = single_vec["given"]["scriptTree"]
    t_single = Tree(single_tree)
    mixed_vec = load_construction_vector("p2mr_different_version_leaves")
    mixed_tree = mixed_vec["given"]["scriptTree"]
    t_mixed = Tree(mixed_tree)

    # A comb-shaped tree whose deepest leaf sits at depth 128: its control
    # block is 1 + 32*128 = 4097 bytes, the maximum. Pins the accepting
    # side of the depth limit (the rejecting side is an invalid vector).
    deep_tree = checksig_leaf(0, key[2])
    for n in range(1, 129):
        deep_tree = [deep_tree,
                     {"id": n, "script": "51", "leafVersion": LEAF_VERSION_TAPSCRIPT}]
    t_deep = Tree(deep_tree)
    assert len(t_deep.control_block(0)) == 1 + 32 * 128

    # The reused trees must reproduce their published construction vectors.
    assert t_single.merkle_root.hex() == single_vec["intermediary"]["merkleRoot"]
    assert t_mixed.merkle_root.hex() == mixed_vec["intermediary"]["merkleRoot"]
    assert (t_mixed.control_block(1).hex()
            == mixed_vec["expected"]["scriptPathControlBlocks"][1])

    # ---- the valid spending group: one tx, five inputs --------------------
    spends = [
        # (tree, tree_json, leaf_id, key or None, hash_type, annex, comment)
        (t_two, two_leaf, 0, key[0], SIGHASH_DEFAULT, None,
         "two-leaf tree, depth-1 leaf, SIGHASH_DEFAULT"),
        (t_three, three_leaf, 1, key[3], SIGHASH_ALL, None,
         "three-leaf tree, depth-2 leaf, SIGHASH_ALL"),
        (t_two, two_leaf, 1, key[1], SIGHASH_DEFAULT,
         bytes([ANNEX_TAG]) + b"p2mr annex",
         "annex present: last witness element, covered by the signature"),
        (t_single, single_tree, 0, None, None, None,
         "p2mr_single_leaf_script_tree: depth-0, script execution is "
         "skipped, no signature; anyone who knows the leaf script can "
         "spend (v0.12.0 rule)"),
        (t_mixed, mixed_tree, 1, None, None, None,
         "p2mr_different_version_leaves through the 0xfa leaf: unknown "
         "leaf versions are unencumbered"),
        (t_deep, deep_tree, 0, key[2], SIGHASH_DEFAULT, None,
         "depth-128 leaf: the control block is exactly the maximum "
         "1 + 32*128 bytes"),
    ]

    utxos = [(100000 + 1000 * i, s[0].script_pubkey)
             for i, s in enumerate(spends)]
    out_spk = CScript(bytes.fromhex("0014") + sha256(b"p2mr_spending/out/0")[:20])
    tx = build_tx(len(spends), [(sum(u[0] for u in utxos) - 10000, out_spk)])
    raw_unsigned = tx.serialize_without_witness().hex()
    spent = [CTxOut(amount, spk) for amount, spk in utxos]

    input_vectors = []
    for i, (tree, tree_json, leaf_id, k, hash_type, annex, comment) in enumerate(spends):
        script, version = tree.leaf_script(leaf_id)
        control = tree.control_block(leaf_id)
        intermediary = {
            "leafHash": tapleaf_hash(script, version).hex(),
            "merkleRoot": tree.merkle_root.hex(),
            "controlBlock": control.hex(),
            "sigMsg": None,
            "sigHash": None,
        }
        witness = []
        if k is not None:
            msg = TaprootSignatureMsg(tx, spent, hash_type, i, scriptpath=True,
                                      leaf_script=script, leaf_ver=version,
                                      annex=annex,
                                      codeseparator_pos=0xFFFFFFFF)
            sighash = TaggedHash("TapSighash", msg)
            sig = sign_schnorr(k, sighash)
            if hash_type != SIGHASH_DEFAULT:
                sig += bytes([hash_type])
            intermediary["sigMsg"] = msg.hex()
            intermediary["sigHash"] = sighash.hex()
            witness.append(sig)
        witness += [script, control]
        if annex is not None:
            witness.append(annex)
        tx.wit.vtxinwit[i].scriptWitness.stack = witness
        input_vectors.append({
            "given": {
                "txinIndex": i,
                "scriptTree": tree_json,
                "leafId": leaf_id,
                "privkey": k.hex() if k else None,
                "hashType": hash_type,
                "annex": annex.hex() if annex else None,
            },
            "intermediary": intermediary,
            "expected": {"witness": [w.hex() for w in witness]},
            "comment": comment,
        })

    valid_group = {
        "given": {
            "rawUnsignedTx": raw_unsigned,
            "utxosSpent": [{"scriptPubKey": spk.hex(), "amountSats": amount}
                           for amount, spk in utxos],
        },
        "intermediary": {
            "hashAmounts": BIP341_sha_amounts(spent).hex(),
            "hashOutputs": BIP341_sha_outputs(tx).hex(),
            "hashPrevouts": BIP341_sha_prevouts(tx).hex(),
            "hashScriptPubkeys": BIP341_sha_scriptpubkeys(spent).hex(),
            "hashSequences": BIP341_sha_sequences(tx).hex(),
        },
        "inputSpending": input_vectors,
        "auxiliary": {"fullySignedTx": tx.serialize().hex()},
    }

    # ---- invalid spends: one single-input tx each -------------------------
    invalid = []

    def invalid_case(vector_id, tree, witness, error, comment):
        itx = build_tx(1, [(90000, out_spk)])
        itx.wit.vtxinwit[0].scriptWitness.stack = witness
        invalid.append({
            "id": vector_id,
            "given": {
                "rawTx": itx.serialize().hex(),
                "utxoSpent": {"scriptPubKey": tree.script_pubkey.hex(),
                              "amountSats": 100000},
            },
            "expected": {"error": error},
            "comment": comment,
        })

    # A correctly signed spend of the two-leaf tree, then broken one way
    # per case. All invalid txs share the same deterministic shape, so one
    # signature fits them all.
    base_tx = build_tx(1, [(90000, out_spk)])
    base_spent = [CTxOut(100000, t_two.script_pubkey)]
    script, version = t_two.leaf_script(0)
    control = t_two.control_block(0)
    msg = TaprootSignatureMsg(base_tx, base_spent, SIGHASH_DEFAULT, 0,
                              scriptpath=True, leaf_script=script,
                              leaf_ver=version,
                              codeseparator_pos=0xFFFFFFFF)
    sig = sign_schnorr(key[0], TaggedHash("TapSighash", msg))

    invalid_case("p2mr_spend_invalid_signature", t_two,
                 [bytes([sig[0] ^ 0x01]) + sig[1:], script, control],
                 "invalid signature",
                 "first byte of an otherwise valid signature flipped")

    invalid_case("p2mr_spend_tampered_merkle_path", t_two,
                 [sig, script,
                  control[:1] + bytes([control[1] ^ 0x01]) + control[2:]],
                 "witness program mismatch",
                 "one bit of the Merkle path flipped: the computed root no "
                 "longer matches the witness program")

    invalid_case("p2mr_spend_control_byte_low_bit_zero", t_two,
                 [sig, script, bytes([control[0] & 0xfe]) + control[1:]],
                 "invalid control byte",
                 "the control byte's low bit is 0; Script Validation says "
                 "it 'is unused and must be 1'")

    invalid_case("p2mr_spend_single_witness_element", t_two,
                 [script],
                 "fewer than two witness elements",
                 "a P2MR witness needs at least a script and a control block")

    invalid_case("p2mr_spend_two_elements_ending_in_annex", t_two,
                 [script, bytes([ANNEX_TAG]) + b"x"],
                 "annex with fewer than two remaining witness elements",
                 "with exactly two elements the last may not start with 0x50")

    invalid_case("p2mr_spend_control_block_too_deep", t_two,
                 [sig, script, control[:1] + bytes(32 * 129)],
                 "invalid control block size",
                 "a Merkle path of 129 elements exceeds the maximum depth "
                 "of 128")

    invalid_case("p2mr_spend_empty_witness", t_two,
                 [],
                 "empty witness",
                 "a witness program needs a witness")

    invalid_case("p2mr_spend_empty_control_block", t_two,
                 [sig, script, b""],
                 "invalid control block size",
                 "the control block must carry at least the control byte")

    invalid_case("p2mr_spend_control_block_bad_length", t_two,
                 [sig, script, control + b"\x00"],
                 "invalid control block size",
                 "control block length must be 1 + 32*m: 34 bytes is not")

    # ---- write ------------------------------------------------------------
    doc = {
        "version": 1,
        "comment": "BIP 360 P2MR spend-path test vectors. Deterministic: "
                   "privkeys are sha256('p2mr_spending/key/<n>'), prevout "
                   "txids sha256('p2mr_spending/prevout/<n>'), BIP 340 "
                   "signing with all-zero aux. The trees for txinIndex 3 "
                   "and 4 are p2mr_single_leaf_script_tree and "
                   "p2mr_different_version_leaves from "
                   "p2mr_construction.json. For inputs spent without a "
                   "signature, privkey/hashType/annex/sigMsg/sigHash are "
                   "null.",
        "scriptPathSpending": [valid_group],
        "invalidSpending": invalid,
    }
    with open(out_path, "w") as f:
        json.dump(doc, f, indent=1)
        f.write("\n")
    print(f"wrote {out_path}")


if __name__ == "__main__":
    main()
