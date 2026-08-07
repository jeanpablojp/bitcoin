#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Generate OP_CHECKPQSIG spend vectors (pqsig_spending.json).

These are verification vectors, not signing vectors. Both vendored PQ
implementations randomize part of a signature and draw that randomness
from randombytes(), so a signature is reproducible from a seed only for
code that installs the same entropy hook this tree does. Publishing a
seed and calling the signature derivable from it would be a promise no
FIPS 204 or 205 implementation can keep. The signature is therefore
given data, the way most BIP 340 vectors give one, and everything an
implementer derives for themselves (leaf hash, Merkle root, control
block, public key commitment, signature message and sighash) is
published next to it.

Everything else is deterministic: prevout txids are
sha256("pqsig_spending/prevout/<n>"), the EC key is
sha256("pqsig_spending/key/0"), and the PQ seeds are the constants
below. Running this twice produces identical output, since the node
reinstalls the seed before signing.

The node is used as a signing oracle and nothing more. Transactions are
built and their sighashes computed here, so the node never sees them.

Usage: test/functional/tool_pqsig_spend_vectors.py [--output PATH]
"""

import hashlib
import json
import os

from test_framework.key import ECKey, compute_xonly_pubkey, sign_schnorr
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
    CScriptOp,
    LEAF_VERSION_TAPSCRIPT,
    OP_0,
    OP_1,
    OP_2,
    OP_CHECKSIG,
    OP_DROP,
    OP_ENDIF,
    OP_IF,
    OP_RETURN,
    OP_VERIFY,
    TaggedHash,
    TaprootSignatureMsg,
    ser_string,
)
from test_framework.test_framework import BitcoinTestFramework

OP_CHECKPQSIG = CScriptOp(0xbb)
SIGHASH_DEFAULT = 0
SIGHASH_ALL = 1
SIGHASH_SINGLE = 3
SIGHASH_ANYONECANPAY = 0x80

# Scheme ids as committed in the leaf, with the seed each key is derived
# from and the exact signature size the opcode admits.
SCHEMES = {
    "slh-dsa-sha2-128s": {"byte": 2, "seed": bytes([0x17]) * 48, "sig_len": 7856},
    "ml-dsa-44": {"byte": 1, "seed": bytes([0x2b]) * 32, "sig_len": 2420},
}
PQ_MAX_ELEMENT_SIZE = 8192


def sha256(b):
    return hashlib.sha256(b).digest()


def prevout_txid(n):
    return sha256(f"pqsig_spending/prevout/{n}".encode())


def tapleaf_hash(script, version=LEAF_VERSION_TAPSCRIPT):
    return TaggedHash("TapLeaf", bytes([version]) + ser_string(script))


def tapbranch_hash(a, b):
    return TaggedHash("TapBranch", b"".join(sorted([a, b])))


def pq_commitment(scheme, pubkey):
    """<scheme_byte || H(pubkey)>, the 33 bytes the leaf commits to."""
    return bytes([SCHEMES[scheme]["byte"]]) + TaggedHash("PQPubKeyHash", pubkey)


class Tree:
    """Merkle tree over a nested scriptTree, BIP 360 hashing. `node` is a
    leaf dict {"id", "script", "leafVersion"} or a two-element list, the
    same shape the C++ reader walks."""

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


def leaf_json(leaf_id, script):
    return {"id": leaf_id, "script": script.hex(),
            "leafVersion": LEAF_VERSION_TAPSCRIPT}


def build_tx(n_inputs, outputs):
    tx = CTransaction()
    tx.version = 2
    tx.nLockTime = 0
    tx.vin = [CTxIn(COutPoint(uint256_from_str(prevout_txid(i)), i), b"",
                    0xfffffffd) for i in range(n_inputs)]
    tx.vout = [CTxOut(amount, script) for amount, script in outputs]
    tx.wit.vtxinwit = [CTxInWitness() for _ in range(n_inputs)]
    return tx


class PQSigVectorTool(BitcoinTestFramework):
    def add_options(self, parser):
        default = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "..", "..", "src", "test", "data",
                               "pqsig_spending.json")
        parser.add_argument("--output", dest="output", default=default,
                            help="where to write the vectors")

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def pq_pubkey(self, scheme):
        return bytes.fromhex(
            self.nodes[0].pqpubkey(scheme, SCHEMES[scheme]["seed"].hex())["pubkey"])

    def pq_sign(self, scheme, sighash):
        return bytes.fromhex(self.nodes[0].pqsignhash(
            scheme, SCHEMES[scheme]["seed"].hex(), sighash.hex())["signature"])

    def sighash_for(self, tx, spent, index, script, hash_type, annex=None):
        msg = TaprootSignatureMsg(tx, spent, hash_type, index, scriptpath=True,
                                  leaf_script=script,
                                  leaf_ver=LEAF_VERSION_TAPSCRIPT, annex=annex,
                                  codeseparator_pos=0xFFFFFFFF)
        return msg, TaggedHash("TapSighash", msg)

    def run_test(self):
        slh, ml = "slh-dsa-sha2-128s", "ml-dsa-44"
        pk = {s: self.pq_pubkey(s) for s in SCHEMES}

        ec_key = ECKey()
        ec_key.set(sha256(b"pqsig_spending/key/0"), True)
        ec_xonly = compute_xonly_pubkey(ec_key.get_bytes())[0]

        # The leaves the vectors spend, each paired with an OP_RETURN
        # sibling so no output is a depth-0 anyone-can-spend.
        leaf_slh = CScript([pq_commitment(slh, pk[slh]), OP_CHECKPQSIG])
        leaf_ml = CScript([pq_commitment(ml, pk[ml]), OP_CHECKPQSIG])
        leaf_hybrid = CScript([pq_commitment(slh, pk[slh]), OP_CHECKPQSIG,
                               OP_VERIFY, ec_xonly, OP_CHECKSIG])
        leaf_both = CScript([pq_commitment(ml, pk[ml]), OP_CHECKPQSIG,
                             OP_VERIFY, pq_commitment(slh, pk[slh]),
                             OP_CHECKPQSIG])
        # OP_CHECKPQSIG inside a branch that never runs. The larger element
        # bound follows the textual presence of the opcode, since the
        # OP_SUCCESSx scan reads the whole script before any branch is
        # evaluated, so this leaf may carry an element well over 520 bytes
        # while checking no signature at all.
        leaf_unexecuted = CScript([OP_0, OP_IF, pq_commitment(slh, pk[slh]),
                                   OP_CHECKPQSIG, OP_ENDIF, OP_DROP, OP_1])
        sibling = CScript([OP_RETURN])

        def two_leaf(script):
            nodes = [leaf_json(0, script), leaf_json(1, sibling)]
            return Tree(nodes), nodes

        t_slh, j_slh = two_leaf(leaf_slh)
        t_ml, j_ml = two_leaf(leaf_ml)
        t_hybrid, j_hybrid = two_leaf(leaf_hybrid)
        t_both, j_both = two_leaf(leaf_both)
        t_branch, j_branch = two_leaf(leaf_unexecuted)

        spends = [
            # SIGHASH_SINGLE needs an output at this input's index, and there
            # is one output, so this case goes first.
            {"tree": t_slh, "json": j_slh, "schemes": [slh],
             "hash_type": SIGHASH_SINGLE | SIGHASH_ANYONECANPAY,
             "comment": "SLH-DSA leaf under SIGHASH_SINGLE | "
                        "SIGHASH_ANYONECANPAY: the whole BIP 341 hash type "
                        "range applies, and this one takes the other branch "
                        "of the message, covering a single output and this "
                        "input's own prevout rather than the aggregates"},
            {"tree": t_slh, "json": j_slh, "schemes": [slh],
             "hash_type": SIGHASH_DEFAULT,
             "comment": "SLH-DSA-SHA2-128s leaf, SIGHASH_DEFAULT"},
            {"tree": t_ml, "json": j_ml, "schemes": [ml],
             "hash_type": SIGHASH_ALL,
             "comment": "ML-DSA-44 leaf, SIGHASH_ALL: the signature carries "
                        "an explicit trailing hash type byte"},
            {"tree": t_hybrid, "json": j_hybrid, "schemes": [slh],
             "hash_type": SIGHASH_DEFAULT, "needs_ec": True,
             "comment": "one leaf requiring an SLH-DSA and a BIP 340 "
                        "signature over the same sighash"},
            {"tree": t_slh, "json": j_slh, "schemes": [slh],
             "hash_type": SIGHASH_DEFAULT,
             "annex": bytes([ANNEX_TAG]) + b"pqsig annex",
             "comment": "annex present: last witness element, covered by "
                        "the sighash"},
            {"tree": t_both, "json": j_both, "schemes": [ml, slh],
             "hash_type": SIGHASH_DEFAULT,
             "comment": "one leaf requiring both schemes, each with its own "
                        "key"},
            {"tree": t_branch, "json": j_branch, "schemes": [],
             "hash_type": None, "padding": PQ_MAX_ELEMENT_SIZE,
             "comment": "OP_CHECKPQSIG in a branch that never executes. The "
                        "leaf checks nothing and needs no signature, yet it "
                        "may carry an initial stack element of the full "
                        "8192 bytes, because the bound follows the presence "
                        "of the opcode in the script rather than its "
                        "execution"},
        ]

        utxos = [(100000 + 1000 * i, s["tree"].script_pubkey)
                 for i, s in enumerate(spends)]
        out_spk = CScript(bytes.fromhex("0014") + sha256(b"pqsig_spending/out/0")[:20])
        tx = build_tx(len(spends), [(sum(u[0] for u in utxos) - 10000, out_spk)])
        raw_unsigned = tx.serialize_without_witness().hex()
        spent = [CTxOut(amount, spk) for amount, spk in utxos]

        input_vectors = []
        for i, s in enumerate(spends):
            tree, schemes = s["tree"], s["schemes"]
            hash_type, annex = s["hash_type"], s.get("annex")
            needs_ec, padding = s.get("needs_ec", False), s.get("padding")
            script, version = tree.leaf_script(0)
            control = tree.control_block(0)

            # A leaf that checks nothing signs nothing, and publishes no
            # message: there is no signature for one to be the message of.
            msg = sighash = None
            if schemes or needs_ec:
                msg, sighash = self.sighash_for(tx, spent, i, script,
                                                hash_type, annex)

            # Witness order is the reverse of the order the script consumes
            # the checks in: the last OP_CHECKPQSIG executed pops the
            # deepest stack items.
            witness = []
            for scheme in schemes:
                sig = self.pq_sign(scheme, sighash)
                if hash_type != SIGHASH_DEFAULT:
                    sig += bytes([hash_type])
                witness = [sig, pk[scheme]] + witness
            if needs_ec:
                ec_sig = sign_schnorr(ec_key.get_bytes(), sighash)
                if hash_type != SIGHASH_DEFAULT:
                    ec_sig += bytes([hash_type])
                witness = [ec_sig] + witness
            if padding is not None:
                witness = [bytes(padding)] + witness
            witness += [script, control]
            if annex is not None:
                witness.append(annex)
            tx.wit.vtxinwit[i].scriptWitness.stack = witness

            input_vectors.append({
                "given": {
                    "txinIndex": i,
                    "scriptTree": s["json"],
                    "leafId": 0,
                    # In leaf-script order, which for a two-scheme leaf is
                    # the reverse of the order the witness carries them.
                    "schemes": schemes,
                    "pubkeys": [pk[x].hex() for x in schemes],
                    "ecPubkey": ec_xonly.hex() if needs_ec else None,
                    "hashType": hash_type,
                    "annex": annex.hex() if annex else None,
                    "paddingSize": padding,
                },
                "intermediary": {
                    "leafHash": tapleaf_hash(script, version).hex(),
                    "merkleRoot": tree.merkle_root.hex(),
                    "controlBlock": control.hex(),
                    "pubkeyCommitments": [pq_commitment(x, pk[x]).hex()
                                          for x in schemes],
                    "sigMsg": msg.hex() if msg else None,
                    "sigHash": sighash.hex() if sighash else None,
                },
                "expected": {"witness": [w.hex() for w in witness]},
                "comment": s["comment"],
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

        invalid = self.build_invalid(t_slh, pk, slh, ml, out_spk)

        doc = {
            "version": 1,
            "comment":
                "OP_CHECKPQSIG spend vectors, a draft opcode redefining "
                "OP_SUCCESS187 inside BIP 360 P2MR leaves. Verification "
                "vectors: both schemes randomize signing, so a signature "
                "cannot be re-derived from a seed by a conforming FIPS 204 "
                "or 205 implementation, and the signature is given rather "
                "than derived. Everything else is deterministic: prevout "
                "txids are sha256('pqsig_spending/prevout/<n>') and the EC "
                "key is sha256('pqsig_spending/key/0'). Scheme ids are 1 "
                "for ML-DSA-44 and 2 for SLH-DSA-SHA2-128s; the leaf "
                "commits to scheme_byte || TaggedHash('PQPubKeyHash', "
                "pubkey). Where a leaf checks two schemes, schemes and "
                "pubkeys are in the order the leaf script checks them, "
                "which is the reverse of the order their witness elements "
                "appear: the first check executed pops the elements "
                "nearest the top of the stack. "
                "Verify these with the draft SCRIPT_VERIFY_PQSIG flag set. "
                "Without it 0xbb is still OP_SUCCESS187, which succeeds "
                "before any other rule is looked at, so every invalid "
                "vector here would be accepted and every valid one would "
                "pass for the wrong reason. "
                "One spend needs no signature, the leaf whose "
                "OP_CHECKPQSIG sits in a branch that never runs; for it "
                "hashType, sigMsg and sigHash are null. paddingSize is the "
                "size of the leading witness element where a vector "
                "carries one, and null elsewhere.",
            "scriptPathSpending": [valid_group],
            "invalidSpending": invalid,
        }

        with open(self.options.output, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=1)
            f.write("\n")
        self.log.info(f"wrote {self.options.output}")

    def build_invalid(self, tree, pk, slh, ml, out_spk):
        """One single-input transaction per case. The cases that start from
        a valid spend share a shape, so one signature serves all of them.
        The last two commit to a malformed leaf and therefore to a
        different output, which makes that signature wrong for them; it
        never gets looked at, because the commitment is checked before the
        signature is."""
        invalid = []
        script, version = tree.leaf_script(0)
        control = tree.control_block(0)

        base = build_tx(1, [(90000, out_spk)])
        base_spent = [CTxOut(100000, tree.script_pubkey)]
        _, sighash = self.sighash_for(base, base_spent, 0, script,
                                      SIGHASH_DEFAULT)
        sig = self.pq_sign(slh, sighash)

        def case(vector_id, spk, witness, error, comment):
            itx = build_tx(1, [(90000, out_spk)])
            itx.wit.vtxinwit[0].scriptWitness.stack = witness
            invalid.append({
                "id": vector_id,
                "given": {
                    "rawTx": itx.serialize().hex(),
                    "utxoSpent": {"scriptPubKey": spk.hex(),
                                  "amountSats": 100000},
                },
                "expected": {"error": error},
                "comment": comment,
            })

        spk = tree.script_pubkey
        case("pqsig_spend_invalid_signature", spk,
             [bytes([sig[0] ^ 0x01]) + sig[1:], pk[slh], script, control],
             "invalid signature",
             "first byte of an otherwise valid signature flipped")

        case("pqsig_spend_wrong_pubkey", spk,
             [sig, bytes([pk[slh][0] ^ 0x01]) + pk[slh][1:], script, control],
             "public key does not match the commitment",
             "a correctly sized public key that the leaf does not commit to")

        case("pqsig_spend_pubkey_wrong_size", spk,
             [sig, pk[slh] + b"\x00", script, control],
             "wrong object size for the scheme",
             "the public key must be exactly the scheme's size, 32 bytes "
             "for SLH-DSA-SHA2-128s")

        case("pqsig_spend_signature_too_short", spk,
             [sig[:-1], pk[slh], script, control],
             "wrong object size for the scheme",
             "a signature is the scheme's exact size, or that plus one "
             "explicit hash type byte, and nothing else")

        case("pqsig_spend_explicit_default_hashtype", spk,
             [sig + b"\x00", pk[slh], script, control],
             "invalid hash type",
             "an explicit 0x00 hash type byte is rejected, the rule BIP 341 "
             "applies to 65-byte Schnorr signatures")

        case("pqsig_spend_oversized_element", spk,
             [bytes(PQ_MAX_ELEMENT_SIZE + 1), pk[slh], script, control],
             "witness element too large",
             "a leaf containing OP_CHECKPQSIG lifts the element bound to "
             "8192 bytes, and one byte past it is still rejected")

        case("pqsig_spend_empty_signature", spk,
             [b"", pk[slh], script, control],
             "script evaluated false",
             "an empty signature pushes false and consumes no budget "
             "instead of failing the script, so evaluation ends false")

        case("pqsig_spend_empty_signature_other_scheme_pubkey", spk,
             [b"", pk[ml], script, control],
             "script evaluated false",
             "the same false push with a public key of the other scheme's "
             "size, 1312 bytes against an SLH-DSA leaf. On the empty "
             "signature path the key is deliberately not inspected: a "
             "branch over two schemes leaves the other scheme's key on the "
             "stack, and rejecting on size here would fail the IF/ELSE "
             "construction the rule exists to keep cheap")

        # Leaves that are malformed in themselves, each in its own tree so
        # the witness program commits to the broken leaf.
        short_leaf = CScript([bytes(32), OP_CHECKPQSIG])
        t_short = Tree([leaf_json(0, short_leaf), leaf_json(1, CScript([OP_RETURN]))])
        case("pqsig_spend_commitment_too_short", t_short.script_pubkey,
             [sig, pk[slh], bytes(short_leaf), t_short.control_block(0)],
             "wrong object size for the scheme",
             "the commitment is 33 bytes, a scheme byte and a 32-byte "
             "hash; 32 bytes alone is not a commitment")

        # The relaxed bound is scoped to leaves that contain the opcode. A
        # leaf without it keeps the 520-byte limit, so an element the PQ
        # leaf above carries happily is refused here.
        plain_leaf = CScript([OP_DROP, OP_1])
        t_plain = Tree([leaf_json(0, plain_leaf), leaf_json(1, CScript([OP_RETURN]))])
        case("pqsig_spend_large_element_in_plain_leaf", t_plain.script_pubkey,
             [bytes(521), bytes(plain_leaf), t_plain.control_block(0)],
             "witness element too large",
             "521 bytes in a leaf with no OP_CHECKPQSIG: the larger bound "
             "belongs to leaves that contain the opcode and does not leak "
             "to the rest of the tree")

        bad_scheme_leaf = CScript([bytes([0x7f]) + bytes(32), OP_CHECKPQSIG])
        t_bad = Tree([leaf_json(0, bad_scheme_leaf), leaf_json(1, CScript([OP_RETURN]))])
        case("pqsig_spend_unknown_scheme", t_bad.script_pubkey,
             [sig, pk[slh], bytes(bad_scheme_leaf), t_bad.control_block(0)],
             "unknown scheme",
             "scheme byte 0x7f is not one this build verifies, and unknown "
             "schemes fail rather than being treated as anyone-can-spend")

        return invalid


if __name__ == "__main__":
    PQSigVectorTool(__file__).main()
