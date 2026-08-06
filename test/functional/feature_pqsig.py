#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the draft OP_CHECKPQSIG opcode on regtest, through real blocks.

The sighash, the witness and the block are built here, so the consensus
rules meet an independent implementation of the BIP 341/342 signature
message. The post-quantum signature itself cannot be produced in Python,
so that one primitive comes from the pqsignhash RPC; everything the
opcode actually rules on is assembled on this side.

Spends land through submitblock rather than the mempool: a multi-kB
signature is over the 80-byte standard stack item limit, so relay policy
turns these away whatever consensus thinks.
"""

from test_framework.blocktools import (
    add_witness_commitment,
    create_block,
    create_coinbase,
)
from test_framework.key import (
    ECKey,
    compute_xonly_pubkey,
    sign_schnorr,
    tweak_add_privkey,
)
from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
)
from test_framework.script import (
    CScript,
    CScriptOp,
    LEAF_VERSION_TAPSCRIPT,
    OP_1,
    OP_2,
    OP_2DROP,
    OP_2DUP,
    OP_CHECKSIG,
    OP_RETURN,
    OP_VERIFY,
    TaggedHash,
    TaprootSignatureHash,
    ser_string,
    taproot_construct,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import MiniWallet

# Redefinition of OP_SUCCESS187 under SCRIPT_VERIFY_PQSIG.
OP_CHECKPQSIG = CScriptOp(0xbb)
# The control byte carries the leaf version in its upper 7 bits; the low bit
# is unused and must be 1 (BIP 360, Script Validation).
CONTROL_BYTE = LEAF_VERSION_TAPSCRIPT | 1

SCHEMES = {
    "slh-dsa-sha2-128s": {"byte": 2, "seed": bytes([0x17]) * 48, "sig_len": 7856},
    "ml-dsa-44": {"byte": 1, "seed": bytes([0x2b]) * 32, "sig_len": 2420},
}


def tapleaf_hash(script):
    return TaggedHash("TapLeaf", bytes([LEAF_VERSION_TAPSCRIPT]) + ser_string(script))


def tapbranch_hash(a, b):
    return TaggedHash("TapBranch", b''.join(sorted([a, b])))


def pq_leaf(scheme_byte, pubkey):
    """<scheme_byte || H(pubkey)> OP_CHECKPQSIG, the 35-byte leaf the design
    note specifies."""
    commitment = bytes([scheme_byte]) + TaggedHash("PQPubKeyHash", pubkey)
    return CScript([commitment, OP_CHECKPQSIG])


class PQSigTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def pq_pubkey(self, scheme):
        return bytes.fromhex(self.nodes[0].pqpubkey(scheme, SCHEMES[scheme]["seed"].hex())["pubkey"])

    def pq_sign(self, scheme, sighash):
        result = self.nodes[0].pqsignhash(scheme, SCHEMES[scheme]["seed"].hex(), sighash.hex())
        return bytes.fromhex(result["signature"])

    def two_leaf_tree(self, leaf):
        """A two-leaf tree, so the output is not depth-0 anyone-can-spend."""
        other = CScript([OP_RETURN])
        h_leaf, h_other = tapleaf_hash(leaf), tapleaf_hash(other)
        root = tapbranch_hash(h_leaf, h_other)
        control = bytes([CONTROL_BYTE]) + h_other
        return CScript([OP_2, root]), control

    def fund(self, script_pubkey, amount_sat=100000):
        sent = self.wallet.send_to(from_node=self.nodes[0], scriptPubKey=script_pubkey, amount=amount_sat)
        self.generate(self.wallet, 1)
        return sent['tx'], sent['sent_vout'], amount_sat

    def spend_tx(self, funded, fee_sat=5000):
        prev_tx, vout, amount = funded
        tx = CTransaction()
        tx.vin = [CTxIn(COutPoint(prev_tx.txid_int, vout))]
        tx.vout = [CTxOut(amount - fee_sat, self.wallet.get_output_script())]
        tx.wit.vtxinwit = [CTxInWitness()]
        return tx

    def sighash_for(self, tx, funded, leaf):
        prev_tx, vout, _ = funded
        return TaprootSignatureHash(
            tx, [prev_tx.vout[vout]], hash_type=0, input_index=0,
            scriptpath=True, leaf_script=leaf, codeseparator_pos=0xFFFFFFFF,
        )

    def submit_block_with(self, tx, accept, reason=None):
        """Mine a hand-built block containing tx: consensus, not policy."""
        node = self.nodes[0]
        tip = int(node.getbestblockhash(), 16)
        height = node.getblockcount() + 1
        block = create_block(tip, create_coinbase(height),
                             ntime=node.getblock(node.getbestblockhash())['time'] + 1)
        block.vtx.append(tx)
        add_witness_commitment(block)
        block.solve()
        response = node.submitblock(block.serialize().hex())
        if accept:
            assert_equal(response, None)
            assert_equal(node.getbestblockhash(), block.hash_hex)
        else:
            assert response is not None, "block was accepted but should not have been"
            if reason is not None:
                assert reason in response, f"expected {reason!r} in {response!r}"
            assert node.getbestblockhash() != block.hash_hex

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])
        self.generate(self.wallet, 101)

        for scheme in SCHEMES:
            self.log.info(f"{scheme}: spending a PQ leaf through a block")
            self.test_valid_spend(scheme)
            self.log.info(f"{scheme}: a tampered signature is rejected by consensus")
            self.test_tampered_signature(scheme)
            self.log.info(f"{scheme}: a public key that misses the commitment is rejected")
            self.test_wrong_pubkey(scheme)
            self.log.info(f"{scheme}: a valid signature under a substituted key is rejected")
            self.test_substituted_key(scheme)

        self.log.info("a PQ spend is nonstandard, so it never reaches a block through the mempool")
        self.test_nonstandard_in_mempool()
        self.log.info("one leaf can require a PQ and an EC signature together")
        self.test_hybrid_leaf()
        self.log.info("one leaf can require both schemes")
        self.test_both_schemes()
        self.log.info("witness cost of each spend type")
        self.test_witness_weight()
        self.log.info("the validation weight budget boundary, per scheme")
        self.test_validation_weight_budget()

    def prepare(self, scheme):
        """Fund a two-leaf tree whose PQ leaf commits to the scheme's key."""
        pubkey = self.pq_pubkey(scheme)
        leaf = pq_leaf(SCHEMES[scheme]["byte"], pubkey)
        spk, control = self.two_leaf_tree(leaf)
        funded = self.fund(spk)
        tx = self.spend_tx(funded)
        sighash = self.sighash_for(tx, funded, leaf)
        return pubkey, leaf, control, funded, tx, sighash

    def test_valid_spend(self, scheme):
        pubkey, leaf, control, _funded, tx, sighash = self.prepare(scheme)
        sig = self.pq_sign(scheme, sighash)
        assert_equal(len(sig), SCHEMES[scheme]["sig_len"])
        tx.wit.vtxinwit[0].scriptWitness.stack = [sig, pubkey, bytes(leaf), control]
        self.submit_block_with(tx, accept=True)

    def test_tampered_signature(self, scheme):
        pubkey, leaf, control, _funded, tx, sighash = self.prepare(scheme)
        sig = bytearray(self.pq_sign(scheme, sighash))
        sig[len(sig) // 2] ^= 0x01
        tx.wit.vtxinwit[0].scriptWitness.stack = [bytes(sig), pubkey, bytes(leaf), control]
        self.submit_block_with(tx, accept=False, reason="block-script-verify-flag-failed")

    def test_wrong_pubkey(self, scheme):
        """A correctly sized key that is not the one the leaf commits to."""
        pubkey, leaf, control, _funded, tx, sighash = self.prepare(scheme)
        sig = self.pq_sign(scheme, sighash)
        other = bytearray(pubkey)
        other[-1] ^= 0x01
        tx.wit.vtxinwit[0].scriptWitness.stack = [sig, bytes(other), bytes(leaf), control]
        self.submit_block_with(tx, accept=False, reason="block-script-verify-flag-failed")

    def test_substituted_key(self, scheme):
        """The theft case: a signature that verifies perfectly, under a key
        the spender chose instead of the one the leaf commits to. Only the
        commitment stands between this and anyone spending the output."""
        _pubkey, leaf, control, funded, tx, sighash = self.prepare(scheme)

        attacker_seed = bytes([0x99]) * len(SCHEMES[scheme]["seed"])
        node = self.nodes[0]
        attacker_pubkey = bytes.fromhex(node.pqpubkey(scheme, attacker_seed.hex())["pubkey"])
        signed = node.pqsignhash(scheme, attacker_seed.hex(), sighash.hex())
        attacker_sig = bytes.fromhex(signed["signature"])
        # The two RPCs agree on which key a seed produces.
        assert_equal(signed["pubkey"], attacker_pubkey.hex())

        tx.wit.vtxinwit[0].scriptWitness.stack = [attacker_sig, attacker_pubkey, bytes(leaf), control]
        self.submit_block_with(tx, accept=False, reason="block-script-verify-flag-failed")

    def test_nonstandard_in_mempool(self):
        """Consensus accepts these spends, relay policy does not. The witness
        never reaches script verification: the standard stack item limit is
        80 bytes and the smallest PQ signature here is 2420, so the spend is
        turned away on witness shape alone."""
        scheme = "ml-dsa-44"
        pubkey, leaf, control, _funded, tx, sighash = self.prepare(scheme)
        sig = self.pq_sign(scheme, sighash)
        tx.wit.vtxinwit[0].scriptWitness.stack = [sig, pubkey, bytes(leaf), control]
        assert_raises_rpc_error(-26, "bad-witness-nonstandard",
                                self.nodes[0].sendrawtransaction, tx.serialize().hex())
        # The same transaction is fine in a block.
        self.submit_block_with(tx, accept=True)

    def test_hybrid_leaf(self):
        scheme = "slh-dsa-sha2-128s"
        ec_key = ECKey()
        ec_key.generate()
        xonly = compute_xonly_pubkey(ec_key.get_bytes())[0]

        pq_pubkey = self.pq_pubkey(scheme)
        commitment = bytes([SCHEMES[scheme]["byte"]]) + TaggedHash("PQPubKeyHash", pq_pubkey)
        leaf = CScript([commitment, OP_CHECKPQSIG, OP_VERIFY, xonly, OP_CHECKSIG])
        spk, control = self.two_leaf_tree(leaf)
        funded = self.fund(spk)
        tx = self.spend_tx(funded)
        sighash = self.sighash_for(tx, funded, leaf)

        pq_sig = self.pq_sign(scheme, sighash)
        ec_sig = sign_schnorr(ec_key.get_bytes(), sighash)
        tx.wit.vtxinwit[0].scriptWitness.stack = [ec_sig, pq_sig, pq_pubkey, bytes(leaf), control]
        self.submit_block_with(tx, accept=True)

    def test_both_schemes(self):
        slh, ml = "slh-dsa-sha2-128s", "ml-dsa-44"
        slh_pubkey, ml_pubkey = self.pq_pubkey(slh), self.pq_pubkey(ml)
        slh_commit = bytes([SCHEMES[slh]["byte"]]) + TaggedHash("PQPubKeyHash", slh_pubkey)
        ml_commit = bytes([SCHEMES[ml]["byte"]]) + TaggedHash("PQPubKeyHash", ml_pubkey)
        leaf = CScript([ml_commit, OP_CHECKPQSIG, OP_VERIFY, slh_commit, OP_CHECKPQSIG])
        spk, control = self.two_leaf_tree(leaf)
        funded = self.fund(spk)
        tx = self.spend_tx(funded)
        sighash = self.sighash_for(tx, funded, leaf)

        tx.wit.vtxinwit[0].scriptWitness.stack = [
            self.pq_sign(slh, sighash), slh_pubkey,
            self.pq_sign(ml, sighash), ml_pubkey,
            bytes(leaf), control,
        ]
        self.submit_block_with(tx, accept=True)

    def test_witness_weight(self):
        """One row per spend type, all spent for real through blocks. The
        witness size is fully determined by the construction, so those are
        asserted exactly; weight and vsize depend on the surrounding
        transaction and are logged for the record."""
        rows = []

        def record(name, tx):
            raw = tx.serialize().hex()
            self.submit_block_with(tx, accept=True)
            info = self.nodes[0].decoderawtransaction(raw)
            # The serialized witness of the input, which is the same object
            # the BIP 342 budget is computed from: the element count and the
            # elements with their prefixes.
            witness = len(tx.wit.vtxinwit[0].serialize())
            rows.append((name, witness, info['weight'], info['vsize']))
            return witness

        ec_key = ECKey()
        ec_key.generate()
        xonly = compute_xonly_pubkey(ec_key.get_bytes())[0]
        leaf_ec = CScript([xonly, OP_CHECKSIG])

        # P2TR key path: the cheapest spend Bitcoin has today.
        tap = taproot_construct(xonly)
        funded = self.fund(tap.scriptPubKey)
        tx = self.spend_tx(funded)
        prev_tx, vout, _ = funded
        sighash = TaprootSignatureHash(tx, [prev_tx.vout[vout]], hash_type=0,
                                       input_index=0, scriptpath=False)
        sig = sign_schnorr(tweak_add_privkey(ec_key.get_bytes(), tap.tweak), sighash)
        tx.wit.vtxinwit[0].scriptWitness.stack = [sig]
        record("p2tr key path", tx)

        # P2TR script path over the same leaf, two-leaf tree.
        tap = taproot_construct(xonly, [("a", leaf_ec), ("b", CScript([OP_RETURN]))])
        funded = self.fund(tap.scriptPubKey)
        tx = self.spend_tx(funded)
        tapleaf = tap.leaves["a"]
        sighash = self.sighash_for(tx, funded, leaf_ec)
        control = bytes([tapleaf.version + tap.negflag]) + tap.internal_pubkey + tapleaf.merklebranch
        tx.wit.vtxinwit[0].scriptWitness.stack = [
            sign_schnorr(ec_key.get_bytes(), sighash), bytes(leaf_ec), control]
        record("p2tr script path", tx)

        # The same leaf under P2MR: 32 fewer witness bytes, no internal key.
        spk, control = self.two_leaf_tree(leaf_ec)
        funded = self.fund(spk)
        tx = self.spend_tx(funded)
        sighash = self.sighash_for(tx, funded, leaf_ec)
        tx.wit.vtxinwit[0].scriptWitness.stack = [
            sign_schnorr(ec_key.get_bytes(), sighash), bytes(leaf_ec), control]
        record("p2mr ec leaf", tx)

        # The PQ leaves, one per scheme.
        for scheme in ("ml-dsa-44", "slh-dsa-sha2-128s"):
            pubkey, leaf, control, _funded, tx, sighash = self.prepare(scheme)
            sig = self.pq_sign(scheme, sighash)
            tx.wit.vtxinwit[0].scriptWitness.stack = [sig, pubkey, bytes(leaf), control]
            record(f"p2mr {scheme}", tx)

        # The hybrid leaf: one EC and one SLH-DSA signature together.
        scheme = "slh-dsa-sha2-128s"
        pq_pubkey = self.pq_pubkey(scheme)
        commitment = bytes([SCHEMES[scheme]["byte"]]) + TaggedHash("PQPubKeyHash", pq_pubkey)
        leaf = CScript([commitment, OP_CHECKPQSIG, OP_VERIFY, xonly, OP_CHECKSIG])
        spk, control = self.two_leaf_tree(leaf)
        funded = self.fund(spk)
        tx = self.spend_tx(funded)
        sighash = self.sighash_for(tx, funded, leaf)
        tx.wit.vtxinwit[0].scriptWitness.stack = [
            sign_schnorr(ec_key.get_bytes(), sighash),
            self.pq_sign(scheme, sighash), pq_pubkey, bytes(leaf), control]
        record("p2mr hybrid ec+slh-dsa", tx)

        for name, witness, weight, vsize in rows:
            self.log.info(f"  {name}: witness {witness} B, weight {weight}, vsize {vsize}")

        witness = {name: wit for name, wit, _, _ in rows}
        assert_equal(witness["p2tr key path"], 66)
        assert_equal(witness["p2tr script path"], 167)
        assert_equal(witness["p2mr ec leaf"], 135)
        assert_equal(witness["p2mr ml-dsa-44"], 3809)
        assert_equal(witness["p2mr slh-dsa-sha2-128s"], 7963)
        assert_equal(witness["p2mr hybrid ec+slh-dsa"], 8063)
        # The P2MR discount is exactly the internal key.
        assert_equal(witness["p2tr script path"] - witness["p2mr ec leaf"], 32)
        # The hybrid adds one Schnorr signature (65 bytes with its prefix)
        # and 35 leaf bytes (OP_VERIFY, the x-only key push, OP_CHECKSIG)
        # on top of the pure SLH-DSA spend.
        assert_equal(witness["p2mr hybrid ec+slh-dsa"] - witness["p2mr slh-dsa-sha2-128s"], 100)

    def test_validation_weight_budget(self):
        """The calibrated per-scheme costs, pinned from both sides through
        blocks. A repeated check funds no extra signature bytes, so the
        budget carried by one signature's witness runs out: at cost 1000 an
        SLH-DSA witness funds eight checks, at cost 200 an ML-DSA witness
        funds twenty-three."""
        boundaries = (("slh-dsa-sha2-128s", 8), ("ml-dsa-44", 23))
        for scheme, affordable in boundaries:
            pubkey = self.pq_pubkey(scheme)
            commitment = bytes([SCHEMES[scheme]["byte"]]) + TaggedHash("PQPubKeyHash", pubkey)
            for checks, accept in ((affordable, True), (affordable + 1, False)):
                leaf = CScript([OP_2DUP, commitment, OP_CHECKPQSIG, OP_VERIFY] * checks
                               + [OP_2DROP, OP_1])
                spk, control = self.two_leaf_tree(leaf)
                funded = self.fund(spk)
                tx = self.spend_tx(funded)
                sighash = self.sighash_for(tx, funded, leaf)
                sig = self.pq_sign(scheme, sighash)
                tx.wit.vtxinwit[0].scriptWitness.stack = [sig, pubkey, bytes(leaf), control]
                if accept:
                    self.submit_block_with(tx, accept=True)
                else:
                    self.submit_block_with(
                        tx, accept=False,
                        reason="block-script-verify-flag-failed (Too much signature "
                               "validation relative to witness weight)")
            self.log.info(f"  {scheme}: {affordable} checks pass, "
                          f"{affordable + 1} exhaust the budget")


if __name__ == '__main__':
    PQSigTest(__file__).main()
