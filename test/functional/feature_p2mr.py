#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test BIP 360 P2MR (pay-to-Merkle-root) outputs on regtest.

Witnesses are built here rather than through the P2MR RPCs, so the
consensus rules are checked against an independent implementation of the
BIP 341/342 signature message.
"""

from decimal import Decimal

from test_framework.blocktools import (
    add_witness_commitment,
    create_block,
    create_coinbase,
)
from test_framework.key import ECKey, compute_xonly_pubkey, sign_schnorr
from test_framework.messages import (
    COIN,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
)
from test_framework.script import (
    ANNEX_TAG,
    CScript,
    LEAF_VERSION_TAPSCRIPT,
    OP_2,
    OP_2DUP,
    OP_CHECKSIG,
    OP_CHECKSIGVERIFY,
    OP_DROP,
    TaggedHash,
    TaprootSignatureHash,
    ser_string,
    taproot_construct,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import MiniWallet

# The control byte carries the leaf version in its upper 7 bits; the low bit
# is unused and must be 1 (BIP 360, Script Validation).
CONTROL_BYTE = LEAF_VERSION_TAPSCRIPT | 1
# src/policy/policy.h MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE
MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE = 80


def tapleaf_hash(script, version=LEAF_VERSION_TAPSCRIPT):
    return TaggedHash("TapLeaf", bytes([version]) + ser_string(script))


def tapbranch_hash(a, b):
    return TaggedHash("TapBranch", b''.join(sorted([a, b])))


class P2MRTree:
    """A script tree built here rather than by the node, with each leaf's
    P2MR control block. The shape is our own (it matches createp2mraddress
    up to four leaves, and deliberately need not beyond that): BIP 360
    commits to the root, not to a particular tree shape."""

    def __init__(self, scripts):
        self.scripts = scripts
        hashes = [tapleaf_hash(s) for s in scripts]
        paths = [[] for _ in scripts]
        # Build level by level, recording each leaf's sibling hashes.
        nodes = [(h, [i]) for i, h in enumerate(hashes)]
        while len(nodes) > 1:
            nxt = []
            for i in range(0, len(nodes) - 1, 2):
                (lh, li), (rh, ri) = nodes[i], nodes[i + 1]
                for idx in li:
                    paths[idx].append(rh)
                for idx in ri:
                    paths[idx].append(lh)
                nxt.append((tapbranch_hash(lh, rh), li + ri))
            if len(nodes) % 2:
                nxt.append(nodes[-1])
            nodes = nxt
        self.merkle_root = nodes[0][0]
        self.leaf_hashes = hashes
        self.control_blocks = [bytes([CONTROL_BYTE]) + b''.join(p) for p in paths]

    @property
    def script_pubkey(self):
        return CScript([OP_2, self.merkle_root])


class P2MRTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def fund(self, script_pubkey, amount_sat=100000):
        """Create an output paying script_pubkey and mine it."""
        sent = self.wallet.send_to(from_node=self.nodes[0], scriptPubKey=script_pubkey, amount=amount_sat)
        self.generate(self.wallet, 1)
        return sent['tx'], sent['sent_vout'], amount_sat

    def spend_tx(self, funded, fee_sat=1000):
        """A transaction spending the funded P2MR output back to the wallet."""
        prev_tx, vout, amount = funded
        tx = CTransaction()
        tx.vin = [CTxIn(COutPoint(prev_tx.txid_int, vout))]
        tx.vout = [CTxOut(amount - fee_sat, self.wallet.get_output_script())]
        tx.wit.vtxinwit = [CTxInWitness()]
        return tx

    def spent_outputs(self, funded):
        prev_tx, vout, _ = funded
        return [prev_tx.vout[vout]]

    def sign_leaf(self, tx, spent_outputs, key, script, annex=None):
        sighash = TaprootSignatureHash(
            tx, spent_outputs, hash_type=0, input_index=0,
            scriptpath=True, leaf_script=script, annex=annex,
            codeseparator_pos=0xFFFFFFFF,
        )
        return sign_schnorr(key.get_bytes(), sighash)

    def submit_block_with(self, tx, accept, reason=None):
        """Mine a hand-built block containing tx (consensus, not policy)."""
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
        node = self.nodes[0]
        self.wallet = MiniWallet(node)
        self.generate(self.wallet, 110)

        keys = []
        for _ in range(4):
            k = ECKey()
            k.generate()
            keys.append(k)
        xonly = [compute_xonly_pubkey(k.get_bytes())[0] for k in keys]
        checksig = [CScript([x, OP_CHECKSIG]) for x in xonly]

        self.test_funding(checksig)
        self.test_valid_two_leaf_spend(keys, checksig)
        self.test_depth_zero(checksig)
        self.test_deeper_tree(keys, checksig)
        self.test_invalid_signature(keys, checksig)
        self.test_tampered_control_block(keys, checksig)
        self.test_block_level_rejection(keys, checksig)
        self.test_annex(keys, checksig)
        self.test_witness_weight(keys, checksig)
        self.test_validation_weight_budget(keys, checksig)
        self.test_official_vector()
        self.test_rpc_round_trip(keys, xonly)
        self.test_short_witness(checksig)
        self.test_annex_without_script(checksig)
        self.test_policy_limits(keys, checksig)
        self.test_unknown_leaf_version(checksig)

    def test_funding(self, checksig):
        self.log.info("Funding a P2MR output is standard and gives a bcrt1z address")
        tree = P2MRTree(checksig[:2])
        funded = self.fund(tree.script_pubkey)
        txid = funded[0].txid_hex
        decoded = self.nodes[0].decodescript(tree.script_pubkey.hex())
        assert_equal(decoded['type'], 'witness_v2_p2mr')
        assert decoded['address'].startswith('bcrt1z')
        info = self.nodes[0].validateaddress(decoded['address'])
        assert_equal(info['witness_version'], 2)
        assert_equal(info['scriptPubKey'], tree.script_pubkey.hex())
        assert txid in self.nodes[0].getblock(self.nodes[0].getbestblockhash())['tx']

    def test_valid_two_leaf_spend(self, keys, checksig):
        self.log.info("Spending a two-leaf tree through each leaf")
        tree = P2MRTree(checksig[:2])
        for leaf in (0, 1):
            funded = self.fund(tree.script_pubkey)
            tx = self.spend_tx(funded)
            spent = self.spent_outputs(funded)
            sig = self.sign_leaf(tx, spent, keys[leaf], tree.scripts[leaf])
            tx.wit.vtxinwit[0].scriptWitness.stack = [sig, tree.scripts[leaf], tree.control_blocks[leaf]]
            txid = self.nodes[0].sendrawtransaction(tx.serialize().hex())
            self.generate(self.wallet, 1)
            assert txid in self.nodes[0].getblock(self.nodes[0].getbestblockhash())['tx']

    def test_depth_zero(self, checksig):
        self.log.info("Depth-zero trees are anyone-can-spend, and the RPC refuses to build one")
        script = checksig[0]
        spk = CScript([OP_2, tapleaf_hash(script)])
        funded = self.fund(spk)
        tx = self.spend_tx(funded)
        # No signature: revealing the committed leaf script is enough, and
        # extra stack items are ignored because the script is never executed.
        tx.wit.vtxinwit[0].scriptWitness.stack = [b'\xde\xad', script, bytes([CONTROL_BYTE])]
        txid = self.nodes[0].sendrawtransaction(tx.serialize().hex())
        self.generate(self.wallet, 1)
        assert txid in self.nodes[0].getblock(self.nodes[0].getbestblockhash())['tx']

        # A different script does not satisfy the commitment.
        funded2 = self.fund(spk)
        tx = self.spend_tx(funded2)
        tx.wit.vtxinwit[0].scriptWitness.stack = [checksig[1], bytes([CONTROL_BYTE])]
        assert_raises_rpc_error(-26, "mempool-script-verify-flag-failed (Witness program hash mismatch)",
                                self.nodes[0].sendrawtransaction, tx.serialize().hex())

        assert_raises_rpc_error(-8, "at least two leaves",
                                self.nodes[0].createp2mraddress, [checksig[0].hex()])

    def test_deeper_tree(self, keys, checksig):
        self.log.info("Spending a four-leaf tree through a non-first leaf")
        tree = P2MRTree(checksig[:4])
        assert_equal(len(tree.control_blocks[2]), 1 + 2 * 32)
        funded = self.fund(tree.script_pubkey)
        tx = self.spend_tx(funded)
        sig = self.sign_leaf(tx, self.spent_outputs(funded), keys[2], tree.scripts[2])
        tx.wit.vtxinwit[0].scriptWitness.stack = [sig, tree.scripts[2], tree.control_blocks[2]]
        txid = self.nodes[0].sendrawtransaction(tx.serialize().hex())
        self.generate(self.wallet, 1)
        assert txid in self.nodes[0].getblock(self.nodes[0].getbestblockhash())['tx']

    def test_invalid_signature(self, keys, checksig):
        self.log.info("An invalid signature is rejected by the mempool")
        tree = P2MRTree(checksig[:2])
        funded = self.fund(tree.script_pubkey)
        tx = self.spend_tx(funded)
        sig = self.sign_leaf(tx, self.spent_outputs(funded), keys[1], tree.scripts[0])  # wrong key
        tx.wit.vtxinwit[0].scriptWitness.stack = [sig, tree.scripts[0], tree.control_blocks[0]]
        assert_raises_rpc_error(-26, "mempool-script-verify-flag-failed",
                                self.nodes[0].sendrawtransaction, tx.serialize().hex())

    def test_tampered_control_block(self, keys, checksig):
        self.log.info("Tampered control blocks are rejected")
        tree = P2MRTree(checksig[:2])
        funded = self.fund(tree.script_pubkey)
        spent = self.spent_outputs(funded)

        # Flipped byte in the Merkle path: commitment mismatch.
        tx = self.spend_tx(funded)
        sig = self.sign_leaf(tx, spent, keys[0], tree.scripts[0])
        bad = bytearray(tree.control_blocks[0])
        bad[5] ^= 1
        tx.wit.vtxinwit[0].scriptWitness.stack = [sig, tree.scripts[0], bytes(bad)]
        assert_raises_rpc_error(-26, "mempool-script-verify-flag-failed (Witness program hash mismatch)",
                                self.nodes[0].sendrawtransaction, tx.serialize().hex())

        # Control byte with the low bit cleared.
        tx = self.spend_tx(funded)
        sig = self.sign_leaf(tx, spent, keys[0], tree.scripts[0])
        bad = bytearray(tree.control_blocks[0])
        bad[0] = LEAF_VERSION_TAPSCRIPT
        tx.wit.vtxinwit[0].scriptWitness.stack = [sig, tree.scripts[0], bytes(bad)]
        assert_raises_rpc_error(-26, "mempool-script-verify-flag-failed (P2MR control byte low bit must be set)",
                                self.nodes[0].sendrawtransaction, tx.serialize().hex())

        # Wrong length.
        tx = self.spend_tx(funded)
        sig = self.sign_leaf(tx, spent, keys[0], tree.scripts[0])
        tx.wit.vtxinwit[0].scriptWitness.stack = [sig, tree.scripts[0], tree.control_blocks[0] + b'\x00']
        assert_raises_rpc_error(-26, "mempool-script-verify-flag-failed (Invalid Taproot control block size)",
                                self.nodes[0].sendrawtransaction, tx.serialize().hex())

        # Positive control: the untampered control block spends the output.
        tx = self.spend_tx(funded)
        sig = self.sign_leaf(tx, spent, keys[0], tree.scripts[0])
        tx.wit.vtxinwit[0].scriptWitness.stack = [sig, tree.scripts[0], tree.control_blocks[0]]
        self.nodes[0].sendrawtransaction(tx.serialize().hex())
        self.generate(self.wallet, 1)

    def test_block_level_rejection(self, keys, checksig):
        self.log.info("An invalid P2MR spend is rejected at block level")
        tree = P2MRTree(checksig[:2])
        funded = self.fund(tree.script_pubkey)

        # A valid spend in a hand-built block is accepted...
        tx = self.spend_tx(funded)
        sig = self.sign_leaf(tx, self.spent_outputs(funded), keys[0], tree.scripts[0])
        tx.wit.vtxinwit[0].scriptWitness.stack = [sig, tree.scripts[0], tree.control_blocks[0]]
        self.submit_block_with(tx, accept=True)

        # ...while an invalid one is not, even bypassing the mempool.
        funded2 = self.fund(tree.script_pubkey)
        tx2 = self.spend_tx(funded2)
        sig2 = bytearray(self.sign_leaf(tx2, self.spent_outputs(funded2), keys[0], tree.scripts[0]))
        sig2[10] ^= 1
        tx2.wit.vtxinwit[0].scriptWitness.stack = [bytes(sig2), tree.scripts[0], tree.control_blocks[0]]
        self.submit_block_with(tx2, accept=False, reason="block-script-verify-flag-failed (Invalid Schnorr signature)")

    def test_annex(self, keys, checksig):
        self.log.info("The annex is covered by the signature and is non-standard")
        tree = P2MRTree(checksig[:2])
        funded = self.fund(tree.script_pubkey)
        spent = self.spent_outputs(funded)
        annex = bytes([ANNEX_TAG, 0xff])

        tx = self.spend_tx(funded)
        sig = self.sign_leaf(tx, spent, keys[0], tree.scripts[0], annex=annex)
        tx.wit.vtxinwit[0].scriptWitness.stack = [sig, tree.scripts[0], tree.control_blocks[0], annex]
        # Valid by consensus, non-standard by policy: accepted in a block only.
        assert_raises_rpc_error(-26, "bad-witness-nonstandard",
                                self.nodes[0].sendrawtransaction, tx.serialize().hex())
        self.submit_block_with(tx, accept=True)

        # The signature commits to the annex contents, not just its presence:
        # swapping the annex for one of the same length fails.
        funded2 = self.fund(tree.script_pubkey)
        tx2 = self.spend_tx(funded2)
        sig2 = self.sign_leaf(tx2, self.spent_outputs(funded2), keys[0], tree.scripts[0], annex=annex)
        other_annex = bytes([ANNEX_TAG, 0x00])
        tx2.wit.vtxinwit[0].scriptWitness.stack = [sig2, tree.scripts[0], tree.control_blocks[0], other_annex]
        self.submit_block_with(tx2, accept=False, reason="block-script-verify-flag-failed (Invalid Schnorr signature)")

    def test_witness_weight(self, keys, checksig):
        """Measure P2MR spends and compare with equivalent P2TR script paths."""
        self.log.info("Witness weight: two-leaf vs deeper trees")
        results = []
        for n in (2, 4):
            tree = P2MRTree(checksig[:n])
            funded = self.fund(tree.script_pubkey)
            tx = self.spend_tx(funded)
            sig = self.sign_leaf(tx, self.spent_outputs(funded), keys[0], tree.scripts[0])
            tx.wit.vtxinwit[0].scriptWitness.stack = [sig, tree.scripts[0], tree.control_blocks[0]]
            raw = tx.serialize().hex()
            self.nodes[0].sendrawtransaction(raw)
            self.generate(self.wallet, 1)
            info = self.nodes[0].decoderawtransaction(raw)
            results.append((n, len(tree.control_blocks[0]), info['weight'], info['vsize']))
        for n, cb, weight, vsize in results:
            self.log.info(f"  {n} leaves: control block {cb} B, weight {weight}, vsize {vsize}")
        # A deeper tree costs exactly the extra 32-byte Merkle path node.
        assert_equal(results[1][1] - results[0][1], 32)
        assert_equal(results[1][2] - results[0][2], 32)   # weight, as reported by the node
        assert_equal(results[1][3] - results[0][3], 8)    # vsize

        # The same two leaves under taproot, spent through the script path.
        # BIP 360: "a P2MR witness will always be 32 bytes smaller than an
        # equivalent P2TR script path spend witness" (the internal key).
        tap = taproot_construct(compute_xonly_pubkey(keys[3].get_bytes())[0],
                                [("a", checksig[0]), ("b", checksig[1])])
        funded = self.fund(tap.scriptPubKey)
        tx = self.spend_tx(funded)
        leaf = tap.leaves["a"]
        sighash = TaprootSignatureHash(tx, self.spent_outputs(funded), hash_type=0,
                                       input_index=0, scriptpath=True,
                                       leaf_script=leaf.script,
                                       codeseparator_pos=0xFFFFFFFF)
        sig = sign_schnorr(keys[0].get_bytes(), sighash)
        control = bytes([leaf.version + tap.negflag]) + tap.internal_pubkey + leaf.merklebranch
        tx.wit.vtxinwit[0].scriptWitness.stack = [sig, leaf.script, control]
        raw = tx.serialize().hex()
        self.nodes[0].sendrawtransaction(raw)
        self.generate(self.wallet, 1)
        p2tr = self.nodes[0].decoderawtransaction(raw)
        self.log.info(f"  2 leaves as P2TR script path: control block {len(control)} B, "
                      f"weight {p2tr['weight']}, vsize {p2tr['vsize']}")
        assert_equal(len(control) - results[0][1], 32)
        assert_equal(p2tr['weight'] - results[0][2], 32)

    def test_validation_weight_budget(self, keys, checksig):
        """The BIP 342 budget is the serialized witness size plus 50, and each
        signature check that passes costs 50. A P2MR witness is 32 bytes
        smaller than the equivalent taproot script path, so it starts with 32
        less budget: the one place where the smaller control block counts
        against P2MR rather than for it."""
        self.log.info("Validation weight budget: P2MR affords one check fewer than taproot")
        key = keys[0]
        xonly = compute_xonly_pubkey(key.get_bytes())[0]

        def leaf(checks):
            """A leaf checking the same signature `checks` times. Each check
            past the first adds 2 script bytes and costs 50 of budget, so the
            budget runs out well before the script does."""
            return CScript([OP_2DUP, OP_CHECKSIGVERIFY] * (checks - 1) + [OP_CHECKSIG])

        # Three checks fit in a depth-1 P2MR spend; the fourth does not.
        for checks, accept in ((3, True), (4, False)):
            tree = P2MRTree([leaf(checks), checksig[1]])
            funded = self.fund(tree.script_pubkey)
            tx = self.spend_tx(funded)
            sig = self.sign_leaf(tx, self.spent_outputs(funded), key, tree.scripts[0])
            tx.wit.vtxinwit[0].scriptWitness.stack = [
                sig, xonly, tree.scripts[0], tree.control_blocks[0]]
            if accept:
                self.nodes[0].sendrawtransaction(tx.serialize().hex())
                self.generate(self.wallet, 1)
            else:
                self.submit_block_with(
                    tx, accept=False,
                    reason="block-script-verify-flag-failed (Too much signature "
                           "validation relative to witness weight)")

        # The same four-check leaf under taproot: the internal key in the
        # control block pays for the check that P2MR cannot afford.
        tap = taproot_construct(compute_xonly_pubkey(keys[3].get_bytes())[0],
                                [("a", leaf(4)), ("b", checksig[1])])
        funded = self.fund(tap.scriptPubKey)
        tx = self.spend_tx(funded)
        tapleaf = tap.leaves["a"]
        sighash = TaprootSignatureHash(tx, self.spent_outputs(funded), hash_type=0,
                                       input_index=0, scriptpath=True,
                                       leaf_script=tapleaf.script,
                                       codeseparator_pos=0xFFFFFFFF)
        sig = sign_schnorr(key.get_bytes(), sighash)
        control = bytes([tapleaf.version + tap.negflag]) + tap.internal_pubkey + tapleaf.merklebranch
        tx.wit.vtxinwit[0].scriptWitness.stack = [sig, xonly, tapleaf.script, control]
        self.nodes[0].sendrawtransaction(tx.serialize().hex())
        self.generate(self.wallet, 1)
        self.log.info("  four checks: rejected as P2MR, accepted as a P2TR script path")

    def test_official_vector(self):
        """Cross-check the Python tree against a published BIP 360 vector."""
        self.log.info("Reproducing an official BIP 360 construction vector")
        # p2mr_two_leaf_same_version, bitcoin/bips at commit b31410c.
        scripts = [
            CScript(bytes.fromhex("2044b178d64c32c4a05cc4f4d1407268f764c940d20ce97abfd44db5c3592b72fdac")),
            CScript(bytes.fromhex("07546170726f6f74")),
        ]
        tree = P2MRTree(scripts)
        assert_equal(tree.merkle_root.hex(),
                     "ab179431c28d3b68fb798957faf5497d69c883c6fb1e1cd9f81483d87bac90cc")
        assert_equal(tree.script_pubkey.hex(),
                     "5220ab179431c28d3b68fb798957faf5497d69c883c6fb1e1cd9f81483d87bac90cc")
        assert_equal([cb.hex() for cb in tree.control_blocks],
                     ["c12cb2b90daa543b544161530c925f285b06196940d6085ca9474d41dc3822c5cb",
                      "c164512fecdb5afa04f98839b50e6f0cb7b1e539bf6f205f67934083cdcc3c8d89"])
        # The vector's address is mainnet; the regtest one differs in both the
        # HRP and the checksum computed over it.
        decoded = self.nodes[0].decodescript(tree.script_pubkey.hex())
        assert_equal(decoded['type'], 'witness_v2_p2mr')

    def test_rpc_round_trip(self, keys, xonly):
        """createp2mraddress and signp2mrspend against the Python model."""
        self.log.info("The P2MR RPCs agree with the independently built tree")
        node = self.nodes[0]
        created = node.createp2mraddress([xonly[0].hex(), xonly[1].hex()])
        tree = P2MRTree([CScript([xonly[0], OP_CHECKSIG]), CScript([xonly[1], OP_CHECKSIG])])
        assert_equal(created['merkle_root'], tree.merkle_root.hex())
        assert_equal(created['scriptPubKey'], tree.script_pubkey.hex())
        for i in (0, 1):
            assert_equal(created['leaves'][i]['script'], tree.scripts[i].hex())
            assert_equal(created['leaves'][i]['control_block'], tree.control_blocks[i].hex())

        funded = self.fund(tree.script_pubkey)
        tx = self.spend_tx(funded)
        prevout = {"scriptPubKey": created['scriptPubKey'], "amount": Decimal(funded[2]) / COIN}
        signed = node.signp2mrspend(tx.serialize().hex(), 0, [prevout],
                                    created['leaves'][0]['script'],
                                    created['leaves'][0]['control_block'],
                                    keys[0].get_bytes().hex())
        txid = node.sendrawtransaction(signed['hex'])
        self.generate(self.wallet, 1)
        assert txid in node.getblock(node.getbestblockhash())['tx']

        # The signer refuses a control block that does not match the output.
        other = P2MRTree([CScript([xonly[2], OP_CHECKSIG]), CScript([xonly[3], OP_CHECKSIG])])
        assert_raises_rpc_error(-8, "do not reconstruct", node.signp2mrspend,
                                tx.serialize().hex(), 0, [prevout],
                                other.scripts[0].hex(), other.control_blocks[0].hex(),
                                keys[2].get_bytes().hex())
        # ...and a depth-zero control block, which would authenticate nothing.
        assert_raises_rpc_error(-8, "depth-zero", node.signp2mrspend,
                                tx.serialize().hex(), 0, [prevout],
                                created['leaves'][0]['script'], f"{CONTROL_BYTE:02x}",
                                keys[0].get_bytes().hex())

    def test_short_witness(self, checksig):
        """A witness with fewer than two elements cannot satisfy a P2MR output."""
        self.log.info("Witnesses with fewer than two elements are rejected")
        tree = P2MRTree(checksig[:2])
        funded = self.fund(tree.script_pubkey)
        for stack in ([], [tree.control_blocks[0]]):
            tx = self.spend_tx(funded)
            tx.wit.vtxinwit[0].scriptWitness.stack = stack
            assert_raises_rpc_error(-26, "mempool-script-verify-flag-failed",
                                    self.nodes[0].sendrawtransaction, tx.serialize().hex())

    def test_annex_without_script(self, checksig):
        """A two-element witness whose last element is an annex is invalid."""
        self.log.info("A witness of [script, annex] is rejected by consensus")
        tree = P2MRTree(checksig[:2])
        funded = self.fund(tree.script_pubkey)
        tx = self.spend_tx(funded)
        # Only reachable through a block: policy rejects annexes earlier.
        tx.wit.vtxinwit[0].scriptWitness.stack = [tree.scripts[0], bytes([ANNEX_TAG, 0x01])]
        self.submit_block_with(tx, accept=False,
                               reason="block-script-verify-flag-failed (Witness program hash mismatch)")

    def test_policy_limits(self, keys, checksig):
        """Stack items above the tapscript limit are non-standard."""
        self.log.info("Oversized witness stack items are non-standard but valid")
        # A leaf that drops the topmost item and then checks a signature, so
        # the witness can carry an arbitrarily sized extra element.
        leaf = CScript([OP_DROP, checksig[0][1:33], OP_CHECKSIG])
        tree = P2MRTree([leaf, checksig[1]])

        for size, standard in ((MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE, True),
                               (MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE + 1, False)):
            funded = self.fund(tree.script_pubkey)
            spent = self.spent_outputs(funded)
            tx = self.spend_tx(funded)
            sig = self.sign_leaf(tx, spent, keys[0], tree.scripts[0])
            tx.wit.vtxinwit[0].scriptWitness.stack = [sig, b'\x11' * size, tree.scripts[0], tree.control_blocks[0]]
            if standard:
                self.nodes[0].sendrawtransaction(tx.serialize().hex())
                self.generate(self.wallet, 1)
            else:
                assert_raises_rpc_error(-26, "bad-witness-nonstandard",
                                        self.nodes[0].sendrawtransaction, tx.serialize().hex())
                # Non-standard, but valid by consensus.
                self.submit_block_with(tx, accept=True)

    def test_unknown_leaf_version(self, checksig):
        """Unknown leaf versions stay unencumbered, as in taproot."""
        self.log.info("An unknown leaf version is non-standard but spendable")
        unknown_version = 0xbe
        script = checksig[0]
        sibling = tapleaf_hash(checksig[1])
        leaf = tapleaf_hash(script, unknown_version)
        root = tapbranch_hash(leaf, sibling)
        spk = CScript([OP_2, root])
        funded = self.fund(spk)
        tx = self.spend_tx(funded)
        control = bytes([unknown_version | 1]) + sibling
        tx.wit.vtxinwit[0].scriptWitness.stack = [script, control]
        assert_raises_rpc_error(-26, "mempool-script-verify-flag-failed",
                                self.nodes[0].sendrawtransaction, tx.serialize().hex())
        self.submit_block_with(tx, accept=True)


if __name__ == '__main__':
    P2MRTest(__file__).main()
