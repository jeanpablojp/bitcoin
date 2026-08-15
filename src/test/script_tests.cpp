// Copyright (c) 2011-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <common/system.h>
#include <compressor.h>
#include <core_io.h>
#include <key.h>
#include <pqc/pqc_verify.h>
#include <rpc/util.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/sigcache.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <secp256k1.h>
#include <streams.h>
#include <test/data/bip341_wallet_vectors.json.h>
#include <test/data/script_tests.json.h>
#include <test/util/common.h>
#include <test/util/json.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <test/util/transaction_utils.h>
#include <univalue.h>
#include <util/fs.h>
#include <util/strencodings.h>
#include <util/string.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <set>
#include <string>
#include <vector>

// Uncomment if you want to output updated JSON tests.
// #define UPDATE_JSON_TESTS

using namespace util::hex_literals;

static const script_verify_flags gFlags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_STRICTENC;

script_verify_flags ParseScriptFlags(std::string strFlags);

struct ScriptErrorDesc
{
    ScriptError_t err;
    const char *name;
};

static ScriptErrorDesc script_errors[]={
    {SCRIPT_ERR_OK, "OK"},
    {SCRIPT_ERR_EVAL_FALSE, "EVAL_FALSE"},
    {SCRIPT_ERR_OP_RETURN, "OP_RETURN"},
    {SCRIPT_ERR_SCRIPT_SIZE, "SCRIPT_SIZE"},
    {SCRIPT_ERR_PUSH_SIZE, "PUSH_SIZE"},
    {SCRIPT_ERR_OP_COUNT, "OP_COUNT"},
    {SCRIPT_ERR_STACK_SIZE, "STACK_SIZE"},
    {SCRIPT_ERR_SIG_COUNT, "SIG_COUNT"},
    {SCRIPT_ERR_PUBKEY_COUNT, "PUBKEY_COUNT"},
    {SCRIPT_ERR_VERIFY, "VERIFY"},
    {SCRIPT_ERR_EQUALVERIFY, "EQUALVERIFY"},
    {SCRIPT_ERR_CHECKMULTISIGVERIFY, "CHECKMULTISIGVERIFY"},
    {SCRIPT_ERR_CHECKSIGVERIFY, "CHECKSIGVERIFY"},
    {SCRIPT_ERR_NUMEQUALVERIFY, "NUMEQUALVERIFY"},
    {SCRIPT_ERR_BAD_OPCODE, "BAD_OPCODE"},
    {SCRIPT_ERR_DISABLED_OPCODE, "DISABLED_OPCODE"},
    {SCRIPT_ERR_INVALID_STACK_OPERATION, "INVALID_STACK_OPERATION"},
    {SCRIPT_ERR_INVALID_ALTSTACK_OPERATION, "INVALID_ALTSTACK_OPERATION"},
    {SCRIPT_ERR_UNBALANCED_CONDITIONAL, "UNBALANCED_CONDITIONAL"},
    {SCRIPT_ERR_NEGATIVE_LOCKTIME, "NEGATIVE_LOCKTIME"},
    {SCRIPT_ERR_UNSATISFIED_LOCKTIME, "UNSATISFIED_LOCKTIME"},
    {SCRIPT_ERR_SIG_HASHTYPE, "SIG_HASHTYPE"},
    {SCRIPT_ERR_SIG_DER, "SIG_DER"},
    {SCRIPT_ERR_MINIMALDATA, "MINIMALDATA"},
    {SCRIPT_ERR_SIG_PUSHONLY, "SIG_PUSHONLY"},
    {SCRIPT_ERR_SIG_HIGH_S, "SIG_HIGH_S"},
    {SCRIPT_ERR_SIG_NULLDUMMY, "SIG_NULLDUMMY"},
    {SCRIPT_ERR_PUBKEYTYPE, "PUBKEYTYPE"},
    {SCRIPT_ERR_CLEANSTACK, "CLEANSTACK"},
    {SCRIPT_ERR_MINIMALIF, "MINIMALIF"},
    {SCRIPT_ERR_SIG_NULLFAIL, "NULLFAIL"},
    {SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS, "DISCOURAGE_UPGRADABLE_NOPS"},
    {SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM"},
    {SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH, "WITNESS_PROGRAM_WRONG_LENGTH"},
    {SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY, "WITNESS_PROGRAM_WITNESS_EMPTY"},
    {SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH, "WITNESS_PROGRAM_MISMATCH"},
    {SCRIPT_ERR_WITNESS_MALLEATED, "WITNESS_MALLEATED"},
    {SCRIPT_ERR_WITNESS_MALLEATED_P2SH, "WITNESS_MALLEATED_P2SH"},
    {SCRIPT_ERR_WITNESS_UNEXPECTED, "WITNESS_UNEXPECTED"},
    {SCRIPT_ERR_WITNESS_PUBKEYTYPE, "WITNESS_PUBKEYTYPE"},
    {SCRIPT_ERR_TAPSCRIPT_EMPTY_PUBKEY, "TAPSCRIPT_EMPTY_PUBKEY"},
    {SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT, "TAPSCRIPT_VALIDATION_WEIGHT"},
    {SCRIPT_ERR_SCHNORR_SIG, "SCHNORR_SIG"},
    {SCRIPT_ERR_TAPROOT_WRONG_CONTROL_SIZE, "TAPROOT_WRONG_CONTROL_SIZE"},
    {SCRIPT_ERR_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION, "DISCOURAGE_UPGRADABLE_TAPROOT_VERSION"},
    {SCRIPT_ERR_P2MR_WRONG_CONTROL_BYTE, "P2MR_WRONG_CONTROL_BYTE"},
    {SCRIPT_ERR_PQSIG_SCHEME, "PQSIG_SCHEME"},
    {SCRIPT_ERR_PQSIG_SIZE, "PQSIG_SIZE"},
    {SCRIPT_ERR_PQSIG_HASHTYPE, "PQSIG_HASHTYPE"},
    {SCRIPT_ERR_PQSIG_PUBKEYHASH, "PQSIG_PUBKEYHASH"},
    {SCRIPT_ERR_PQSIG, "PQSIG"},
    {SCRIPT_ERR_OP_CODESEPARATOR, "OP_CODESEPARATOR"},
    {SCRIPT_ERR_SIG_FINDANDDELETE, "SIG_FINDANDDELETE"},
    {SCRIPT_ERR_SCRIPTNUM, "SCRIPTNUM"}
};

static std::string FormatScriptFlags(script_verify_flags flags)
{
    return util::Join(GetScriptFlagNames(flags), ",");
}

static std::string FormatScriptError(ScriptError_t err)
{
    for (const auto& se : script_errors)
        if (se.err == err)
            return se.name;
    BOOST_ERROR("Unknown scripterror enumeration value, update script_errors in script_tests.cpp.");
    return "";
}

static ScriptError_t ParseScriptError(const std::string& name)
{
    for (const auto& se : script_errors)
        if (se.name == name)
            return se.err;
    BOOST_ERROR("Unknown scripterror \"" << name << "\" in test description");
    return SCRIPT_ERR_UNKNOWN_ERROR;
}

struct ScriptTest : BasicTestingSetup {
void DoTest(const CScript& scriptPubKey, const CScript& scriptSig, const CScriptWitness& scriptWitness, script_verify_flags flags, const std::string& message, int scriptError, CAmount nValue = 0)
{
    bool expect = (scriptError == SCRIPT_ERR_OK);
    if (flags & SCRIPT_VERIFY_CLEANSTACK) {
        flags |= SCRIPT_VERIFY_P2SH;
        flags |= SCRIPT_VERIFY_WITNESS;
    }
    ScriptError err;
    const CTransaction txCredit{BuildCreditingTransaction(scriptPubKey, nValue)};
    CMutableTransaction tx = BuildSpendingTransaction(scriptSig, scriptWitness, txCredit);
    BOOST_CHECK_MESSAGE(VerifyScript(scriptSig, scriptPubKey, &scriptWitness, flags, MutableTransactionSignatureChecker(&tx, 0, txCredit.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err) == expect, message);
    BOOST_CHECK_MESSAGE(err == scriptError, FormatScriptError(err) + " where " + FormatScriptError((ScriptError_t)scriptError) + " expected: " + message);

    // Verify that removing flags from a passing test or adding flags to a failing test does not change the result.
    for (int i = 0; i < 256; ++i) {
        script_verify_flags extra_flags = script_verify_flags::from_int(m_rng.randbits(MAX_SCRIPT_VERIFY_FLAGS_BITS));
        script_verify_flags combined_flags{expect ? (flags & ~extra_flags) : (flags | extra_flags)};
        // Weed out some invalid flag combinations.
        if (combined_flags & SCRIPT_VERIFY_CLEANSTACK && ~combined_flags & (SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS)) continue;
        if (combined_flags & SCRIPT_VERIFY_WITNESS && ~combined_flags & SCRIPT_VERIFY_P2SH) continue;
        BOOST_CHECK_MESSAGE(VerifyScript(scriptSig, scriptPubKey, &scriptWitness, combined_flags, MutableTransactionSignatureChecker(&tx, 0, txCredit.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err) == expect, message + strprintf(" (with flags %x)", combined_flags.as_int()));
    }
}
}; // struct ScriptTest

void static NegateSignatureS(std::vector<unsigned char>& vchSig) {
    // Parse the signature.
    std::vector<unsigned char> r, s;
    r = std::vector<unsigned char>(vchSig.begin() + 4, vchSig.begin() + 4 + vchSig[3]);
    s = std::vector<unsigned char>(vchSig.begin() + 6 + vchSig[3], vchSig.begin() + 6 + vchSig[3] + vchSig[5 + vchSig[3]]);

    while (s.size() < 33) {
        s.insert(s.begin(), 0x00);
    }
    assert(s[0] == 0);
    // Perform mod-n negation of s by (ab)using libsecp256k1
    // (note that this function is meant to be used for negating secret keys,
    //  but it works for any non-zero scalar modulo the group order, i.e. also for s)
    int ret = secp256k1_ec_seckey_negate(secp256k1_context_static, s.data() + 1);
    assert(ret);

    if (s[1] < 0x80) {
        s.erase(s.begin());
    }

    // Reconstruct the signature.
    vchSig.clear();
    vchSig.push_back(0x30);
    vchSig.push_back(4 + r.size() + s.size());
    vchSig.push_back(0x02);
    vchSig.push_back(r.size());
    vchSig.insert(vchSig.end(), r.begin(), r.end());
    vchSig.push_back(0x02);
    vchSig.push_back(s.size());
    vchSig.insert(vchSig.end(), s.begin(), s.end());
}

namespace
{
const unsigned char vchKey0[32] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
const unsigned char vchKey1[32] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0};
const unsigned char vchKey2[32] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0};

struct KeyData
{
    CKey key0, key0C, key1, key1C, key2, key2C;
    CPubKey pubkey0, pubkey0C, pubkey0H;
    CPubKey pubkey1, pubkey1C;
    CPubKey pubkey2, pubkey2C;

    KeyData()
    {
        key0.Set(vchKey0, vchKey0 + 32, false);
        key0C.Set(vchKey0, vchKey0 + 32, true);
        pubkey0 = key0.GetPubKey();
        pubkey0H = key0.GetPubKey();
        pubkey0C = key0C.GetPubKey();
        *const_cast<unsigned char*>(pubkey0H.data()) = 0x06 | (pubkey0H[64] & 1);

        key1.Set(vchKey1, vchKey1 + 32, false);
        key1C.Set(vchKey1, vchKey1 + 32, true);
        pubkey1 = key1.GetPubKey();
        pubkey1C = key1C.GetPubKey();

        key2.Set(vchKey2, vchKey2 + 32, false);
        key2C.Set(vchKey2, vchKey2 + 32, true);
        pubkey2 = key2.GetPubKey();
        pubkey2C = key2C.GetPubKey();
    }
};

enum class WitnessMode {
    NONE,
    PKH,
    SH
};

class TestBuilder
{
private:
    //! Actually executed script
    CScript script;
    //! The P2SH redeemscript
    CScript redeemscript;
    //! The Witness embedded script
    CScript witscript;
    CScriptWitness scriptWitness;
    CTransactionRef creditTx;
    CMutableTransaction spendTx;
    bool havePush{false};
    std::vector<unsigned char> push;
    std::string comment;
    script_verify_flags flags;
    int scriptError{SCRIPT_ERR_OK};
    CAmount nValue;

    void DoPush()
    {
        if (havePush) {
            spendTx.vin[0].scriptSig << push;
            havePush = false;
        }
    }

    void DoPush(const std::vector<unsigned char>& data)
    {
        DoPush();
        push = data;
        havePush = true;
    }

public:
    TestBuilder(const CScript& script_, const std::string& comment_, script_verify_flags flags_, bool P2SH = false, WitnessMode wm = WitnessMode::NONE, int witnessversion = 0, CAmount nValue_ = 0) : script(script_), comment(comment_), flags(flags_), nValue(nValue_)
    {
        CScript scriptPubKey = script;
        if (wm == WitnessMode::PKH) {
            uint160 hash;
            CHash160().Write(std::span{script}.subspan(1)).Finalize(hash);
            script = CScript() << OP_DUP << OP_HASH160 << ToByteVector(hash) << OP_EQUALVERIFY << OP_CHECKSIG;
            scriptPubKey = CScript() << witnessversion << ToByteVector(hash);
        } else if (wm == WitnessMode::SH) {
            witscript = scriptPubKey;
            uint256 hash;
            CSHA256().Write(witscript.data(), witscript.size()).Finalize(hash.begin());
            scriptPubKey = CScript() << witnessversion << ToByteVector(hash);
        }
        if (P2SH) {
            redeemscript = scriptPubKey;
            scriptPubKey = CScript() << OP_HASH160 << ToByteVector(CScriptID(redeemscript)) << OP_EQUAL;
        }
        creditTx = MakeTransactionRef(BuildCreditingTransaction(scriptPubKey, nValue));
        spendTx = BuildSpendingTransaction(CScript(), CScriptWitness(), *creditTx);
    }

    TestBuilder& ScriptError(ScriptError_t err)
    {
        scriptError = err;
        return *this;
    }

    TestBuilder& Opcode(const opcodetype& _op)
    {
        DoPush();
        spendTx.vin[0].scriptSig << _op;
        return *this;
    }

    TestBuilder& Num(int num)
    {
        DoPush();
        spendTx.vin[0].scriptSig << num;
        return *this;
    }

    TestBuilder& Push(const std::string& hex)
    {
        DoPush(ParseHex(hex));
        return *this;
    }

    TestBuilder& Push(const CScript& _script)
    {
        DoPush(std::vector<unsigned char>(_script.begin(), _script.end()));
        return *this;
    }

    TestBuilder& PushSig(const CKey& key, int nHashType = SIGHASH_ALL, unsigned int lenR = 32, unsigned int lenS = 32, SigVersion sigversion = SigVersion::BASE, CAmount amount = 0)
    {
        uint256 hash = SignatureHash(script, spendTx, 0, nHashType, amount, sigversion);
        std::vector<unsigned char> vchSig, r, s;
        uint32_t iter = 0;
        do {
            key.Sign(hash, vchSig, false, iter++);
            if ((lenS == 33) != (vchSig[5 + vchSig[3]] == 33)) {
                NegateSignatureS(vchSig);
            }
            r = std::vector<unsigned char>(vchSig.begin() + 4, vchSig.begin() + 4 + vchSig[3]);
            s = std::vector<unsigned char>(vchSig.begin() + 6 + vchSig[3], vchSig.begin() + 6 + vchSig[3] + vchSig[5 + vchSig[3]]);
        } while (lenR != r.size() || lenS != s.size());
        vchSig.push_back(static_cast<unsigned char>(nHashType));
        DoPush(vchSig);
        return *this;
    }

    TestBuilder& PushWitSig(const CKey& key, CAmount amount = -1, int nHashType = SIGHASH_ALL, unsigned int lenR = 32, unsigned int lenS = 32, SigVersion sigversion = SigVersion::WITNESS_V0)
    {
        if (amount == -1)
            amount = nValue;
        return PushSig(key, nHashType, lenR, lenS, sigversion, amount).AsWit();
    }

    TestBuilder& Push(const CPubKey& pubkey)
    {
        DoPush(std::vector<unsigned char>(pubkey.begin(), pubkey.end()));
        return *this;
    }

    TestBuilder& PushRedeem()
    {
        DoPush(std::vector<unsigned char>(redeemscript.begin(), redeemscript.end()));
        return *this;
    }

    TestBuilder& PushWitRedeem()
    {
        DoPush(std::vector<unsigned char>(witscript.begin(), witscript.end()));
        return AsWit();
    }

    TestBuilder& EditPush(unsigned int pos, const std::string& hexin, const std::string& hexout)
    {
        assert(havePush);
        std::vector<unsigned char> datain = ParseHex(hexin);
        std::vector<unsigned char> dataout = ParseHex(hexout);
        assert(pos + datain.size() <= push.size());
        BOOST_CHECK_MESSAGE(std::vector<unsigned char>(push.begin() + pos, push.begin() + pos + datain.size()) == datain, comment);
        push.erase(push.begin() + pos, push.begin() + pos + datain.size());
        push.insert(push.begin() + pos, dataout.begin(), dataout.end());
        return *this;
    }

    TestBuilder& DamagePush(unsigned int pos)
    {
        assert(havePush);
        assert(pos < push.size());
        push[pos] ^= 1;
        return *this;
    }

    TestBuilder& Test(ScriptTest& test)
    {
        TestBuilder copy = *this; // Make a copy so we can rollback the push.
        DoPush();
        test.DoTest(creditTx->vout[0].scriptPubKey, spendTx.vin[0].scriptSig, scriptWitness, flags, comment, scriptError, nValue);
        *this = copy;
        return *this;
    }

    TestBuilder& AsWit()
    {
        assert(havePush);
        scriptWitness.stack.push_back(push);
        havePush = false;
        return *this;
    }

    UniValue GetJSON()
    {
        DoPush();
        UniValue array(UniValue::VARR);
        if (!scriptWitness.stack.empty()) {
            UniValue wit(UniValue::VARR);
            for (unsigned i = 0; i < scriptWitness.stack.size(); i++) {
                wit.push_back(HexStr(scriptWitness.stack[i]));
            }
            wit.push_back(ValueFromAmount(nValue));
            array.push_back(std::move(wit));
        }
        array.push_back(FormatScript(spendTx.vin[0].scriptSig));
        array.push_back(FormatScript(creditTx->vout[0].scriptPubKey));
        array.push_back(FormatScriptFlags(flags));
        array.push_back(FormatScriptError((ScriptError_t)scriptError));
        array.push_back(comment);
        return array;
    }

    std::string GetComment() const
    {
        return comment;
    }
};

std::string JSONPrettyPrint(const UniValue& univalue)
{
    std::string ret = univalue.write(4);
    // Workaround for libunivalue pretty printer, which puts a space between commas and newlines
    size_t pos = 0;
    while ((pos = ret.find(" \n", pos)) != std::string::npos) {
        ret.replace(pos, 2, "\n");
        pos++;
    }
    return ret;
}
} // namespace

BOOST_FIXTURE_TEST_SUITE(script_tests, ScriptTest)

BOOST_AUTO_TEST_CASE(script_build)
{
    const KeyData keys;

    std::vector<TestBuilder> tests;

    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "P2PK", 0
                               ).PushSig(keys.key0));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "P2PK, bad sig", 0
                               ).PushSig(keys.key0).DamagePush(10).ScriptError(SCRIPT_ERR_EVAL_FALSE));

    tests.push_back(TestBuilder(CScript() << OP_DUP << OP_HASH160 << ToByteVector(keys.pubkey1C.GetID()) << OP_EQUALVERIFY << OP_CHECKSIG,
                                "P2PKH", 0
                               ).PushSig(keys.key1).Push(keys.pubkey1C));
    tests.push_back(TestBuilder(CScript() << OP_DUP << OP_HASH160 << ToByteVector(keys.pubkey2C.GetID()) << OP_EQUALVERIFY << OP_CHECKSIG,
                                "P2PKH, bad pubkey", 0
                               ).PushSig(keys.key2).Push(keys.pubkey2C).DamagePush(5).ScriptError(SCRIPT_ERR_EQUALVERIFY));

    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1) << OP_CHECKSIG,
                                "P2PK anyonecanpay", 0
                               ).PushSig(keys.key1, SIGHASH_ALL | SIGHASH_ANYONECANPAY));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1) << OP_CHECKSIG,
                                "P2PK anyonecanpay marked with normal hashtype", 0
                               ).PushSig(keys.key1, SIGHASH_ALL | SIGHASH_ANYONECANPAY).EditPush(70, "81", "01").ScriptError(SCRIPT_ERR_EVAL_FALSE));

    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0C) << OP_CHECKSIG,
                                "P2SH(P2PK)", SCRIPT_VERIFY_P2SH, true
                               ).PushSig(keys.key0).PushRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0C) << OP_CHECKSIG,
                                "P2SH(P2PK), bad redeemscript", SCRIPT_VERIFY_P2SH, true
                               ).PushSig(keys.key0).PushRedeem().DamagePush(10).ScriptError(SCRIPT_ERR_EVAL_FALSE));

    tests.push_back(TestBuilder(CScript() << OP_DUP << OP_HASH160 << ToByteVector(keys.pubkey0.GetID()) << OP_EQUALVERIFY << OP_CHECKSIG,
                                "P2SH(P2PKH)", SCRIPT_VERIFY_P2SH, true
                               ).PushSig(keys.key0).Push(keys.pubkey0).PushRedeem());
    tests.push_back(TestBuilder(CScript() << OP_DUP << OP_HASH160 << ToByteVector(keys.pubkey1.GetID()) << OP_EQUALVERIFY << OP_CHECKSIG,
                                "P2SH(P2PKH), bad sig but no VERIFY_P2SH", 0, true
                               ).PushSig(keys.key0).DamagePush(10).PushRedeem());
    tests.push_back(TestBuilder(CScript() << OP_DUP << OP_HASH160 << ToByteVector(keys.pubkey1.GetID()) << OP_EQUALVERIFY << OP_CHECKSIG,
                                "P2SH(P2PKH), bad sig", SCRIPT_VERIFY_P2SH, true
                               ).PushSig(keys.key0).DamagePush(10).PushRedeem().ScriptError(SCRIPT_ERR_EQUALVERIFY));

    tests.push_back(TestBuilder(CScript() << OP_3 << ToByteVector(keys.pubkey0C) << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_3 << OP_CHECKMULTISIG,
                                "3-of-3", 0
                               ).Num(0).PushSig(keys.key0).PushSig(keys.key1).PushSig(keys.key2));
    tests.push_back(TestBuilder(CScript() << OP_3 << ToByteVector(keys.pubkey0C) << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_3 << OP_CHECKMULTISIG,
                                "3-of-3, 2 sigs", 0
                               ).Num(0).PushSig(keys.key0).PushSig(keys.key1).Num(0).ScriptError(SCRIPT_ERR_EVAL_FALSE));

    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey0C) << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_3 << OP_CHECKMULTISIG,
                                "P2SH(2-of-3)", SCRIPT_VERIFY_P2SH, true
                               ).Num(0).PushSig(keys.key1).PushSig(keys.key2).PushRedeem());
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey0C) << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_3 << OP_CHECKMULTISIG,
                                "P2SH(2-of-3), 1 sig", SCRIPT_VERIFY_P2SH, true
                               ).Num(0).PushSig(keys.key1).Num(0).PushRedeem().ScriptError(SCRIPT_ERR_EVAL_FALSE));

    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG,
                                "P2PK with too much R padding but no DERSIG", 0
                               ).PushSig(keys.key1, SIGHASH_ALL, 31, 32).EditPush(1, "43021F", "44022000"));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG,
                                "P2PK with too much R padding", SCRIPT_VERIFY_DERSIG
                               ).PushSig(keys.key1, SIGHASH_ALL, 31, 32).EditPush(1, "43021F", "44022000").ScriptError(SCRIPT_ERR_SIG_DER));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG,
                                "P2PK with too much S padding but no DERSIG", 0
                               ).PushSig(keys.key1, SIGHASH_ALL).EditPush(1, "44", "45").EditPush(37, "20", "2100"));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG,
                                "P2PK with too much S padding", SCRIPT_VERIFY_DERSIG
                               ).PushSig(keys.key1, SIGHASH_ALL).EditPush(1, "44", "45").EditPush(37, "20", "2100").ScriptError(SCRIPT_ERR_SIG_DER));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG,
                                "P2PK with too little R padding but no DERSIG", 0
                               ).PushSig(keys.key1, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220"));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG,
                                "P2PK with too little R padding", SCRIPT_VERIFY_DERSIG
                               ).PushSig(keys.key1, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").ScriptError(SCRIPT_ERR_SIG_DER));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey2C) << OP_CHECKSIG << OP_NOT,
                                "P2PK NOT with bad sig with too much R padding but no DERSIG", 0
                               ).PushSig(keys.key2, SIGHASH_ALL, 31, 32).EditPush(1, "43021F", "44022000").DamagePush(10));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey2C) << OP_CHECKSIG << OP_NOT,
                                "P2PK NOT with bad sig with too much R padding", SCRIPT_VERIFY_DERSIG
                               ).PushSig(keys.key2, SIGHASH_ALL, 31, 32).EditPush(1, "43021F", "44022000").DamagePush(10).ScriptError(SCRIPT_ERR_SIG_DER));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey2C) << OP_CHECKSIG << OP_NOT,
                                "P2PK NOT with too much R padding but no DERSIG", 0
                               ).PushSig(keys.key2, SIGHASH_ALL, 31, 32).EditPush(1, "43021F", "44022000").ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey2C) << OP_CHECKSIG << OP_NOT,
                                "P2PK NOT with too much R padding", SCRIPT_VERIFY_DERSIG
                               ).PushSig(keys.key2, SIGHASH_ALL, 31, 32).EditPush(1, "43021F", "44022000").ScriptError(SCRIPT_ERR_SIG_DER));

    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG,
                                "BIP66 example 1, without DERSIG", 0
                               ).PushSig(keys.key1, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220"));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG,
                                "BIP66 example 1, with DERSIG", SCRIPT_VERIFY_DERSIG
                               ).PushSig(keys.key1, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").ScriptError(SCRIPT_ERR_SIG_DER));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG << OP_NOT,
                                "BIP66 example 2, without DERSIG", 0
                               ).PushSig(keys.key1, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG << OP_NOT,
                                "BIP66 example 2, with DERSIG", SCRIPT_VERIFY_DERSIG
                               ).PushSig(keys.key1, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").ScriptError(SCRIPT_ERR_SIG_DER));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG,
                                "BIP66 example 3, without DERSIG", 0
                               ).Num(0).ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG,
                                "BIP66 example 3, with DERSIG", SCRIPT_VERIFY_DERSIG
                               ).Num(0).ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG << OP_NOT,
                                "BIP66 example 4, without DERSIG", 0
                               ).Num(0));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG << OP_NOT,
                                "BIP66 example 4, with DERSIG", SCRIPT_VERIFY_DERSIG
                               ).Num(0));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG,
                                "BIP66 example 5, without DERSIG", 0
                               ).Num(1).ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG,
                                "BIP66 example 5, with DERSIG", SCRIPT_VERIFY_DERSIG
                               ).Num(1).ScriptError(SCRIPT_ERR_SIG_DER));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG << OP_NOT,
                                "BIP66 example 6, without DERSIG", 0
                               ).Num(1));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG << OP_NOT,
                                "BIP66 example 6, with DERSIG", SCRIPT_VERIFY_DERSIG
                               ).Num(1).ScriptError(SCRIPT_ERR_SIG_DER));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_2 << OP_CHECKMULTISIG,
                                "BIP66 example 7, without DERSIG", 0
                               ).Num(0).PushSig(keys.key1, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").PushSig(keys.key2));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_2 << OP_CHECKMULTISIG,
                                "BIP66 example 7, with DERSIG", SCRIPT_VERIFY_DERSIG
                               ).Num(0).PushSig(keys.key1, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").PushSig(keys.key2).ScriptError(SCRIPT_ERR_SIG_DER));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_2 << OP_CHECKMULTISIG << OP_NOT,
                                "BIP66 example 8, without DERSIG", 0
                               ).Num(0).PushSig(keys.key1, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").PushSig(keys.key2).ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_2 << OP_CHECKMULTISIG << OP_NOT,
                                "BIP66 example 8, with DERSIG", SCRIPT_VERIFY_DERSIG
                               ).Num(0).PushSig(keys.key1, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").PushSig(keys.key2).ScriptError(SCRIPT_ERR_SIG_DER));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_2 << OP_CHECKMULTISIG,
                                "BIP66 example 9, without DERSIG", 0
                               ).Num(0).Num(0).PushSig(keys.key2, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_2 << OP_CHECKMULTISIG,
                                "BIP66 example 9, with DERSIG", SCRIPT_VERIFY_DERSIG
                               ).Num(0).Num(0).PushSig(keys.key2, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").ScriptError(SCRIPT_ERR_SIG_DER));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_2 << OP_CHECKMULTISIG << OP_NOT,
                                "BIP66 example 10, without DERSIG", 0
                               ).Num(0).Num(0).PushSig(keys.key2, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220"));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_2 << OP_CHECKMULTISIG << OP_NOT,
                                "BIP66 example 10, with DERSIG", SCRIPT_VERIFY_DERSIG
                               ).Num(0).Num(0).PushSig(keys.key2, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").ScriptError(SCRIPT_ERR_SIG_DER));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_2 << OP_CHECKMULTISIG,
                                "BIP66 example 11, without DERSIG", 0
                               ).Num(0).PushSig(keys.key1, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").Num(0).ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_2 << OP_CHECKMULTISIG,
                                "BIP66 example 11, with DERSIG", SCRIPT_VERIFY_DERSIG
                               ).Num(0).PushSig(keys.key1, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").Num(0).ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_2 << OP_CHECKMULTISIG << OP_NOT,
                                "BIP66 example 12, without DERSIG", 0
                               ).Num(0).PushSig(keys.key1, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").Num(0));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_2 << OP_CHECKMULTISIG << OP_NOT,
                                "BIP66 example 12, with DERSIG", SCRIPT_VERIFY_DERSIG
                               ).Num(0).PushSig(keys.key1, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").Num(0));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey2C) << OP_CHECKSIG,
                                "P2PK with multi-byte hashtype, without DERSIG", 0
                               ).PushSig(keys.key2, SIGHASH_ALL).EditPush(70, "01", "0101"));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey2C) << OP_CHECKSIG,
                                "P2PK with multi-byte hashtype, with DERSIG", SCRIPT_VERIFY_DERSIG
                               ).PushSig(keys.key2, SIGHASH_ALL).EditPush(70, "01", "0101").ScriptError(SCRIPT_ERR_SIG_DER));

    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey2C) << OP_CHECKSIG,
                                "P2PK with high S but no LOW_S", 0
                               ).PushSig(keys.key2, SIGHASH_ALL, 32, 33));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey2C) << OP_CHECKSIG,
                                "P2PK with high S", SCRIPT_VERIFY_LOW_S
                               ).PushSig(keys.key2, SIGHASH_ALL, 32, 33).ScriptError(SCRIPT_ERR_SIG_HIGH_S));

    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0H) << OP_CHECKSIG,
                                "P2PK with hybrid pubkey but no STRICTENC", 0
                               ).PushSig(keys.key0, SIGHASH_ALL));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0H) << OP_CHECKSIG,
                                "P2PK with hybrid pubkey", SCRIPT_VERIFY_STRICTENC
                               ).PushSig(keys.key0, SIGHASH_ALL).ScriptError(SCRIPT_ERR_PUBKEYTYPE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0H) << OP_CHECKSIG << OP_NOT,
                                "P2PK NOT with hybrid pubkey but no STRICTENC", 0
                               ).PushSig(keys.key0, SIGHASH_ALL).ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0H) << OP_CHECKSIG << OP_NOT,
                                "P2PK NOT with hybrid pubkey", SCRIPT_VERIFY_STRICTENC
                               ).PushSig(keys.key0, SIGHASH_ALL).ScriptError(SCRIPT_ERR_PUBKEYTYPE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0H) << OP_CHECKSIG << OP_NOT,
                                "P2PK NOT with invalid hybrid pubkey but no STRICTENC", 0
                               ).PushSig(keys.key0, SIGHASH_ALL).DamagePush(10));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0H) << OP_CHECKSIG << OP_NOT,
                                "P2PK NOT with invalid hybrid pubkey", SCRIPT_VERIFY_STRICTENC
                               ).PushSig(keys.key0, SIGHASH_ALL).DamagePush(10).ScriptError(SCRIPT_ERR_PUBKEYTYPE));
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey0H) << ToByteVector(keys.pubkey1C) << OP_2 << OP_CHECKMULTISIG,
                                "1-of-2 with the second 1 hybrid pubkey and no STRICTENC", 0
                               ).Num(0).PushSig(keys.key1, SIGHASH_ALL));
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey0H) << ToByteVector(keys.pubkey1C) << OP_2 << OP_CHECKMULTISIG,
                                "1-of-2 with the second 1 hybrid pubkey", SCRIPT_VERIFY_STRICTENC
                               ).Num(0).PushSig(keys.key1, SIGHASH_ALL));
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey0H) << OP_2 << OP_CHECKMULTISIG,
                                "1-of-2 with the first 1 hybrid pubkey", SCRIPT_VERIFY_STRICTENC
                               ).Num(0).PushSig(keys.key1, SIGHASH_ALL).ScriptError(SCRIPT_ERR_PUBKEYTYPE));

    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1) << OP_CHECKSIG,
                                "P2PK with undefined hashtype but no STRICTENC", 0
                               ).PushSig(keys.key1, 5));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1) << OP_CHECKSIG,
                                "P2PK with undefined hashtype", SCRIPT_VERIFY_STRICTENC
                               ).PushSig(keys.key1, 5).ScriptError(SCRIPT_ERR_SIG_HASHTYPE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1) << OP_CHECKSIG << OP_NOT,
                                "P2PK NOT with invalid sig and undefined hashtype but no STRICTENC", 0
                               ).PushSig(keys.key1, 5).DamagePush(10));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1) << OP_CHECKSIG << OP_NOT,
                                "P2PK NOT with invalid sig and undefined hashtype", SCRIPT_VERIFY_STRICTENC
                               ).PushSig(keys.key1, 5).DamagePush(10).ScriptError(SCRIPT_ERR_SIG_HASHTYPE));

    tests.push_back(TestBuilder(CScript() << OP_3 << ToByteVector(keys.pubkey0C) << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_3 << OP_CHECKMULTISIG,
                                "3-of-3 with nonzero dummy but no NULLDUMMY", 0
                               ).Num(1).PushSig(keys.key0).PushSig(keys.key1).PushSig(keys.key2));
    tests.push_back(TestBuilder(CScript() << OP_3 << ToByteVector(keys.pubkey0C) << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_3 << OP_CHECKMULTISIG,
                                "3-of-3 with nonzero dummy", SCRIPT_VERIFY_NULLDUMMY
                               ).Num(1).PushSig(keys.key0).PushSig(keys.key1).PushSig(keys.key2).ScriptError(SCRIPT_ERR_SIG_NULLDUMMY));
    tests.push_back(TestBuilder(CScript() << OP_3 << ToByteVector(keys.pubkey0C) << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_3 << OP_CHECKMULTISIG << OP_NOT,
                                "3-of-3 NOT with invalid sig and nonzero dummy but no NULLDUMMY", 0
                               ).Num(1).PushSig(keys.key0).PushSig(keys.key1).PushSig(keys.key2).DamagePush(10));
    tests.push_back(TestBuilder(CScript() << OP_3 << ToByteVector(keys.pubkey0C) << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_3 << OP_CHECKMULTISIG << OP_NOT,
                                "3-of-3 NOT with invalid sig with nonzero dummy", SCRIPT_VERIFY_NULLDUMMY
                               ).Num(1).PushSig(keys.key0).PushSig(keys.key1).PushSig(keys.key2).DamagePush(10).ScriptError(SCRIPT_ERR_SIG_NULLDUMMY));

    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey1C) << OP_2 << OP_CHECKMULTISIG,
                                "2-of-2 with two identical keys and sigs pushed using OP_DUP but no SIGPUSHONLY", 0
                               ).Num(0).PushSig(keys.key1).Opcode(OP_DUP));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey1C) << OP_2 << OP_CHECKMULTISIG,
                                "2-of-2 with two identical keys and sigs pushed using OP_DUP", SCRIPT_VERIFY_SIGPUSHONLY
                               ).Num(0).PushSig(keys.key1).Opcode(OP_DUP).ScriptError(SCRIPT_ERR_SIG_PUSHONLY));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey2C) << OP_CHECKSIG,
                                "P2SH(P2PK) with non-push scriptSig but no P2SH or SIGPUSHONLY", 0, true
                               ).PushSig(keys.key2).Opcode(OP_NOP8).PushRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey2C) << OP_CHECKSIG,
                                "P2PK with non-push scriptSig but with P2SH validation", SCRIPT_VERIFY_P2SH
                               ).PushSig(keys.key2).Opcode(OP_NOP8));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey2C) << OP_CHECKSIG,
                                "P2SH(P2PK) with non-push scriptSig but no SIGPUSHONLY", SCRIPT_VERIFY_P2SH, true
                               ).PushSig(keys.key2).Opcode(OP_NOP8).PushRedeem().ScriptError(SCRIPT_ERR_SIG_PUSHONLY));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey2C) << OP_CHECKSIG,
                                "P2SH(P2PK) with non-push scriptSig but not P2SH", SCRIPT_VERIFY_SIGPUSHONLY, true
                               ).PushSig(keys.key2).Opcode(OP_NOP8).PushRedeem().ScriptError(SCRIPT_ERR_SIG_PUSHONLY));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey1C) << OP_2 << OP_CHECKMULTISIG,
                                "2-of-2 with two identical keys and sigs pushed", SCRIPT_VERIFY_SIGPUSHONLY
                               ).Num(0).PushSig(keys.key1).PushSig(keys.key1));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "P2PK with unnecessary input but no CLEANSTACK", SCRIPT_VERIFY_P2SH
                               ).Num(11).PushSig(keys.key0));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "P2PK with unnecessary input", SCRIPT_VERIFY_CLEANSTACK | SCRIPT_VERIFY_P2SH
                               ).Num(11).PushSig(keys.key0).ScriptError(SCRIPT_ERR_CLEANSTACK));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "P2SH with unnecessary input but no CLEANSTACK", SCRIPT_VERIFY_P2SH, true
                               ).Num(11).PushSig(keys.key0).PushRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "P2SH with unnecessary input", SCRIPT_VERIFY_CLEANSTACK | SCRIPT_VERIFY_P2SH, true
                               ).Num(11).PushSig(keys.key0).PushRedeem().ScriptError(SCRIPT_ERR_CLEANSTACK));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "P2SH with CLEANSTACK", SCRIPT_VERIFY_CLEANSTACK | SCRIPT_VERIFY_P2SH, true
                               ).PushSig(keys.key0).PushRedeem());

    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "Basic P2WSH", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::SH,
                                0, 1).PushWitSig(keys.key0).PushWitRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0),
                                "Basic P2WPKH", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::PKH,
                                0, 1).PushWitSig(keys.key0).Push(keys.pubkey0).AsWit());
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "Basic P2SH(P2WSH)", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true, WitnessMode::SH,
                                0, 1).PushWitSig(keys.key0).PushWitRedeem().PushRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0),
                                "Basic P2SH(P2WPKH)", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true, WitnessMode::PKH,
                                0, 1).PushWitSig(keys.key0).Push(keys.pubkey0).AsWit().PushRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1) << OP_CHECKSIG,
                                "Basic P2WSH with the wrong key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::SH
                               ).PushWitSig(keys.key0).PushWitRedeem().ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1),
                                "Basic P2WPKH with the wrong key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::PKH
                               ).PushWitSig(keys.key0).Push(keys.pubkey1).AsWit().ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1) << OP_CHECKSIG,
                                "Basic P2SH(P2WSH) with the wrong key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true, WitnessMode::SH
                               ).PushWitSig(keys.key0).PushWitRedeem().PushRedeem().ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1),
                                "Basic P2SH(P2WPKH) with the wrong key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true, WitnessMode::PKH
                               ).PushWitSig(keys.key0).Push(keys.pubkey1).AsWit().PushRedeem().ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1) << OP_CHECKSIG,
                                "Basic P2WSH with the wrong key but no WITNESS", SCRIPT_VERIFY_P2SH, false, WitnessMode::SH
                               ).PushWitSig(keys.key0).PushWitRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1),
                                "Basic P2WPKH with the wrong key but no WITNESS", SCRIPT_VERIFY_P2SH, false, WitnessMode::PKH
                               ).PushWitSig(keys.key0).Push(keys.pubkey1).AsWit());
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1) << OP_CHECKSIG,
                                "Basic P2SH(P2WSH) with the wrong key but no WITNESS", SCRIPT_VERIFY_P2SH, true, WitnessMode::SH
                               ).PushWitSig(keys.key0).PushWitRedeem().PushRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1),
                                "Basic P2SH(P2WPKH) with the wrong key but no WITNESS", SCRIPT_VERIFY_P2SH, true, WitnessMode::PKH
                               ).PushWitSig(keys.key0).Push(keys.pubkey1).AsWit().PushRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "Basic P2WSH with wrong value", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::SH,
                                0, 0).PushWitSig(keys.key0, 1).PushWitRedeem().ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0),
                                "Basic P2WPKH with wrong value", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::PKH,
                                0, 0).PushWitSig(keys.key0, 1).Push(keys.pubkey0).AsWit().ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "Basic P2SH(P2WSH) with wrong value", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true, WitnessMode::SH,
                                0, 0).PushWitSig(keys.key0, 1).PushWitRedeem().PushRedeem().ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0),
                                "Basic P2SH(P2WPKH) with wrong value", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true, WitnessMode::PKH,
                                0, 0).PushWitSig(keys.key0, 1).Push(keys.pubkey0).AsWit().PushRedeem().ScriptError(SCRIPT_ERR_EVAL_FALSE));

    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0),
                                "P2WPKH with future witness version", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH |
                                SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, false, WitnessMode::PKH, 1
                               ).PushWitSig(keys.key0).Push(keys.pubkey0).AsWit().ScriptError(SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM));
    {
        CScript witscript = CScript() << ToByteVector(keys.pubkey0);
        uint256 hash;
        CSHA256().Write(witscript.data(), witscript.size()).Finalize(hash.begin());
        std::vector<unsigned char> hashBytes = ToByteVector(hash);
        hashBytes.pop_back();
        tests.push_back(TestBuilder(CScript() << OP_0 << hashBytes,
                                    "P2WPKH with wrong witness program length", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false
                                   ).PushWitSig(keys.key0).Push(keys.pubkey0).AsWit().ScriptError(SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH));
    }
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "P2WSH with empty witness", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::SH
                               ).ScriptError(SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY));
    {
        CScript witscript = CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG;
        tests.push_back(TestBuilder(witscript,
                                    "P2WSH with witness program mismatch", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::SH
                                   ).PushWitSig(keys.key0).Push(witscript).DamagePush(0).AsWit().ScriptError(SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH));
    }
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0),
                                "P2WPKH with witness program mismatch", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::PKH
                               ).PushWitSig(keys.key0).Push(keys.pubkey0).AsWit().Push("0").AsWit().ScriptError(SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0),
                                "P2WPKH with non-empty scriptSig", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::PKH
                               ).PushWitSig(keys.key0).Push(keys.pubkey0).AsWit().Num(11).ScriptError(SCRIPT_ERR_WITNESS_MALLEATED));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1),
                                "P2SH(P2WPKH) with superfluous push in scriptSig", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true, WitnessMode::PKH
                               ).PushWitSig(keys.key0).Push(keys.pubkey1).AsWit().Num(11).PushRedeem().ScriptError(SCRIPT_ERR_WITNESS_MALLEATED_P2SH));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "P2PK with witness", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH
                               ).PushSig(keys.key0).Push("0").AsWit().ScriptError(SCRIPT_ERR_WITNESS_UNEXPECTED));

    // Compressed keys should pass SCRIPT_VERIFY_WITNESS_PUBKEYTYPE
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0C) << OP_CHECKSIG,
                                "Basic P2WSH with compressed key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, false, WitnessMode::SH,
                                0, 1).PushWitSig(keys.key0C).PushWitRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0C),
                                "Basic P2WPKH with compressed key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, false, WitnessMode::PKH,
                                0, 1).PushWitSig(keys.key0C).Push(keys.pubkey0C).AsWit());
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0C) << OP_CHECKSIG,
                                "Basic P2SH(P2WSH) with compressed key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, true, WitnessMode::SH,
                                0, 1).PushWitSig(keys.key0C).PushWitRedeem().PushRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0C),
                                "Basic P2SH(P2WPKH) with compressed key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, true, WitnessMode::PKH,
                                0, 1).PushWitSig(keys.key0C).Push(keys.pubkey0C).AsWit().PushRedeem());

    // Testing uncompressed key in witness with SCRIPT_VERIFY_WITNESS_PUBKEYTYPE
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "Basic P2WSH", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, false, WitnessMode::SH,
                                0, 1).PushWitSig(keys.key0).PushWitRedeem().ScriptError(SCRIPT_ERR_WITNESS_PUBKEYTYPE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0),
                                "Basic P2WPKH", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, false, WitnessMode::PKH,
                                0, 1).PushWitSig(keys.key0).Push(keys.pubkey0).AsWit().ScriptError(SCRIPT_ERR_WITNESS_PUBKEYTYPE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "Basic P2SH(P2WSH)", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, true, WitnessMode::SH,
                                0, 1).PushWitSig(keys.key0).PushWitRedeem().PushRedeem().ScriptError(SCRIPT_ERR_WITNESS_PUBKEYTYPE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0),
                                "Basic P2SH(P2WPKH)", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, true, WitnessMode::PKH,
                                0, 1).PushWitSig(keys.key0).Push(keys.pubkey0).AsWit().PushRedeem().ScriptError(SCRIPT_ERR_WITNESS_PUBKEYTYPE));

    // P2WSH 1-of-2 multisig with compressed keys
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey0C) << OP_2 << OP_CHECKMULTISIG,
                                "P2WSH CHECKMULTISIG with compressed keys", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, false, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key0C).PushWitRedeem());
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey0C) << OP_2 << OP_CHECKMULTISIG,
                                "P2SH(P2WSH) CHECKMULTISIG with compressed keys", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, true, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key0C).PushWitRedeem().PushRedeem());
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey0C) << OP_2 << OP_CHECKMULTISIG,
                                "P2WSH CHECKMULTISIG with compressed keys", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, false, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key1C).PushWitRedeem());
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey0C) << OP_2 << OP_CHECKMULTISIG,
                                "P2SH(P2WSH) CHECKMULTISIG with compressed keys", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, true, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key1C).PushWitRedeem().PushRedeem());

    // P2WSH 1-of-2 multisig with first key uncompressed
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey0) << OP_2 << OP_CHECKMULTISIG,
                                "P2WSH CHECKMULTISIG with first key uncompressed and signing with the first key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key0).PushWitRedeem());
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey0) << OP_2 << OP_CHECKMULTISIG,
                                "P2SH(P2WSH) CHECKMULTISIG first key uncompressed and signing with the first key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key0).PushWitRedeem().PushRedeem());
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey0) << OP_2 << OP_CHECKMULTISIG,
                                "P2WSH CHECKMULTISIG with first key uncompressed and signing with the first key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, false, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key0).PushWitRedeem().ScriptError(SCRIPT_ERR_WITNESS_PUBKEYTYPE));
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey0) << OP_2 << OP_CHECKMULTISIG,
                                "P2SH(P2WSH) CHECKMULTISIG with first key uncompressed and signing with the first key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, true, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key0).PushWitRedeem().PushRedeem().ScriptError(SCRIPT_ERR_WITNESS_PUBKEYTYPE));
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey0) << OP_2 << OP_CHECKMULTISIG,
                                "P2WSH CHECKMULTISIG with first key uncompressed and signing with the second key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key1C).PushWitRedeem());
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey0) << OP_2 << OP_CHECKMULTISIG,
                                "P2SH(P2WSH) CHECKMULTISIG with first key uncompressed and signing with the second key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key1C).PushWitRedeem().PushRedeem());
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey0) << OP_2 << OP_CHECKMULTISIG,
                                "P2WSH CHECKMULTISIG with first key uncompressed and signing with the second key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, false, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key1C).PushWitRedeem().ScriptError(SCRIPT_ERR_WITNESS_PUBKEYTYPE));
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey0) << OP_2 << OP_CHECKMULTISIG,
                                "P2SH(P2WSH) CHECKMULTISIG with first key uncompressed and signing with the second key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, true, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key1C).PushWitRedeem().PushRedeem().ScriptError(SCRIPT_ERR_WITNESS_PUBKEYTYPE));
    // P2WSH 1-of-2 multisig with second key uncompressed
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1) << ToByteVector(keys.pubkey0C) << OP_2 << OP_CHECKMULTISIG,
                                "P2WSH CHECKMULTISIG with second key uncompressed and signing with the first key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key0C).PushWitRedeem());
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1) << ToByteVector(keys.pubkey0C) << OP_2 << OP_CHECKMULTISIG,
                                "P2SH(P2WSH) CHECKMULTISIG second key uncompressed and signing with the first key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key0C).PushWitRedeem().PushRedeem());
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1) << ToByteVector(keys.pubkey0C) << OP_2 << OP_CHECKMULTISIG,
                                "P2WSH CHECKMULTISIG with second key uncompressed and signing with the first key should pass as the uncompressed key is not used", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, false, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key0C).PushWitRedeem());
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1) << ToByteVector(keys.pubkey0C) << OP_2 << OP_CHECKMULTISIG,
                                "P2SH(P2WSH) CHECKMULTISIG with second key uncompressed and signing with the first key should pass as the uncompressed key is not used", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, true, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key0C).PushWitRedeem().PushRedeem());
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1) << ToByteVector(keys.pubkey0C) << OP_2 << OP_CHECKMULTISIG,
                                "P2WSH CHECKMULTISIG with second key uncompressed and signing with the second key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key1).PushWitRedeem());
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1) << ToByteVector(keys.pubkey0C) << OP_2 << OP_CHECKMULTISIG,
                                "P2SH(P2WSH) CHECKMULTISIG with second key uncompressed and signing with the second key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key1).PushWitRedeem().PushRedeem());
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1) << ToByteVector(keys.pubkey0C) << OP_2 << OP_CHECKMULTISIG,
                                "P2WSH CHECKMULTISIG with second key uncompressed and signing with the second key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, false, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key1).PushWitRedeem().ScriptError(SCRIPT_ERR_WITNESS_PUBKEYTYPE));
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1) << ToByteVector(keys.pubkey0C) << OP_2 << OP_CHECKMULTISIG,
                                "P2SH(P2WSH) CHECKMULTISIG with second key uncompressed and signing with the second key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, true, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key1).PushWitRedeem().PushRedeem().ScriptError(SCRIPT_ERR_WITNESS_PUBKEYTYPE));

    std::set<std::string> tests_set;

    {
        UniValue json_tests = read_json(json_tests::script_tests);

        for (unsigned int idx = 0; idx < json_tests.size(); idx++) {
            const UniValue& tv = json_tests[idx];
            tests_set.insert(JSONPrettyPrint(tv.get_array()));
        }
    }

#ifdef UPDATE_JSON_TESTS
    std::string strGen;
#endif
    for (TestBuilder& test : tests) {
        test.Test(*this);
        std::string str = JSONPrettyPrint(test.GetJSON());
#ifdef UPDATE_JSON_TESTS
        strGen += str + ",\n";
#else
        if (!tests_set.contains(str)) {
            BOOST_CHECK_MESSAGE(false, "Missing auto script_valid test: " + test.GetComment());
        }
#endif
    }

#ifdef UPDATE_JSON_TESTS
    FILE* file = fsbridge::fopen("script_tests.json.gen", "w");
    fputs(strGen.c_str(), file);
    fclose(file);
#endif
}

BOOST_AUTO_TEST_CASE(script_json_test)
{
    // Read tests from test/data/script_tests.json
    // Format is an array of arrays
    // Inner arrays are [ ["wit"..., nValue]?, "scriptSig", "scriptPubKey", "flags", "expected_scripterror" ]
    // ... where scriptSig and scriptPubKey are stringified
    // scripts.
    // If a witness is given, then the last value in the array should be the
    // amount (nValue) to use in the crediting tx
    UniValue tests = read_json(json_tests::script_tests);

    const KeyData keys;
    for (unsigned int idx = 0; idx < tests.size(); idx++) {
        const UniValue& test = tests[idx];
        std::string strTest = test.write();
        CScriptWitness witness;
        TaprootBuilder taprootBuilder;
        CAmount nValue = 0;
        unsigned int pos = 0;
        if (test.size() > 0 && test[pos].isArray()) {
            unsigned int i=0;
            for (i = 0; i < test[pos].size()-1; i++) {
                auto element = test[pos][i].get_str();
                // We use #SCRIPT# to flag a non-hex script that we can read using ParseScript
                // Taproot script must be third from the last element in witness stack
                static const std::string SCRIPT_FLAG{"#SCRIPT#"};
                if (element.starts_with(SCRIPT_FLAG)) {
                    CScript script = ParseScript(element.substr(SCRIPT_FLAG.size()));
                    witness.stack.push_back(ToByteVector(script));
                } else if (element == "#CONTROLBLOCK#") {
                    // Taproot script control block - second from the last element in witness stack
                    // If #CONTROLBLOCK# we auto-generate the control block
                    taprootBuilder.Add(/*depth=*/0, witness.stack.back(), TAPROOT_LEAF_TAPSCRIPT, /*track=*/true);
                    taprootBuilder.Finalize(XOnlyPubKey(keys.key0.GetPubKey()));
                    auto controlblocks = taprootBuilder.GetSpendData().scripts[{witness.stack.back(), TAPROOT_LEAF_TAPSCRIPT}];
                    witness.stack.push_back(*(controlblocks.begin()));
                } else {
                    const auto witness_value{TryParseHex<unsigned char>(element)};
                    if (!witness_value.has_value()) {
                        BOOST_ERROR("Bad witness in test: " << strTest << " witness is not hex: " << element);
                    }
                    witness.stack.push_back(witness_value.value());
                }
            }
            nValue = AmountFromValue(test[pos][i]);
            pos++;
        }
        if (test.size() < 4 + pos) // Allow size > 3; extra stuff ignored (useful for comments)
        {
            if (test.size() != 1) {
                BOOST_ERROR("Bad test: " << strTest);
            }
            continue;
        }
        std::string scriptSigString = test[pos++].get_str();
        CScript scriptSig = ParseScript(scriptSigString);
        std::string scriptPubKeyString = test[pos++].get_str();
        CScript scriptPubKey;
        // If requested, auto-generate the taproot output
        if (scriptPubKeyString == "0x51 0x20 #TAPROOTOUTPUT#") {
            BOOST_CHECK_MESSAGE(taprootBuilder.IsComplete(), "Failed to autogenerate Tapscript output key");
            scriptPubKey = CScript() << OP_1 << ToByteVector(taprootBuilder.GetOutput());
        } else {
            scriptPubKey = ParseScript(scriptPubKeyString);
        }
        script_verify_flags scriptflags = ParseScriptFlags(test[pos++].get_str());
        int scriptError = ParseScriptError(test[pos++].get_str());

        DoTest(scriptPubKey, scriptSig, witness, scriptflags, strTest, scriptError, nValue);
    }
}

BOOST_AUTO_TEST_CASE(script_PushData)
{
    // Check that PUSHDATA1, PUSHDATA2, and PUSHDATA4 create the same value on
    // the stack as the 1-75 opcodes do.
    static const unsigned char direct[] = { 1, 0x5a };
    static const unsigned char pushdata1[] = { OP_PUSHDATA1, 1, 0x5a };
    static const unsigned char pushdata2[] = { OP_PUSHDATA2, 1, 0, 0x5a };
    static const unsigned char pushdata4[] = { OP_PUSHDATA4, 1, 0, 0, 0, 0x5a };

    ScriptError err;
    std::vector<std::vector<unsigned char> > directStack;
    BOOST_CHECK(EvalScript(directStack, CScript(direct, direct + sizeof(direct)), SCRIPT_VERIFY_P2SH, BaseSignatureChecker(), SigVersion::BASE, &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));

    std::vector<std::vector<unsigned char> > pushdata1Stack;
    BOOST_CHECK(EvalScript(pushdata1Stack, CScript(pushdata1, pushdata1 + sizeof(pushdata1)), SCRIPT_VERIFY_P2SH, BaseSignatureChecker(), SigVersion::BASE, &err));
    BOOST_CHECK(pushdata1Stack == directStack);
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));

    std::vector<std::vector<unsigned char> > pushdata2Stack;
    BOOST_CHECK(EvalScript(pushdata2Stack, CScript(pushdata2, pushdata2 + sizeof(pushdata2)), SCRIPT_VERIFY_P2SH, BaseSignatureChecker(), SigVersion::BASE, &err));
    BOOST_CHECK(pushdata2Stack == directStack);
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));

    std::vector<std::vector<unsigned char> > pushdata4Stack;
    BOOST_CHECK(EvalScript(pushdata4Stack, CScript(pushdata4, pushdata4 + sizeof(pushdata4)), SCRIPT_VERIFY_P2SH, BaseSignatureChecker(), SigVersion::BASE, &err));
    BOOST_CHECK(pushdata4Stack == directStack);
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));

    const std::vector<unsigned char> pushdata1_trunc{OP_PUSHDATA1, 1};
    const std::vector<unsigned char> pushdata2_trunc{OP_PUSHDATA2, 1, 0};
    const std::vector<unsigned char> pushdata4_trunc{OP_PUSHDATA4, 1, 0, 0, 0};

    std::vector<std::vector<unsigned char>> stack_ignore;
    BOOST_CHECK(!EvalScript(stack_ignore, CScript(pushdata1_trunc.begin(), pushdata1_trunc.end()), SCRIPT_VERIFY_P2SH, BaseSignatureChecker(), SigVersion::BASE, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BAD_OPCODE);
    BOOST_CHECK(!EvalScript(stack_ignore, CScript(pushdata2_trunc.begin(), pushdata2_trunc.end()), SCRIPT_VERIFY_P2SH, BaseSignatureChecker(), SigVersion::BASE, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BAD_OPCODE);
    BOOST_CHECK(!EvalScript(stack_ignore, CScript(pushdata4_trunc.begin(), pushdata4_trunc.end()), SCRIPT_VERIFY_P2SH, BaseSignatureChecker(), SigVersion::BASE, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BAD_OPCODE);
}

BOOST_AUTO_TEST_CASE(script_cltv_truncated)
{
    const auto script_cltv_trunc = CScript() << OP_CHECKLOCKTIMEVERIFY;

    std::vector<std::vector<unsigned char>> stack_ignore;
    ScriptError err;
    BOOST_CHECK(!EvalScript(stack_ignore, script_cltv_trunc, SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY, BaseSignatureChecker(), SigVersion::BASE, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INVALID_STACK_OPERATION);
}

static CScript
sign_multisig(const CScript& scriptPubKey, const std::vector<CKey>& keys, const CTransaction& transaction)
{
    uint256 hash = SignatureHash(scriptPubKey, transaction, 0, SIGHASH_ALL, 0, SigVersion::BASE);

    CScript result;
    //
    // NOTE: CHECKMULTISIG has an unfortunate bug; it requires
    // one extra item on the stack, before the signatures.
    // Putting OP_0 on the stack is the workaround;
    // fixing the bug would mean splitting the block chain (old
    // clients would not accept new CHECKMULTISIG transactions,
    // and vice-versa)
    //
    result << OP_0;
    for (const CKey &key : keys)
    {
        std::vector<unsigned char> vchSig;
        BOOST_CHECK(key.Sign(hash, vchSig));
        vchSig.push_back((unsigned char)SIGHASH_ALL);
        result << vchSig;
    }
    return result;
}
static CScript
sign_multisig(const CScript& scriptPubKey, const CKey& key, const CTransaction& transaction)
{
    std::vector<CKey> keys;
    keys.push_back(key);
    return sign_multisig(scriptPubKey, keys, transaction);
}

BOOST_AUTO_TEST_CASE(script_CHECKMULTISIG12)
{
    ScriptError err;
    CKey key1 = GenerateRandomKey();
    CKey key2 = GenerateRandomKey(/*compressed=*/false);
    CKey key3 = GenerateRandomKey();

    CScript scriptPubKey12;
    scriptPubKey12 << OP_1 << ToByteVector(key1.GetPubKey()) << ToByteVector(key2.GetPubKey()) << OP_2 << OP_CHECKMULTISIG;

    const CTransaction txFrom12{BuildCreditingTransaction(scriptPubKey12)};
    CMutableTransaction txTo12 = BuildSpendingTransaction(CScript(), CScriptWitness(), txFrom12);

    CScript goodsig1 = sign_multisig(scriptPubKey12, key1, CTransaction(txTo12));
    BOOST_CHECK(VerifyScript(goodsig1, scriptPubKey12, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo12, 0, txFrom12.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));
    txTo12.vout[0].nValue = 2;
    BOOST_CHECK(!VerifyScript(goodsig1, scriptPubKey12, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo12, 0, txFrom12.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_EVAL_FALSE, ScriptErrorString(err));

    CScript goodsig2 = sign_multisig(scriptPubKey12, key2, CTransaction(txTo12));
    BOOST_CHECK(VerifyScript(goodsig2, scriptPubKey12, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo12, 0, txFrom12.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));

    CScript badsig1 = sign_multisig(scriptPubKey12, key3, CTransaction(txTo12));
    BOOST_CHECK(!VerifyScript(badsig1, scriptPubKey12, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo12, 0, txFrom12.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_EVAL_FALSE, ScriptErrorString(err));
}

BOOST_AUTO_TEST_CASE(script_CHECKMULTISIG23)
{
    ScriptError err;
    CKey key1 = GenerateRandomKey();
    CKey key2 = GenerateRandomKey(/*compressed=*/false);
    CKey key3 = GenerateRandomKey();
    CKey key4 = GenerateRandomKey(/*compressed=*/false);

    CScript scriptPubKey23;
    scriptPubKey23 << OP_2 << ToByteVector(key1.GetPubKey()) << ToByteVector(key2.GetPubKey()) << ToByteVector(key3.GetPubKey()) << OP_3 << OP_CHECKMULTISIG;

    const CTransaction txFrom23{BuildCreditingTransaction(scriptPubKey23)};
    CMutableTransaction txTo23 = BuildSpendingTransaction(CScript(), CScriptWitness(), txFrom23);

    std::vector<CKey> keys;
    keys.push_back(key1); keys.push_back(key2);
    CScript goodsig1 = sign_multisig(scriptPubKey23, keys, CTransaction(txTo23));
    BOOST_CHECK(VerifyScript(goodsig1, scriptPubKey23, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo23, 0, txFrom23.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));

    keys.clear();
    keys.push_back(key1); keys.push_back(key3);
    CScript goodsig2 = sign_multisig(scriptPubKey23, keys, CTransaction(txTo23));
    BOOST_CHECK(VerifyScript(goodsig2, scriptPubKey23, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo23, 0, txFrom23.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));

    keys.clear();
    keys.push_back(key2); keys.push_back(key3);
    CScript goodsig3 = sign_multisig(scriptPubKey23, keys, CTransaction(txTo23));
    BOOST_CHECK(VerifyScript(goodsig3, scriptPubKey23, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo23, 0, txFrom23.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));

    keys.clear();
    keys.push_back(key2); keys.push_back(key2); // Can't reuse sig
    CScript badsig1 = sign_multisig(scriptPubKey23, keys, CTransaction(txTo23));
    BOOST_CHECK(!VerifyScript(badsig1, scriptPubKey23, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo23, 0, txFrom23.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_EVAL_FALSE, ScriptErrorString(err));

    keys.clear();
    keys.push_back(key2); keys.push_back(key1); // sigs must be in correct order
    CScript badsig2 = sign_multisig(scriptPubKey23, keys, CTransaction(txTo23));
    BOOST_CHECK(!VerifyScript(badsig2, scriptPubKey23, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo23, 0, txFrom23.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_EVAL_FALSE, ScriptErrorString(err));

    keys.clear();
    keys.push_back(key3); keys.push_back(key2); // sigs must be in correct order
    CScript badsig3 = sign_multisig(scriptPubKey23, keys, CTransaction(txTo23));
    BOOST_CHECK(!VerifyScript(badsig3, scriptPubKey23, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo23, 0, txFrom23.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_EVAL_FALSE, ScriptErrorString(err));

    keys.clear();
    keys.push_back(key4); keys.push_back(key2); // sigs must match pubkeys
    CScript badsig4 = sign_multisig(scriptPubKey23, keys, CTransaction(txTo23));
    BOOST_CHECK(!VerifyScript(badsig4, scriptPubKey23, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo23, 0, txFrom23.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_EVAL_FALSE, ScriptErrorString(err));

    keys.clear();
    keys.push_back(key1); keys.push_back(key4); // sigs must match pubkeys
    CScript badsig5 = sign_multisig(scriptPubKey23, keys, CTransaction(txTo23));
    BOOST_CHECK(!VerifyScript(badsig5, scriptPubKey23, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo23, 0, txFrom23.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_EVAL_FALSE, ScriptErrorString(err));

    keys.clear(); // Must have signatures
    CScript badsig6 = sign_multisig(scriptPubKey23, keys, CTransaction(txTo23));
    BOOST_CHECK(!VerifyScript(badsig6, scriptPubKey23, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo23, 0, txFrom23.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_INVALID_STACK_OPERATION, ScriptErrorString(err));
}

/** Return the TxoutType of a script without exposing Solver details. */
static TxoutType GetTxoutType(const CScript& output_script)
{
    std::vector<std::vector<uint8_t>> unused;
    return Solver(output_script, unused);
}

#define CHECK_SCRIPT_STATIC_SIZE(script, expected_size)                   \
    do {                                                                  \
        BOOST_CHECK_EQUAL((script).size(), (expected_size));              \
        BOOST_CHECK_EQUAL((script).capacity(), CScriptBase::STATIC_SIZE); \
        BOOST_CHECK_EQUAL((script).allocated_memory(), 0);                \
    } while (0)

#define CHECK_SCRIPT_DYNAMIC_SIZE(script, expected_size, expected_extra)                 \
    do {                                                                 \
        BOOST_CHECK_EQUAL((script).size(), (expected_size));             \
        BOOST_CHECK_EQUAL((script).capacity(), (expected_extra));         \
        BOOST_CHECK_EQUAL((script).allocated_memory(), (expected_extra)); \
    } while (0)

BOOST_AUTO_TEST_CASE(script_size_and_capacity_test)
{
    BOOST_CHECK_EQUAL(sizeof(CompressedScript), 40);
    BOOST_CHECK_EQUAL(sizeof(CScriptBase), 40);
    BOOST_CHECK_NE(sizeof(CScriptBase), sizeof(prevector<CScriptBase::STATIC_SIZE + 1, uint8_t>)); // CScriptBase size should be set to avoid wasting space in padding
    BOOST_CHECK_EQUAL(sizeof(CScript), 40);
    BOOST_CHECK_EQUAL(sizeof(CTxOut), 48);

    CKey dummy_key;
    dummy_key.MakeNewKey(/*fCompressed=*/true);
    const CPubKey dummy_pubkey{dummy_key.GetPubKey()};

    // Small OP_RETURN has direct allocation
    {
        const auto script{CScript() << OP_RETURN << std::vector<uint8_t>(10, 0xaa)};
        BOOST_CHECK_EQUAL(GetTxoutType(script), TxoutType::NULL_DATA);
        CHECK_SCRIPT_STATIC_SIZE(script, 12);
    }

    // P2WPKH has direct allocation
    {
        const auto script{GetScriptForDestination(WitnessV0KeyHash{PKHash{dummy_pubkey}})};
        BOOST_CHECK_EQUAL(GetTxoutType(script), TxoutType::WITNESS_V0_KEYHASH);
        CHECK_SCRIPT_STATIC_SIZE(script, 22);
    }

    // P2SH has direct allocation
    {
        const auto script{GetScriptForDestination(ScriptHash{CScript{} << OP_TRUE})};
        BOOST_CHECK(script.IsPayToScriptHash());
        CHECK_SCRIPT_STATIC_SIZE(script, 23);
    }

    // P2PKH has direct allocation
    {
        const auto script{GetScriptForDestination(PKHash{dummy_pubkey})};
        BOOST_CHECK_EQUAL(GetTxoutType(script), TxoutType::PUBKEYHASH);
        CHECK_SCRIPT_STATIC_SIZE(script, 25);
    }

    // P2WSH has direct allocation
    {
        const auto script{GetScriptForDestination(WitnessV0ScriptHash{CScript{} << OP_TRUE})};
        BOOST_CHECK(script.IsPayToWitnessScriptHash());
        CHECK_SCRIPT_STATIC_SIZE(script, 34);
    }

    // P2TR has direct allocation
    {
        const auto script{GetScriptForDestination(WitnessV1Taproot{XOnlyPubKey{dummy_pubkey}})};
        BOOST_CHECK_EQUAL(GetTxoutType(script), TxoutType::WITNESS_V1_TAPROOT);
        CHECK_SCRIPT_STATIC_SIZE(script, 34);
    }

    // Compressed P2PK has direct allocation
    {
        const auto script{GetScriptForRawPubKey(dummy_pubkey)};
        BOOST_CHECK_EQUAL(GetTxoutType(script), TxoutType::PUBKEY);
        CHECK_SCRIPT_STATIC_SIZE(script, 35);
    }

    // Uncompressed P2PK needs extra allocation
    {
        CKey uncompressed_key;
        uncompressed_key.MakeNewKey(/*fCompressed=*/false);
        const CPubKey uncompressed_pubkey{uncompressed_key.GetPubKey()};

        const auto script{GetScriptForRawPubKey(uncompressed_pubkey)};
        BOOST_CHECK_EQUAL(GetTxoutType(script), TxoutType::PUBKEY);
        CHECK_SCRIPT_DYNAMIC_SIZE(script, 67, 67);
    }

    // Bare multisig needs extra allocation
    {
        const auto script{GetScriptForMultisig(1, std::vector{2, dummy_pubkey})};
        BOOST_CHECK_EQUAL(GetTxoutType(script), TxoutType::MULTISIG);
        CHECK_SCRIPT_DYNAMIC_SIZE(script, 71, 103);
    }
}

/* Wrapper around ProduceSignature to combine two scriptsigs */
SignatureData CombineSignatures(const CTxOut& txout, const CMutableTransaction& tx, const SignatureData& scriptSig1, const SignatureData& scriptSig2)
{
    SignatureData data;
    data.MergeSignatureData(scriptSig1);
    data.MergeSignatureData(scriptSig2);
    ProduceSignature(DUMMY_SIGNING_PROVIDER, MutableTransactionSignatureCreator(tx, 0, txout.nValue, {.sighash_type = SIGHASH_DEFAULT}), txout.scriptPubKey, data);
    return data;
}

BOOST_AUTO_TEST_CASE(script_combineSigs)
{
    // Test the ProduceSignature's ability to combine signatures function
    FillableSigningProvider keystore;
    std::vector<CKey> keys;
    std::vector<CPubKey> pubkeys;
    for (int i = 0; i < 3; i++)
    {
        CKey key = GenerateRandomKey(/*compressed=*/i%2 == 1);
        keys.push_back(key);
        pubkeys.push_back(key.GetPubKey());
        BOOST_CHECK(keystore.AddKey(key));
    }

    CMutableTransaction txFrom = BuildCreditingTransaction(GetScriptForDestination(PKHash(keys[0].GetPubKey())));
    CMutableTransaction txTo = BuildSpendingTransaction(CScript(), CScriptWitness(), CTransaction(txFrom));
    CScript& scriptPubKey = txFrom.vout[0].scriptPubKey;
    SignatureData scriptSig;

    SignatureData empty;
    SignatureData combined = CombineSignatures(txFrom.vout[0], txTo, empty, empty);
    BOOST_CHECK(combined.scriptSig.empty());

    // Single signature case:
    SignatureData dummy;
    BOOST_CHECK(SignSignature(keystore, CTransaction(txFrom), txTo, 0, SIGHASH_ALL, dummy)); // changes scriptSig
    scriptSig = DataFromTransaction(txTo, 0, txFrom.vout[0]);
    combined = CombineSignatures(txFrom.vout[0], txTo, scriptSig, empty);
    BOOST_CHECK(combined.scriptSig == scriptSig.scriptSig);
    combined = CombineSignatures(txFrom.vout[0], txTo, empty, scriptSig);
    BOOST_CHECK(combined.scriptSig == scriptSig.scriptSig);
    SignatureData scriptSigCopy = scriptSig;
    // Signing again will give a different, valid signature:
    SignatureData dummy_b;
    BOOST_CHECK(SignSignature(keystore, CTransaction(txFrom), txTo, 0, SIGHASH_ALL, dummy_b));
    scriptSig = DataFromTransaction(txTo, 0, txFrom.vout[0]);
    combined = CombineSignatures(txFrom.vout[0], txTo, scriptSigCopy, scriptSig);
    BOOST_CHECK(combined.scriptSig == scriptSigCopy.scriptSig || combined.scriptSig == scriptSig.scriptSig);

    // P2SH, single-signature case:
    CScript pkSingle; pkSingle << ToByteVector(keys[0].GetPubKey()) << OP_CHECKSIG;
    BOOST_CHECK(keystore.AddCScript(pkSingle));
    scriptPubKey = GetScriptForDestination(ScriptHash(pkSingle));
    SignatureData dummy_c;
    BOOST_CHECK(SignSignature(keystore, CTransaction(txFrom), txTo, 0, SIGHASH_ALL, dummy_c));
    scriptSig = DataFromTransaction(txTo, 0, txFrom.vout[0]);
    combined = CombineSignatures(txFrom.vout[0], txTo, scriptSig, empty);
    BOOST_CHECK(combined.scriptSig == scriptSig.scriptSig);
    combined = CombineSignatures(txFrom.vout[0], txTo, empty, scriptSig);
    BOOST_CHECK(combined.scriptSig == scriptSig.scriptSig);
    scriptSigCopy = scriptSig;
    SignatureData dummy_d;
    BOOST_CHECK(SignSignature(keystore, CTransaction(txFrom), txTo, 0, SIGHASH_ALL, dummy_d));
    scriptSig = DataFromTransaction(txTo, 0, txFrom.vout[0]);
    combined = CombineSignatures(txFrom.vout[0], txTo, scriptSigCopy, scriptSig);
    BOOST_CHECK(combined.scriptSig == scriptSigCopy.scriptSig || combined.scriptSig == scriptSig.scriptSig);

    // Hardest case:  Multisig 2-of-3
    scriptPubKey = GetScriptForMultisig(2, pubkeys);
    BOOST_CHECK(keystore.AddCScript(scriptPubKey));
    SignatureData dummy_e;
    BOOST_CHECK(SignSignature(keystore, CTransaction(txFrom), txTo, 0, SIGHASH_ALL, dummy_e));
    scriptSig = DataFromTransaction(txTo, 0, txFrom.vout[0]);
    combined = CombineSignatures(txFrom.vout[0], txTo, scriptSig, empty);
    BOOST_CHECK(combined.scriptSig == scriptSig.scriptSig);
    combined = CombineSignatures(txFrom.vout[0], txTo, empty, scriptSig);
    BOOST_CHECK(combined.scriptSig == scriptSig.scriptSig);

    // A couple of partially-signed versions:
    std::vector<unsigned char> sig1;
    uint256 hash1 = SignatureHash(scriptPubKey, txTo, 0, SIGHASH_ALL, 0, SigVersion::BASE);
    BOOST_CHECK(keys[0].Sign(hash1, sig1));
    sig1.push_back(SIGHASH_ALL);
    std::vector<unsigned char> sig2;
    uint256 hash2 = SignatureHash(scriptPubKey, txTo, 0, SIGHASH_NONE, 0, SigVersion::BASE);
    BOOST_CHECK(keys[1].Sign(hash2, sig2));
    sig2.push_back(SIGHASH_NONE);
    std::vector<unsigned char> sig3;
    uint256 hash3 = SignatureHash(scriptPubKey, txTo, 0, SIGHASH_SINGLE, 0, SigVersion::BASE);
    BOOST_CHECK(keys[2].Sign(hash3, sig3));
    sig3.push_back(SIGHASH_SINGLE);

    // Not fussy about order (or even existence) of placeholders or signatures:
    CScript partial1a = CScript() << OP_0 << sig1 << OP_0;
    CScript partial1b = CScript() << OP_0 << OP_0 << sig1;
    CScript partial2a = CScript() << OP_0 << sig2;
    CScript partial2b = CScript() << sig2 << OP_0;
    CScript partial3a = CScript() << sig3;
    CScript partial3b = CScript() << OP_0 << OP_0 << sig3;
    CScript partial3c = CScript() << OP_0 << sig3 << OP_0;
    CScript complete12 = CScript() << OP_0 << sig1 << sig2;
    CScript complete13 = CScript() << OP_0 << sig1 << sig3;
    CScript complete23 = CScript() << OP_0 << sig2 << sig3;
    SignatureData partial1_sigs;
    partial1_sigs.signatures.emplace(keys[0].GetPubKey().GetID(), SigPair(keys[0].GetPubKey(), sig1));
    SignatureData partial2_sigs;
    partial2_sigs.signatures.emplace(keys[1].GetPubKey().GetID(), SigPair(keys[1].GetPubKey(), sig2));
    SignatureData partial3_sigs;
    partial3_sigs.signatures.emplace(keys[2].GetPubKey().GetID(), SigPair(keys[2].GetPubKey(), sig3));

    combined = CombineSignatures(txFrom.vout[0], txTo, partial1_sigs, partial1_sigs);
    BOOST_CHECK(combined.scriptSig == partial1a);
    combined = CombineSignatures(txFrom.vout[0], txTo, partial1_sigs, partial2_sigs);
    BOOST_CHECK(combined.scriptSig == complete12);
    combined = CombineSignatures(txFrom.vout[0], txTo, partial2_sigs, partial1_sigs);
    BOOST_CHECK(combined.scriptSig == complete12);
    combined = CombineSignatures(txFrom.vout[0], txTo, partial1_sigs, partial2_sigs);
    BOOST_CHECK(combined.scriptSig == complete12);
    combined = CombineSignatures(txFrom.vout[0], txTo, partial3_sigs, partial1_sigs);
    BOOST_CHECK(combined.scriptSig == complete13);
    combined = CombineSignatures(txFrom.vout[0], txTo, partial2_sigs, partial3_sigs);
    BOOST_CHECK(combined.scriptSig == complete23);
    combined = CombineSignatures(txFrom.vout[0], txTo, partial3_sigs, partial2_sigs);
    BOOST_CHECK(combined.scriptSig == complete23);
    combined = CombineSignatures(txFrom.vout[0], txTo, partial3_sigs, partial3_sigs);
    BOOST_CHECK(combined.scriptSig == partial3c);
}

/**
 * Reproduction of an exception incorrectly raised when parsing a public key inside a TapMiniscript.
 */
BOOST_AUTO_TEST_CASE(sign_invalid_miniscript)
{
    FillableSigningProvider keystore;
    SignatureData sig_data;
    CMutableTransaction prev, curr;

    // Create a Taproot output which contains a leaf in which a non-32 bytes push is used where a public key is expected
    // by the Miniscript parser. This offending Script was found by the RPC fuzzer.
    const auto invalid_pubkey{"173d36c8c9c9c9ffffffffffff0200000000021e1e37373721361818181818181e1e1e1e19000000000000000000b19292929292926b006c9b9b9292"_hex_u8};
    TaprootBuilder builder;
    builder.Add(0, {invalid_pubkey}, 0xc0);
    builder.Finalize(XOnlyPubKey::NUMS_H);
    prev.vout.emplace_back(0, GetScriptForDestination(builder.GetOutput()));
    curr.vin.emplace_back(COutPoint{prev.GetHash(), 0});
    sig_data.tr_spenddata = builder.GetSpendData();

    // SignSignature can fail but it shouldn't raise an exception (nor crash).
    BOOST_CHECK(!SignSignature(keystore, CTransaction(prev), curr, 0, SIGHASH_ALL, sig_data));
}

/* P2A input should be considered signed. */
BOOST_AUTO_TEST_CASE(sign_paytoanchor)
{
    FillableSigningProvider keystore;
    SignatureData sig_data;
    CMutableTransaction prev, curr;
    prev.vout.emplace_back(0, GetScriptForDestination(PayToAnchor{}));

    curr.vin.emplace_back(COutPoint{prev.GetHash(), 0});

    BOOST_CHECK(SignSignature(keystore, CTransaction(prev), curr, 0, SIGHASH_ALL, sig_data));
}

/** BIP 360 P2MR spending, against the Script Validation section of the spec. */
BOOST_AUTO_TEST_CASE(script_p2mr)
{
    KeyData keys;
    const XOnlyPubKey xpk{keys.pubkey0C};

    // Two-leaf script tree: leaf A = <xonly pubkey> OP_CHECKSIG, leaf B = OP_RETURN.
    const CScript leaf_a = CScript() << ToByteVector(xpk) << OP_CHECKSIG;
    const CScript leaf_b = CScript() << OP_RETURN;
    const uint256 hash_a = ComputeTapleafHash(TAPROOT_LEAF_TAPSCRIPT, leaf_a);
    const uint256 hash_b = ComputeTapleafHash(TAPROOT_LEAF_TAPSCRIPT, leaf_b);
    const uint256 root = ComputeTapbranchHash(hash_a, hash_b);

    const CScript spk = CScript() << OP_2 << ToByteVector(root);
    const CAmount amount{10000};
    const CTransaction credit_tx{BuildCreditingTransaction(spk, amount)};
    CMutableTransaction spend_tx = BuildSpendingTransaction(CScript(), CScriptWitness(), credit_tx);
    // Mark the input as witness-bearing so that Init() detects the P2MR spend
    // and precomputes the BIP 341 sighash midstate.
    spend_tx.vin[0].scriptWitness.stack.push_back({});

    PrecomputedTransactionData txdata;
    txdata.Init(spend_tx, {credit_tx.vout[0]});
    const MutableTransactionSignatureChecker checker{&spend_tx, 0, amount, txdata, MissingDataBehavior::FAIL};

    const unsigned char control_byte{TAPROOT_LEAF_TAPSCRIPT | 1}; // low bit must be 1
    const std::vector<unsigned char> leaf_a_bytes(leaf_a.begin(), leaf_a.end());
    std::vector<unsigned char> control{control_byte};
    control.insert(control.end(), hash_b.begin(), hash_b.end());

    const script_verify_flags base_flags{SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT};
    const script_verify_flags p2mr_flags{base_flags | SCRIPT_VERIFY_P2MR};
    ScriptError err;

    const auto sign_leaf_a = [&](bool annex_present, const uint256& annex_hash) {
        ScriptExecutionData execdata;
        execdata.m_annex_init = true;
        execdata.m_annex_present = annex_present;
        if (annex_present) execdata.m_annex_hash = annex_hash;
        execdata.m_tapleaf_hash_init = true;
        execdata.m_tapleaf_hash = hash_a;
        execdata.m_codeseparator_pos_init = true;
        execdata.m_codeseparator_pos = 0xFFFFFFFF;
        uint256 sighash;
        BOOST_REQUIRE(SignatureHashSchnorr(sighash, execdata, spend_tx, 0, SIGHASH_DEFAULT, SigVersion::TAPSCRIPT, txdata, MissingDataBehavior::FAIL));
        std::vector<unsigned char> sig(64);
        BOOST_REQUIRE(keys.key0C.SignSchnorr(sighash, sig, nullptr, uint256()));
        return sig;
    };

    // Valid spend through leaf A.
    {
        CScriptWitness w;
        w.stack = {sign_leaf_a(false, uint256()), leaf_a_bytes, control};
        BOOST_CHECK(VerifyScript(CScript(), spk, &w, p2mr_flags, checker, &err));
        BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));
    }

    // Without SCRIPT_VERIFY_P2MR the output stays unencumbered.
    {
        CScriptWitness w;
        w.stack = {{0x01}};
        BOOST_CHECK(VerifyScript(CScript(), spk, &w, base_flags, checker, &err));
    }

    // Corrupted signature.
    {
        auto sig = sign_leaf_a(false, uint256());
        sig[10] ^= 1;
        CScriptWitness w;
        w.stack = {sig, leaf_a_bytes, control};
        BOOST_CHECK(!VerifyScript(CScript(), spk, &w, p2mr_flags, checker, &err));
        BOOST_CHECK_EQUAL(FormatScriptError(err), FormatScriptError(SCRIPT_ERR_SCHNORR_SIG));
    }

    // Control block of invalid length.
    {
        auto bad_control = control;
        bad_control.push_back(0x00);
        CScriptWitness w;
        w.stack = {sign_leaf_a(false, uint256()), leaf_a_bytes, bad_control};
        BOOST_CHECK(!VerifyScript(CScript(), spk, &w, p2mr_flags, checker, &err));
        BOOST_CHECK_EQUAL(FormatScriptError(err), FormatScriptError(SCRIPT_ERR_TAPROOT_WRONG_CONTROL_SIZE));
    }

    // Wrong Merkle path.
    {
        auto bad_control = control;
        bad_control[5] ^= 1;
        CScriptWitness w;
        w.stack = {sign_leaf_a(false, uint256()), leaf_a_bytes, bad_control};
        BOOST_CHECK(!VerifyScript(CScript(), spk, &w, p2mr_flags, checker, &err));
        BOOST_CHECK_EQUAL(FormatScriptError(err), FormatScriptError(SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH));
    }

    // Control byte with the low bit unset.
    {
        auto bad_control = control;
        bad_control[0] = TAPROOT_LEAF_TAPSCRIPT;
        CScriptWitness w;
        w.stack = {sign_leaf_a(false, uint256()), leaf_a_bytes, bad_control};
        BOOST_CHECK(!VerifyScript(CScript(), spk, &w, p2mr_flags, checker, &err));
        BOOST_CHECK_EQUAL(FormatScriptError(err), FormatScriptError(SCRIPT_ERR_P2MR_WRONG_CONTROL_BYTE));
    }

    // A single witness element cannot provide both script and control block.
    {
        CScriptWitness w;
        w.stack = {control};
        BOOST_CHECK(!VerifyScript(CScript(), spk, &w, p2mr_flags, checker, &err));
        BOOST_CHECK_EQUAL(FormatScriptError(err), FormatScriptError(SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH));
    }

    // A two-element stack whose last element carries the annex tag is invalid.
    {
        CScriptWitness w;
        w.stack = {leaf_a_bytes, {ANNEX_TAG}};
        BOOST_CHECK(!VerifyScript(CScript(), spk, &w, p2mr_flags, checker, &err));
        BOOST_CHECK_EQUAL(FormatScriptError(err), FormatScriptError(SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH));
    }

    // Annex-covered spend: valid when signed over the annex, invalid otherwise.
    {
        const std::vector<unsigned char> annex{ANNEX_TAG, 0xde, 0xad};
        const uint256 annex_hash{(HashWriter{} << annex).GetSHA256()};
        CScriptWitness w;
        w.stack = {sign_leaf_a(true, annex_hash), leaf_a_bytes, control, annex};
        BOOST_CHECK(VerifyScript(CScript(), spk, &w, p2mr_flags, checker, &err));
        BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));

        w.stack = {sign_leaf_a(false, uint256()), leaf_a_bytes, control, annex};
        BOOST_CHECK(!VerifyScript(CScript(), spk, &w, p2mr_flags, checker, &err));
        BOOST_CHECK_EQUAL(FormatScriptError(err), FormatScriptError(SCRIPT_ERR_SCHNORR_SIG));
    }

    // Depth-zero tree: anyone-can-spend once the leaf script preimage is known.
    // No signature is required and the leaf script is not executed
    // (spec, Script Validation: "If m = 0, succeed immediately").
    {
        const CScript spk_d0 = CScript() << OP_2 << ToByteVector(hash_a);
        CScriptWitness w;
        w.stack = {leaf_a_bytes, {control_byte}};
        BOOST_CHECK(VerifyScript(CScript(), spk_d0, &w, p2mr_flags, checker, &err));
        BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));
    }

    // Unknown leaf version stays unencumbered, but is discouraged by policy.
    {
        const uint256 hash_unk = ComputeTapleafHash(0xe0, leaf_a);
        const CScript spk_unk = CScript() << OP_2 << ToByteVector(ComputeTapbranchHash(hash_unk, hash_b));
        std::vector<unsigned char> control_unk{0xe0 | 1};
        control_unk.insert(control_unk.end(), hash_b.begin(), hash_b.end());
        CScriptWitness w;
        w.stack = {leaf_a_bytes, control_unk};
        BOOST_CHECK(VerifyScript(CScript(), spk_unk, &w, p2mr_flags, checker, &err));
        BOOST_CHECK(!VerifyScript(CScript(), spk_unk, &w, p2mr_flags | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION, checker, &err));
        BOOST_CHECK_EQUAL(FormatScriptError(err), FormatScriptError(SCRIPT_ERR_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION));
    }

    // Three-leaf tree: spend leaf A at depth 2 (two-node Merkle path).
    {
        const CScript leaf_c = CScript() << OP_TRUE;
        const uint256 hash_c = ComputeTapleafHash(TAPROOT_LEAF_TAPSCRIPT, leaf_c);
        const uint256 root2 = ComputeTapbranchHash(ComputeTapbranchHash(hash_a, hash_b), hash_c);
        const CScript spk2 = CScript() << OP_2 << ToByteVector(root2);
        const CTransaction credit2{BuildCreditingTransaction(spk2, amount)};
        CMutableTransaction spend2 = BuildSpendingTransaction(CScript(), CScriptWitness(), credit2);
        spend2.vin[0].scriptWitness.stack.push_back({});
        PrecomputedTransactionData txdata2;
        txdata2.Init(spend2, {credit2.vout[0]});
        const MutableTransactionSignatureChecker checker2{&spend2, 0, amount, txdata2, MissingDataBehavior::FAIL};

        ScriptExecutionData execdata;
        execdata.m_annex_init = true;
        execdata.m_annex_present = false;
        execdata.m_tapleaf_hash_init = true;
        execdata.m_tapleaf_hash = hash_a;
        execdata.m_codeseparator_pos_init = true;
        execdata.m_codeseparator_pos = 0xFFFFFFFF;
        uint256 sighash;
        BOOST_REQUIRE(SignatureHashSchnorr(sighash, execdata, spend2, 0, SIGHASH_DEFAULT, SigVersion::TAPSCRIPT, txdata2, MissingDataBehavior::FAIL));
        std::vector<unsigned char> sig(64);
        BOOST_REQUIRE(keys.key0C.SignSchnorr(sighash, sig, nullptr, uint256()));

        std::vector<unsigned char> control2{control_byte};
        control2.insert(control2.end(), hash_b.begin(), hash_b.end());
        control2.insert(control2.end(), hash_c.begin(), hash_c.end());
        CScriptWitness w;
        w.stack = {sig, leaf_a_bytes, control2};
        BOOST_CHECK(VerifyScript(CScript(), spk2, &w, p2mr_flags, checker2, &err));
        BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));
    }

    // A Merkle path deeper than 128 nodes is invalid.
    {
        std::vector<unsigned char> control129{control_byte};
        control129.resize(1 + 32 * 129, 0x00);
        CScriptWitness w;
        w.stack = {leaf_a_bytes, control129};
        BOOST_CHECK(!VerifyScript(CScript(), spk, &w, p2mr_flags, checker, &err));
        BOOST_CHECK_EQUAL(FormatScriptError(err), FormatScriptError(SCRIPT_ERR_TAPROOT_WRONG_CONTROL_SIZE));
    }

    // Depth-zero spend with an annex: the annex is dropped, then m = 0 applies.
    {
        const CScript spk_d0 = CScript() << OP_2 << ToByteVector(hash_a);
        CScriptWitness w;
        w.stack = {leaf_a_bytes, {control_byte}, {ANNEX_TAG, 0x01}};
        BOOST_CHECK(VerifyScript(CScript(), spk_d0, &w, p2mr_flags, checker, &err));
        BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));
    }

    // Extra initial stack elements are ignored when execution is skipped
    // (m = 0): the spec's success rule precedes script execution, and the
    // initial stack is only consumed by execution.
    {
        const CScript spk_d0 = CScript() << OP_2 << ToByteVector(hash_a);
        CScriptWitness w;
        w.stack = {{0xde, 0xad}, leaf_a_bytes, {control_byte}};
        BOOST_CHECK(VerifyScript(CScript(), spk_d0, &w, p2mr_flags, checker, &err));
        BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));
    }

    // A 128-node Merkle path (the maximum) is valid. An unknown leaf version
    // is used so that no signature is needed (execution is skipped).
    {
        const uint256 hash_unk = ComputeTapleafHash(0xe0, leaf_a);
        std::vector<unsigned char> control128{0xe0 | 1};
        uint256 k = hash_unk;
        for (int j = 0; j < 128; ++j) {
            const uint256 node;
            control128.insert(control128.end(), node.begin(), node.end());
            k = ComputeTapbranchHash(k, node);
        }
        const CScript spk128 = CScript() << OP_2 << ToByteVector(k);
        CScriptWitness w;
        w.stack = {leaf_a_bytes, control128};
        BOOST_CHECK(VerifyScript(CScript(), spk128, &w, p2mr_flags, checker, &err));
        BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));
    }

    // An empty control block is invalid.
    {
        CScriptWitness w;
        w.stack = {leaf_a_bytes, {}};
        BOOST_CHECK(!VerifyScript(CScript(), spk, &w, p2mr_flags, checker, &err));
        BOOST_CHECK_EQUAL(FormatScriptError(err), FormatScriptError(SCRIPT_ERR_TAPROOT_WRONG_CONTROL_SIZE));
    }

    // P2SH-wrapped v2/32 is not P2MR (native segwit only): unencumbered.
    {
        const CScript redeem = CScript() << OP_2 << ToByteVector(root);
        const CScript spk_p2sh = GetScriptForDestination(ScriptHash(redeem));
        const CScript script_sig = CScript() << std::vector<unsigned char>(redeem.begin(), redeem.end());
        CScriptWitness w;
        w.stack = {{0x01}};
        BOOST_CHECK(VerifyScript(script_sig, spk_p2sh, &w, p2mr_flags, checker, &err));
        BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));
    }

    // Witness v2 with a program size other than 32 bytes stays unencumbered.
    {
        const std::vector<unsigned char> program33(33, 0x42);
        const CScript spk33 = CScript() << OP_2 << program33;
        CScriptWitness w;
        w.stack = {{0x01}};
        BOOST_CHECK(VerifyScript(CScript(), spk33, &w, p2mr_flags, checker, &err));
        BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));
    }
}

/** OP_CHECKPQSIG (draft): SLH-DSA-SHA2-128s spending of a P2MR leaf. */
BOOST_AUTO_TEST_CASE(script_pqsig_slh_dsa)
{
    // Deterministic keypair from a fixed seed.
    std::vector<unsigned char> pq_pubkey(pqc::SLH_DSA_SHA2_128S_PUBKEY_SIZE);
    std::vector<unsigned char> pq_seckey(pqc::SLH_DSA_SHA2_128S_SECKEY_SIZE);
    const std::vector<unsigned char> seed(pqc::SLH_DSA_SHA2_128S_SEED_SIZE, 0x17);
    BOOST_REQUIRE(pqc::SeedKeypair(pqc::Scheme::SLH_DSA_SHA2_128S, pq_pubkey.data(), pq_seckey.data(), seed.data(), seed.size()));

    // Leaf script: <scheme_byte || H(pubkey)> OP_CHECKPQSIG.
    HashWriter pubkey_hasher{TaggedHash("PQPubKeyHash")};
    pubkey_hasher.write(MakeByteSpan(pq_pubkey));
    const uint256 pubkey_hash{pubkey_hasher.GetSHA256()};
    std::vector<unsigned char> commitment{static_cast<unsigned char>(pqc::Scheme::SLH_DSA_SHA2_128S)};
    commitment.insert(commitment.end(), pubkey_hash.begin(), pubkey_hash.end());
    const CScript leaf_pq = CScript() << commitment << OP_CHECKPQSIG;
    const std::vector<unsigned char> leaf_pq_bytes(leaf_pq.begin(), leaf_pq.end());
    BOOST_CHECK_EQUAL(leaf_pq_bytes.size(), 35U);

    // Two-leaf tree so that the output is not depth-0 (anyone-can-spend).
    const CScript leaf_b = CScript() << OP_RETURN;
    const uint256 hash_pq = ComputeTapleafHash(TAPROOT_LEAF_TAPSCRIPT, leaf_pq);
    const uint256 hash_b = ComputeTapleafHash(TAPROOT_LEAF_TAPSCRIPT, leaf_b);
    const uint256 root = ComputeTapbranchHash(hash_pq, hash_b);

    const CScript spk = CScript() << OP_2 << ToByteVector(root);
    const CAmount amount{10000};
    const CTransaction credit_tx{BuildCreditingTransaction(spk, amount)};
    CMutableTransaction spend_tx = BuildSpendingTransaction(CScript(), CScriptWitness(), credit_tx);
    spend_tx.vin[0].scriptWitness.stack.push_back({});

    PrecomputedTransactionData txdata;
    txdata.Init(spend_tx, {credit_tx.vout[0]});
    const MutableTransactionSignatureChecker checker{&spend_tx, 0, amount, txdata, MissingDataBehavior::FAIL};

    const unsigned char control_byte{TAPROOT_LEAF_TAPSCRIPT | 1};
    std::vector<unsigned char> control{control_byte};
    control.insert(control.end(), hash_b.begin(), hash_b.end());

    const script_verify_flags base_flags{SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT | SCRIPT_VERIFY_P2MR};
    const script_verify_flags pq_flags{base_flags | SCRIPT_VERIFY_PQSIG};
    ScriptError err;

    // Sign the tapscript sighash of the PQ leaf.
    const auto pq_sign = [&](uint8_t hashtype) {
        ScriptExecutionData execdata;
        execdata.m_annex_init = true;
        execdata.m_annex_present = false;
        execdata.m_tapleaf_hash_init = true;
        execdata.m_tapleaf_hash = hash_pq;
        execdata.m_codeseparator_pos_init = true;
        execdata.m_codeseparator_pos = 0xFFFFFFFF;
        uint256 sighash;
        BOOST_REQUIRE(SignatureHashSchnorr(sighash, execdata, spend_tx, 0, hashtype, SigVersion::TAPSCRIPT, txdata, MissingDataBehavior::FAIL));
        std::vector<unsigned char> sig(pqc::SLH_DSA_SHA2_128S_SIG_SIZE);
        size_t sig_len{0};
        BOOST_REQUIRE(pqc::Sign(pqc::Scheme::SLH_DSA_SHA2_128S, sig.data(), &sig_len, sighash.begin(), pq_seckey.data()));
        BOOST_REQUIRE_EQUAL(sig_len, pqc::SLH_DSA_SHA2_128S_SIG_SIZE);
        if (hashtype != SIGHASH_DEFAULT) sig.push_back(hashtype);
        return sig;
    };
    const std::vector<unsigned char> sig_default{pq_sign(SIGHASH_DEFAULT)};

    // Valid spend, SIGHASH_DEFAULT.
    {
        CScriptWitness w;
        w.stack = {sig_default, pq_pubkey, leaf_pq_bytes, control};
        BOOST_CHECK(VerifyScript(CScript(), spk, &w, pq_flags, checker, &err));
        BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));
    }

    // Valid spend, SIGHASH_ALL (explicit trailing byte).
    {
        CScriptWitness w;
        w.stack = {pq_sign(SIGHASH_ALL), pq_pubkey, leaf_pq_bytes, control};
        BOOST_CHECK(VerifyScript(CScript(), spk, &w, pq_flags, checker, &err));
        BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));
    }

    // Valid spend, SIGHASH_SINGLE | ANYONECANPAY: the full BIP 341 hashtype
    // range applies, not just the ALL variants.
    {
        CScriptWitness w;
        w.stack = {pq_sign(SIGHASH_SINGLE | SIGHASH_ANYONECANPAY), pq_pubkey, leaf_pq_bytes, control};
        BOOST_CHECK(VerifyScript(CScript(), spk, &w, pq_flags, checker, &err));
        BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));
    }

    // Without SCRIPT_VERIFY_PQSIG the leaf is anyone-can-spend: 0xbb is still
    // OP_SUCCESS187, which is what makes the change a soft fork.
    {
        CScriptWitness w;
        w.stack = {{}, {}, leaf_pq_bytes, control};
        BOOST_CHECK(VerifyScript(CScript(), spk, &w, base_flags, checker, &err));
        BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));
    }

    // Bit-flipped signature.
    {
        auto sig = sig_default;
        sig[100] ^= 1;
        CScriptWitness w;
        w.stack = {sig, pq_pubkey, leaf_pq_bytes, control};
        BOOST_CHECK(!VerifyScript(CScript(), spk, &w, pq_flags, checker, &err));
        BOOST_CHECK_EQUAL(FormatScriptError(err), FormatScriptError(SCRIPT_ERR_PQSIG));
    }

    // Signature over a different sighash (wrong hashtype byte appended).
    {
        auto sig = sig_default;
        sig.push_back(SIGHASH_ALL);
        CScriptWitness w;
        w.stack = {sig, pq_pubkey, leaf_pq_bytes, control};
        BOOST_CHECK(!VerifyScript(CScript(), spk, &w, pq_flags, checker, &err));
        BOOST_CHECK_EQUAL(FormatScriptError(err), FormatScriptError(SCRIPT_ERR_PQSIG));
    }

    // An explicit SIGHASH_DEFAULT byte is invalid: it would give every
    // signature two valid encodings.
    {
        auto sig = sig_default;
        sig.push_back(SIGHASH_DEFAULT);
        CScriptWitness w;
        w.stack = {sig, pq_pubkey, leaf_pq_bytes, control};
        BOOST_CHECK(!VerifyScript(CScript(), spk, &w, pq_flags, checker, &err));
        BOOST_CHECK_EQUAL(FormatScriptError(err), FormatScriptError(SCRIPT_ERR_PQSIG_HASHTYPE));
    }

    // An out-of-range hashtype byte (0x04) fails in the sighash computation.
    {
        auto sig = sig_default;
        sig.push_back(0x04);
        CScriptWitness w;
        w.stack = {sig, pq_pubkey, leaf_pq_bytes, control};
        BOOST_CHECK(!VerifyScript(CScript(), spk, &w, pq_flags, checker, &err));
        BOOST_CHECK_EQUAL(FormatScriptError(err), FormatScriptError(SCRIPT_ERR_PQSIG_HASHTYPE));
    }

    // Signature one byte short, and two bytes long. One byte over is the
    // valid encoding with a sighash byte, covered above.
    for (const int delta : {-1, 2}) {
        auto sig = sig_default;
        sig.resize(sig.size() + delta, 0x00);
        CScriptWitness w;
        w.stack = {sig, pq_pubkey, leaf_pq_bytes, control};
        BOOST_CHECK(!VerifyScript(CScript(), spk, &w, pq_flags, checker, &err));
        BOOST_CHECK_EQUAL(FormatScriptError(err), FormatScriptError(SCRIPT_ERR_PQSIG_SIZE));
    }

    // Wrong public key size.
    {
        auto short_pubkey = pq_pubkey;
        short_pubkey.pop_back();
        CScriptWitness w;
        w.stack = {sig_default, short_pubkey, leaf_pq_bytes, control};
        BOOST_CHECK(!VerifyScript(CScript(), spk, &w, pq_flags, checker, &err));
        BOOST_CHECK_EQUAL(FormatScriptError(err), FormatScriptError(SCRIPT_ERR_PQSIG_SIZE));
    }

    // Right size, wrong public key: the committed hash does not match.
    {
        auto other_pubkey = pq_pubkey;
        other_pubkey[0] ^= 1;
        CScriptWitness w;
        w.stack = {sig_default, other_pubkey, leaf_pq_bytes, control};
        BOOST_CHECK(!VerifyScript(CScript(), spk, &w, pq_flags, checker, &err));
        BOOST_CHECK_EQUAL(FormatScriptError(err), FormatScriptError(SCRIPT_ERR_PQSIG_PUBKEYHASH));
    }

    // Empty signature pushes false, so the script fails on a false top stack
    // element rather than aborting. The commitment is still checked, so an
    // empty signature cannot bypass a malformed leaf.
    {
        CScriptWitness w;
        w.stack = {{}, pq_pubkey, leaf_pq_bytes, control};
        BOOST_CHECK(!VerifyScript(CScript(), spk, &w, pq_flags, checker, &err));
        BOOST_CHECK_EQUAL(FormatScriptError(err), FormatScriptError(SCRIPT_ERR_EVAL_FALSE));
    }

    // With an empty signature the pubkey is not inspected at all: a branch
    // construction over two schemes can leave a pubkey of the other scheme's
    // size on the stack, so this must stay a false push, not a size failure.
    {
        CScriptWitness w;
        w.stack = {{}, std::vector<unsigned char>(pqc::ML_DSA_44_PUBKEY_SIZE, 0x00), leaf_pq_bytes, control};
        BOOST_CHECK(!VerifyScript(CScript(), spk, &w, pq_flags, checker, &err));
        BOOST_CHECK_EQUAL(FormatScriptError(err), FormatScriptError(SCRIPT_ERR_EVAL_FALSE));
    }

    // Unknown scheme byte, and a commitment of the wrong length. Both are
    // enforced before the signature is looked at, so an empty signature does
    // not get past them.
    {
        std::vector<unsigned char> bad_scheme{0x7f};
        bad_scheme.insert(bad_scheme.end(), pubkey_hash.begin(), pubkey_hash.end());
        const CScript leaf_bad = CScript() << bad_scheme << OP_CHECKPQSIG;
        const uint256 hash_bad = ComputeTapleafHash(TAPROOT_LEAF_TAPSCRIPT, leaf_bad);
        const CScript spk_bad = CScript() << OP_2 << ToByteVector(ComputeTapbranchHash(hash_bad, hash_b));
        CScriptWitness w;
        w.stack = {{}, pq_pubkey, {leaf_bad.begin(), leaf_bad.end()}, control};
        BOOST_CHECK(!VerifyScript(CScript(), spk_bad, &w, pq_flags, checker, &err));
        BOOST_CHECK_EQUAL(FormatScriptError(err), FormatScriptError(SCRIPT_ERR_PQSIG_SCHEME));
    }
    {
        const CScript leaf_short = CScript() << std::vector<unsigned char>(32, 0x02) << OP_CHECKPQSIG;
        const uint256 hash_short = ComputeTapleafHash(TAPROOT_LEAF_TAPSCRIPT, leaf_short);
        const CScript spk_short = CScript() << OP_2 << ToByteVector(ComputeTapbranchHash(hash_short, hash_b));
        CScriptWitness w;
        w.stack = {{}, pq_pubkey, {leaf_short.begin(), leaf_short.end()}, control};
        BOOST_CHECK(!VerifyScript(CScript(), spk_short, &w, pq_flags, checker, &err));
        BOOST_CHECK_EQUAL(FormatScriptError(err), FormatScriptError(SCRIPT_ERR_PQSIG_SIZE));
    }
    {
        // The same rule from the other side. A commitment one byte too long
        // carries a valid scheme byte and a valid hash, so a length test
        // written as "shorter than 33" would let it through and the leaf
        // script would stop having one form.
        std::vector<unsigned char> long_commitment{static_cast<unsigned char>(pqc::Scheme::SLH_DSA_SHA2_128S)};
        long_commitment.insert(long_commitment.end(), pubkey_hash.begin(), pubkey_hash.end());
        long_commitment.push_back(0x00);
        BOOST_REQUIRE_EQUAL(long_commitment.size(), 34U);
        const CScript leaf_long = CScript() << long_commitment << OP_CHECKPQSIG;
        const uint256 hash_long = ComputeTapleafHash(TAPROOT_LEAF_TAPSCRIPT, leaf_long);
        const CScript spk_long = CScript() << OP_2 << ToByteVector(ComputeTapbranchHash(hash_long, hash_b));
        CScriptWitness w;
        w.stack = {{}, pq_pubkey, {leaf_long.begin(), leaf_long.end()}, control};
        BOOST_CHECK(!VerifyScript(CScript(), spk_long, &w, pq_flags, checker, &err));
        BOOST_CHECK_EQUAL(FormatScriptError(err), FormatScriptError(SCRIPT_ERR_PQSIG_SIZE));
    }

    // The larger element bound follows the textual presence of the opcode,
    // not its execution: the scan runs over the whole script before any
    // branch is evaluated.
    {
        const CScript leaf_branch = CScript() << OP_0 << OP_IF << commitment << OP_CHECKPQSIG << OP_ENDIF << OP_DROP << OP_1;
        const uint256 hash_branch = ComputeTapleafHash(TAPROOT_LEAF_TAPSCRIPT, leaf_branch);
        const CScript spk_branch = CScript() << OP_2 << ToByteVector(ComputeTapbranchHash(hash_branch, hash_b));
        CScriptWitness w;
        w.stack = {std::vector<unsigned char>(1000, 0x00), {leaf_branch.begin(), leaf_branch.end()}, control};
        BOOST_CHECK(VerifyScript(CScript(), spk_branch, &w, pq_flags, checker, &err));
        BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));
    }

    // The opcode is a tapscript rule, so it works the same way in a BIP 341
    // taproot script path. A P2TRv2-style output type reusing this opcode
    // needs no separate verification code.
    {
        TaprootBuilder builder;
        builder.Add(0, leaf_pq, TAPROOT_LEAF_TAPSCRIPT);
        builder.Finalize(XOnlyPubKey::NUMS_H);
        const CScript spk_tr = GetScriptForDestination(builder.GetOutput());
        const CTransaction credit_tr{BuildCreditingTransaction(spk_tr, amount)};
        CMutableTransaction spend_tr = BuildSpendingTransaction(CScript(), CScriptWitness(), credit_tr);
        spend_tr.vin[0].scriptWitness.stack.push_back({});
        PrecomputedTransactionData txdata_tr;
        txdata_tr.Init(spend_tr, {credit_tr.vout[0]});
        const MutableTransactionSignatureChecker checker_tr{&spend_tr, 0, amount, txdata_tr, MissingDataBehavior::FAIL};

        ScriptExecutionData execdata;
        execdata.m_annex_init = true;
        execdata.m_annex_present = false;
        execdata.m_tapleaf_hash_init = true;
        execdata.m_tapleaf_hash = hash_pq;
        execdata.m_codeseparator_pos_init = true;
        execdata.m_codeseparator_pos = 0xFFFFFFFF;
        uint256 sighash;
        BOOST_REQUIRE(SignatureHashSchnorr(sighash, execdata, spend_tr, 0, SIGHASH_DEFAULT, SigVersion::TAPSCRIPT, txdata_tr, MissingDataBehavior::FAIL));
        std::vector<unsigned char> sig_tr(pqc::SLH_DSA_SHA2_128S_SIG_SIZE);
        size_t sig_tr_len{0};
        BOOST_REQUIRE(pqc::Sign(pqc::Scheme::SLH_DSA_SHA2_128S, sig_tr.data(), &sig_tr_len, sighash.begin(), pq_seckey.data()));

        const auto spenddata = builder.GetSpendData();
        const auto& control_tr = *spenddata.scripts.at({leaf_pq_bytes, TAPROOT_LEAF_TAPSCRIPT}).begin();
        CScriptWitness w;
        w.stack = {sig_tr, pq_pubkey, leaf_pq_bytes, control_tr};
        BOOST_CHECK(VerifyScript(CScript(), spk_tr, &w, pq_flags, checker_tr, &err));
        BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));
    }

    // The BIP 342 weight budget applies. A leaf that repeats the check over
    // the same signature funds no extra budget, so enough repetitions run
    // the input out of it. At the calibrated cost of 750, the witness
    // holding one 7856-byte signature funds eleven checks but not twelve.
    //
    // That pair alone would pass for any cost between 703 and 762, since
    // the budget only resolves a per-check cost to about one part in the
    // number of checks a witness affords. Repeating it with the witness
    // padded by the largest element the leaf admits affords twenty-two
    // checks instead of eleven, and the two boundaries together narrow the
    // range that satisfies both to 741 through 762.
    {
        const auto repeat_leaf = [&](int n, size_t padding) {
            CScript s;
            for (int j = 0; j < n; ++j) {
                s = s << OP_2DUP << commitment << OP_CHECKPQSIG << OP_VERIFY;
            }
            s = s << OP_2DROP;
            if (padding > 0) s = s << OP_DROP; // the padding element
            return s << OP_1;
        };
        const auto spend_repeats = [&](int n, size_t padding = 0) {
            const CScript leaf = repeat_leaf(n, padding);
            const uint256 hash_leaf = ComputeTapleafHash(TAPROOT_LEAF_TAPSCRIPT, leaf);
            const CScript spk_rep = CScript() << OP_2 << ToByteVector(ComputeTapbranchHash(hash_leaf, hash_b));
            const CTransaction credit_r{BuildCreditingTransaction(spk_rep, amount)};
            CMutableTransaction spend_r = BuildSpendingTransaction(CScript(), CScriptWitness(), credit_r);
            spend_r.vin[0].scriptWitness.stack.push_back({});
            PrecomputedTransactionData txdata_r;
            txdata_r.Init(spend_r, {credit_r.vout[0]});
            const MutableTransactionSignatureChecker checker_r{&spend_r, 0, amount, txdata_r, MissingDataBehavior::FAIL};

            ScriptExecutionData execdata;
            execdata.m_annex_init = true;
            execdata.m_annex_present = false;
            execdata.m_tapleaf_hash_init = true;
            execdata.m_tapleaf_hash = hash_leaf;
            execdata.m_codeseparator_pos_init = true;
            execdata.m_codeseparator_pos = 0xFFFFFFFF;
            uint256 sighash;
            BOOST_REQUIRE(SignatureHashSchnorr(sighash, execdata, spend_r, 0, SIGHASH_DEFAULT, SigVersion::TAPSCRIPT, txdata_r, MissingDataBehavior::FAIL));
            std::vector<unsigned char> sig(pqc::SLH_DSA_SHA2_128S_SIG_SIZE);
            size_t sig_len{0};
            BOOST_REQUIRE(pqc::Sign(pqc::Scheme::SLH_DSA_SHA2_128S, sig.data(), &sig_len, sighash.begin(), pq_seckey.data()));

            CScriptWitness w;
            // The padding sits below the signature, so the repeats keep
            // working on the top two elements and one OP_DROP clears it.
            w.stack = {sig, pq_pubkey, {leaf.begin(), leaf.end()}, control};
            if (padding > 0) w.stack.insert(w.stack.begin(), std::vector<unsigned char>(padding, 0x00));
            return VerifyScript(CScript(), spk_rep, &w, pq_flags, checker_r, &err);
        };
        BOOST_CHECK(spend_repeats(11));
        BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));
        BOOST_CHECK(!spend_repeats(12));
        BOOST_CHECK_EQUAL(FormatScriptError(err), FormatScriptError(SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT));

        BOOST_CHECK(spend_repeats(22, PQ_MAX_ELEMENT_SIZE));
        BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));
        BOOST_CHECK(!spend_repeats(23, PQ_MAX_ELEMENT_SIZE));
        BOOST_CHECK_EQUAL(FormatScriptError(err), FormatScriptError(SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT));

        // BIP 342 fails a spend only once the budget goes negative, so
        // spending it to exactly zero has to pass. With 570 bytes of
        // padding the witness funds 9000 units against twelve checks
        // costing 9000, which is the one case that separates the rule from
        // an off-by-one that rejects on zero.
        BOOST_CHECK(spend_repeats(12, 570));
        BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));
    }

    // Fewer than three stack elements.
    {
        CScriptWitness w;
        w.stack = {pq_pubkey, leaf_pq_bytes, control};
        BOOST_CHECK(!VerifyScript(CScript(), spk, &w, pq_flags, checker, &err));
        BOOST_CHECK_EQUAL(FormatScriptError(err), FormatScriptError(SCRIPT_ERR_INVALID_STACK_OPERATION));
    }

    // An element larger than the PQ bound is rejected even in a PQ leaf.
    {
        CScriptWitness w;
        w.stack = {std::vector<unsigned char>(PQ_MAX_ELEMENT_SIZE + 1, 0x00), pq_pubkey, leaf_pq_bytes, control};
        BOOST_CHECK(!VerifyScript(CScript(), spk, &w, pq_flags, checker, &err));
        BOOST_CHECK_EQUAL(FormatScriptError(err), FormatScriptError(SCRIPT_ERR_PUSH_SIZE));
    }

    // A leaf without OP_CHECKPQSIG keeps the 520-byte element limit.
    {
        const CScript leaf_plain = CScript() << OP_DROP << OP_1;
        const uint256 hash_plain = ComputeTapleafHash(TAPROOT_LEAF_TAPSCRIPT, leaf_plain);
        const CScript spk_plain = CScript() << OP_2 << ToByteVector(ComputeTapbranchHash(hash_plain, hash_b));
        CScriptWitness w;
        w.stack = {std::vector<unsigned char>(MAX_SCRIPT_ELEMENT_SIZE + 1, 0x00), {leaf_plain.begin(), leaf_plain.end()}, control};
        BOOST_CHECK(!VerifyScript(CScript(), spk_plain, &w, pq_flags, checker, &err));
        BOOST_CHECK_EQUAL(FormatScriptError(err), FormatScriptError(SCRIPT_ERR_PUSH_SIZE));
    }

    // Another OP_SUCCESSx in the same leaf still short-circuits to success,
    // skipping the PQ check entirely (the footgun recorded in the design note).
    {
        const CScript leaf_mixed = CScript() << commitment << OP_CHECKPQSIG << static_cast<opcodetype>(188);
        const uint256 hash_mixed = ComputeTapleafHash(TAPROOT_LEAF_TAPSCRIPT, leaf_mixed);
        const CScript spk_mixed = CScript() << OP_2 << ToByteVector(ComputeTapbranchHash(hash_mixed, hash_b));
        CScriptWitness w;
        w.stack = {{}, {}, {leaf_mixed.begin(), leaf_mixed.end()}, control};
        BOOST_CHECK(VerifyScript(CScript(), spk_mixed, &w, pq_flags, checker, &err));
        BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));
    }

    // Hybrid leaf: the same leaf requires both a PQ and an EC signature.
    {
        KeyData keys;
        const XOnlyPubKey xpk{keys.pubkey0C};
        const CScript leaf_hybrid = CScript() << commitment << OP_CHECKPQSIG << OP_VERIFY << ToByteVector(xpk) << OP_CHECKSIG;
        const uint256 hash_hybrid = ComputeTapleafHash(TAPROOT_LEAF_TAPSCRIPT, leaf_hybrid);
        const CScript spk_hybrid = CScript() << OP_2 << ToByteVector(ComputeTapbranchHash(hash_hybrid, hash_b));
        const CTransaction credit_h{BuildCreditingTransaction(spk_hybrid, amount)};
        CMutableTransaction spend_h = BuildSpendingTransaction(CScript(), CScriptWitness(), credit_h);
        spend_h.vin[0].scriptWitness.stack.push_back({});
        PrecomputedTransactionData txdata_h;
        txdata_h.Init(spend_h, {credit_h.vout[0]});
        const MutableTransactionSignatureChecker checker_h{&spend_h, 0, amount, txdata_h, MissingDataBehavior::FAIL};

        ScriptExecutionData execdata;
        execdata.m_annex_init = true;
        execdata.m_annex_present = false;
        execdata.m_tapleaf_hash_init = true;
        execdata.m_tapleaf_hash = hash_hybrid;
        execdata.m_codeseparator_pos_init = true;
        execdata.m_codeseparator_pos = 0xFFFFFFFF;
        uint256 sighash;
        BOOST_REQUIRE(SignatureHashSchnorr(sighash, execdata, spend_h, 0, SIGHASH_DEFAULT, SigVersion::TAPSCRIPT, txdata_h, MissingDataBehavior::FAIL));
        std::vector<unsigned char> pq_sig(pqc::SLH_DSA_SHA2_128S_SIG_SIZE);
        size_t pq_sig_len{0};
        BOOST_REQUIRE(pqc::Sign(pqc::Scheme::SLH_DSA_SHA2_128S, pq_sig.data(), &pq_sig_len, sighash.begin(), pq_seckey.data()));
        std::vector<unsigned char> ec_sig(64);
        BOOST_REQUIRE(keys.key0C.SignSchnorr(sighash, ec_sig, nullptr, uint256()));

        CScriptWitness w;
        w.stack = {ec_sig, pq_sig, pq_pubkey, {leaf_hybrid.begin(), leaf_hybrid.end()}, control};
        BOOST_CHECK(VerifyScript(CScript(), spk_hybrid, &w, pq_flags, checker_h, &err));
        BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));
    }
}

//! The hook the vendored code draws from. Declared here so the stream it
//! produces can be checked directly; nothing else in the tree calls it.
extern "C" void randombytes(uint8_t* out, size_t outlen);

/** The entropy stream behind key generation and signing. Today's callers
 *  never ask for more than one block at a time, so a stream that repeated
 *  itself would go unnoticed until something asked for more. */
BOOST_AUTO_TEST_CASE(pqsig_entropy_stream)
{
    const std::vector<unsigned char> seed(32, 0x6d);
    pqc::SetDeterministicEntropy(seed.data(), seed.size());

    // A long draw must not repeat a block.
    std::vector<unsigned char> stream(160);
    randombytes(stream.data(), stream.size());
    std::set<std::vector<unsigned char>> blocks;
    for (size_t i = 0; i + 32 <= stream.size(); i += 32) {
        blocks.emplace(stream.begin() + i, stream.begin() + i + 32);
    }
    BOOST_CHECK_EQUAL(blocks.size(), 5U);

    // Successive draws continue the stream rather than restart it.
    pqc::SetDeterministicEntropy(seed.data(), seed.size());
    std::vector<unsigned char> first(32), second(32);
    randombytes(first.data(), first.size());
    randombytes(second.data(), second.size());
    BOOST_CHECK(first != second);
    BOOST_CHECK(std::equal(first.begin(), first.end(), stream.begin()));
    BOOST_CHECK(std::equal(second.begin(), second.end(), stream.begin() + 32));

    // Reinstalling the seed rewinds it, which is what makes signing
    // reproducible.
    pqc::SetDeterministicEntropy(seed.data(), seed.size());
    std::vector<unsigned char> again(32);
    randombytes(again.data(), again.size());
    BOOST_CHECK(again == first);

    // A different seed gives a different stream.
    const std::vector<unsigned char> other_seed(32, 0x6e);
    pqc::SetDeterministicEntropy(other_seed.data(), other_seed.size());
    std::vector<unsigned char> other(32);
    randombytes(other.data(), other.size());
    BOOST_CHECK(other != first);
}

/** The PQ wrapper's own contract, which the opcode relies on but does not
 *  exercise: the opcode enforces exact sizes before calling, so nothing else
 *  covers what Verify() does when handed the wrong ones. */
BOOST_AUTO_TEST_CASE(pqsig_verify_sizes)
{
    const std::vector<unsigned char> seed(pqc::SLH_DSA_SHA2_128S_SEED_SIZE, 0x5c);
    std::vector<unsigned char> pubkey(pqc::SLH_DSA_SHA2_128S_PUBKEY_SIZE);
    std::vector<unsigned char> seckey(pqc::SLH_DSA_SHA2_128S_SECKEY_SIZE);
    BOOST_REQUIRE(pqc::SeedKeypair(pqc::Scheme::SLH_DSA_SHA2_128S, pubkey.data(), seckey.data(), seed.data(), seed.size()));

    const std::vector<unsigned char> msg(32, 0x11);
    std::vector<unsigned char> sig(pqc::SLH_DSA_SHA2_128S_SIG_SIZE);
    size_t sig_len{0};
    BOOST_REQUIRE(pqc::Sign(pqc::Scheme::SLH_DSA_SHA2_128S, sig.data(), &sig_len, msg.data(), seckey.data()));

    const auto verify = [&](const std::vector<unsigned char>& pk, const std::vector<unsigned char>& s) {
        return pqc::Verify(pqc::Scheme::SLH_DSA_SHA2_128S, pk.data(), pk.size(), msg.data(), s.data(), s.size());
    };
    BOOST_CHECK(verify(pubkey, sig));

    // Every size other than the scheme's own is refused, including the
    // trailing-sighash-byte length the opcode strips before calling.
    for (const int delta : {-1, 1}) {
        auto short_sig = sig;
        short_sig.resize(sig.size() + delta, 0x00);
        BOOST_CHECK(!verify(pubkey, short_sig));
        auto short_pk = pubkey;
        short_pk.resize(pubkey.size() + delta, 0x00);
        BOOST_CHECK(!verify(short_pk, sig));
    }

    // The other scheme's sizes are just as wrong.
    BOOST_CHECK(!verify(std::vector<unsigned char>(pqc::ML_DSA_44_PUBKEY_SIZE, 0x00), sig));
    BOOST_CHECK(!pqc::Verify(pqc::Scheme::ML_DSA_44, pubkey.data(), pubkey.size(), msg.data(), sig.data(), sig.size()));

    // Scheme bytes outside the two the design defines.
    for (const uint8_t b : {0x00, 0x03, 0x7f, 0xff}) {
        BOOST_CHECK(!pqc::IsKnownScheme(b));
    }
    BOOST_CHECK(pqc::IsKnownScheme(static_cast<uint8_t>(pqc::Scheme::ML_DSA_44)));
    BOOST_CHECK(pqc::IsKnownScheme(static_cast<uint8_t>(pqc::Scheme::SLH_DSA_SHA2_128S)));

    // Misuse of the key generation and signing entry points returns false
    // rather than tripping the guard inside randombytes().
    {
        std::vector<unsigned char> pk(pqc::ML_DSA_44_PUBKEY_SIZE);
        std::vector<unsigned char> sk(pqc::ML_DSA_44_SECKEY_SIZE);
        BOOST_CHECK(!pqc::SeedKeypair(pqc::Scheme::ML_DSA_44, pk.data(), sk.data(), seed.data(), 0));
        BOOST_CHECK(!pqc::SeedKeypair(pqc::Scheme::SLH_DSA_SHA2_128S, pubkey.data(), seckey.data(), seed.data(), seed.size() - 1));

        pqc::SetDeterministicEntropy(nullptr, 0);
        BOOST_CHECK(!pqc::HasDeterministicEntropy());

        // ML-DSA randomizes its signature and has nothing here to draw from.
        std::vector<unsigned char> ml_sig(pqc::ML_DSA_44_SIG_SIZE);
        size_t ml_sig_len{0};
        BOOST_CHECK(!pqc::Sign(pqc::Scheme::ML_DSA_44, ml_sig.data(), &ml_sig_len, msg.data(), sk.data()));

        // SLH-DSA signing is deterministic under FIPS 205, so it needs none
        // and reproduces what it produced while entropy was installed.
        std::vector<unsigned char> again(pqc::SLH_DSA_SHA2_128S_SIG_SIZE);
        size_t again_len{0};
        BOOST_CHECK(pqc::Sign(pqc::Scheme::SLH_DSA_SHA2_128S, again.data(), &again_len, msg.data(), seckey.data()));
        BOOST_CHECK_EQUAL(again_len, sig_len);
        BOOST_CHECK(again == sig);

        // Verification is unaffected: it draws no randomness.
        BOOST_CHECK(verify(pubkey, sig));

        // The entropy state is global, so put it back rather than leave the
        // next test case to discover it is gone.
        pqc::SetDeterministicEntropy(seed.data(), seed.size());
    }
}

/** OP_CHECKPQSIG (draft): ML-DSA-44, and the scheme byte telling the two
 *  schemes apart. */
BOOST_AUTO_TEST_CASE(script_pqsig_ml_dsa)
{
    const std::vector<unsigned char> seed(32, 0x2b);

    std::vector<unsigned char> ml_pubkey(pqc::ML_DSA_44_PUBKEY_SIZE);
    std::vector<unsigned char> ml_seckey(pqc::ML_DSA_44_SECKEY_SIZE);
    BOOST_REQUIRE(pqc::SeedKeypair(pqc::Scheme::ML_DSA_44, ml_pubkey.data(), ml_seckey.data(), seed.data(), seed.size()));

    std::vector<unsigned char> slh_pubkey(pqc::SLH_DSA_SHA2_128S_PUBKEY_SIZE);
    std::vector<unsigned char> slh_seckey(pqc::SLH_DSA_SHA2_128S_SECKEY_SIZE);
    const std::vector<unsigned char> slh_seed(pqc::SLH_DSA_SHA2_128S_SEED_SIZE, 0x2b);
    BOOST_REQUIRE(pqc::SeedKeypair(pqc::Scheme::SLH_DSA_SHA2_128S, slh_pubkey.data(), slh_seckey.data(), slh_seed.data(), slh_seed.size()));

    const auto commit_to = [](pqc::Scheme scheme, const std::vector<unsigned char>& pubkey) {
        HashWriter hasher{TaggedHash("PQPubKeyHash")};
        hasher.write(MakeByteSpan(pubkey));
        const uint256 hash{hasher.GetSHA256()};
        std::vector<unsigned char> commitment{static_cast<unsigned char>(scheme)};
        commitment.insert(commitment.end(), hash.begin(), hash.end());
        return commitment;
    };
    const std::vector<unsigned char> ml_commitment{commit_to(pqc::Scheme::ML_DSA_44, ml_pubkey)};

    const CScript leaf_ml = CScript() << ml_commitment << OP_CHECKPQSIG;
    const std::vector<unsigned char> leaf_ml_bytes(leaf_ml.begin(), leaf_ml.end());
    const CScript leaf_b = CScript() << OP_RETURN;
    const uint256 hash_ml = ComputeTapleafHash(TAPROOT_LEAF_TAPSCRIPT, leaf_ml);
    const uint256 hash_b = ComputeTapleafHash(TAPROOT_LEAF_TAPSCRIPT, leaf_b);

    const CScript spk = CScript() << OP_2 << ToByteVector(ComputeTapbranchHash(hash_ml, hash_b));
    const CAmount amount{10000};
    const CTransaction credit_tx{BuildCreditingTransaction(spk, amount)};
    CMutableTransaction spend_tx = BuildSpendingTransaction(CScript(), CScriptWitness(), credit_tx);
    spend_tx.vin[0].scriptWitness.stack.push_back({});

    PrecomputedTransactionData txdata;
    txdata.Init(spend_tx, {credit_tx.vout[0]});
    const MutableTransactionSignatureChecker checker{&spend_tx, 0, amount, txdata, MissingDataBehavior::FAIL};

    std::vector<unsigned char> control{static_cast<unsigned char>(TAPROOT_LEAF_TAPSCRIPT | 1)};
    control.insert(control.end(), hash_b.begin(), hash_b.end());

    const script_verify_flags pq_flags{SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT | SCRIPT_VERIFY_P2MR | SCRIPT_VERIFY_PQSIG};
    ScriptError err;

    // Sign the tapscript sighash of the ML-DSA leaf under either scheme, so
    // that the cross-scheme cases below sign the same message.
    const auto sign_leaf = [&](pqc::Scheme scheme, const std::vector<unsigned char>& seckey) {
        ScriptExecutionData execdata;
        execdata.m_annex_init = true;
        execdata.m_annex_present = false;
        execdata.m_tapleaf_hash_init = true;
        execdata.m_tapleaf_hash = hash_ml;
        execdata.m_codeseparator_pos_init = true;
        execdata.m_codeseparator_pos = 0xFFFFFFFF;
        uint256 sighash;
        BOOST_REQUIRE(SignatureHashSchnorr(sighash, execdata, spend_tx, 0, SIGHASH_DEFAULT, SigVersion::TAPSCRIPT, txdata, MissingDataBehavior::FAIL));
        std::vector<unsigned char> sig(pqc::SigSize(scheme));
        size_t sig_len{0};
        BOOST_REQUIRE(pqc::Sign(scheme, sig.data(), &sig_len, sighash.begin(), seckey.data()));
        BOOST_REQUIRE_EQUAL(sig_len, pqc::SigSize(scheme));
        return sig;
    };
    const std::vector<unsigned char> ml_sig{sign_leaf(pqc::Scheme::ML_DSA_44, ml_seckey)};
    BOOST_CHECK_EQUAL(ml_sig.size(), pqc::ML_DSA_44_SIG_SIZE);

    // Both halves are reproducible from the seed, which is what test vectors
    // need. They get there differently: SLH-DSA is deterministic in itself,
    // while this Dilithium copy enables DILITHIUM_RANDOMIZED_SIGNING and so
    // draws from the entropy hook. Reinstalling the seed puts that stream
    // back where it started.
    {
        std::vector<unsigned char> pk_again(pqc::ML_DSA_44_PUBKEY_SIZE);
        std::vector<unsigned char> sk_again(pqc::ML_DSA_44_SECKEY_SIZE);
        BOOST_REQUIRE(pqc::SeedKeypair(pqc::Scheme::ML_DSA_44, pk_again.data(), sk_again.data(), seed.data(), seed.size()));
        BOOST_CHECK(pk_again == ml_pubkey);
        BOOST_CHECK(sk_again == ml_seckey);

        pqc::SetDeterministicEntropy(seed.data(), seed.size());
        const auto sig_a{sign_leaf(pqc::Scheme::ML_DSA_44, ml_seckey)};
        pqc::SetDeterministicEntropy(seed.data(), seed.size());
        const auto sig_b{sign_leaf(pqc::Scheme::ML_DSA_44, ml_seckey)};
        BOOST_CHECK(sig_a == sig_b);
    }

    // Valid ML-DSA spend.
    {
        CScriptWitness w;
        w.stack = {ml_sig, ml_pubkey, leaf_ml_bytes, control};
        BOOST_CHECK(VerifyScript(CScript(), spk, &w, pq_flags, checker, &err));
        BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));
    }

    // Bit-flipped ML-DSA signature.
    {
        auto sig = ml_sig;
        sig[100] ^= 1;
        CScriptWitness w;
        w.stack = {sig, ml_pubkey, leaf_ml_bytes, control};
        BOOST_CHECK(!VerifyScript(CScript(), spk, &w, pq_flags, checker, &err));
        BOOST_CHECK_EQUAL(FormatScriptError(err), FormatScriptError(SCRIPT_ERR_PQSIG));
    }

    // An SLH-DSA key and signature over the same sighash, offered against a
    // leaf that commits to ML-DSA. The scheme byte fixes the expected sizes,
    // so this is rejected on size before anything else.
    {
        CScriptWitness w;
        w.stack = {sign_leaf(pqc::Scheme::SLH_DSA_SHA2_128S, slh_seckey), slh_pubkey, leaf_ml_bytes, control};
        BOOST_CHECK(!VerifyScript(CScript(), spk, &w, pq_flags, checker, &err));
        BOOST_CHECK_EQUAL(FormatScriptError(err), FormatScriptError(SCRIPT_ERR_PQSIG_SIZE));
    }

    // A leaf that commits to the same key under the other scheme byte. The
    // sizes line up with SLH-DSA, so this one gets past the size checks and
    // fails on the commitment instead.
    {
        const std::vector<unsigned char> wrong_scheme_commitment{commit_to(pqc::Scheme::SLH_DSA_SHA2_128S, ml_pubkey)};
        const CScript leaf_wrong = CScript() << wrong_scheme_commitment << OP_CHECKPQSIG;
        const uint256 hash_wrong = ComputeTapleafHash(TAPROOT_LEAF_TAPSCRIPT, leaf_wrong);
        const CScript spk_wrong = CScript() << OP_2 << ToByteVector(ComputeTapbranchHash(hash_wrong, hash_b));
        CScriptWitness w;
        w.stack = {std::vector<unsigned char>(pqc::SLH_DSA_SHA2_128S_SIG_SIZE, 0x00), slh_pubkey,
                   {leaf_wrong.begin(), leaf_wrong.end()}, control};
        BOOST_CHECK(!VerifyScript(CScript(), spk_wrong, &w, pq_flags, checker, &err));
        BOOST_CHECK_EQUAL(FormatScriptError(err), FormatScriptError(SCRIPT_ERR_PQSIG_PUBKEYHASH));
    }

    // Both schemes in one leaf, each with its own key.
    {
        const std::vector<unsigned char> slh_commitment{commit_to(pqc::Scheme::SLH_DSA_SHA2_128S, slh_pubkey)};
        const CScript leaf_both = CScript() << ml_commitment << OP_CHECKPQSIG << OP_VERIFY << slh_commitment << OP_CHECKPQSIG;
        const uint256 hash_both = ComputeTapleafHash(TAPROOT_LEAF_TAPSCRIPT, leaf_both);
        const CScript spk_both = CScript() << OP_2 << ToByteVector(ComputeTapbranchHash(hash_both, hash_b));
        const CTransaction credit_2{BuildCreditingTransaction(spk_both, amount)};
        CMutableTransaction spend_2 = BuildSpendingTransaction(CScript(), CScriptWitness(), credit_2);
        spend_2.vin[0].scriptWitness.stack.push_back({});
        PrecomputedTransactionData txdata_2;
        txdata_2.Init(spend_2, {credit_2.vout[0]});
        const MutableTransactionSignatureChecker checker_2{&spend_2, 0, amount, txdata_2, MissingDataBehavior::FAIL};

        ScriptExecutionData execdata;
        execdata.m_annex_init = true;
        execdata.m_annex_present = false;
        execdata.m_tapleaf_hash_init = true;
        execdata.m_tapleaf_hash = hash_both;
        execdata.m_codeseparator_pos_init = true;
        execdata.m_codeseparator_pos = 0xFFFFFFFF;
        uint256 sighash;
        BOOST_REQUIRE(SignatureHashSchnorr(sighash, execdata, spend_2, 0, SIGHASH_DEFAULT, SigVersion::TAPSCRIPT, txdata_2, MissingDataBehavior::FAIL));
        std::vector<unsigned char> sig_ml(pqc::ML_DSA_44_SIG_SIZE);
        std::vector<unsigned char> sig_slh(pqc::SLH_DSA_SHA2_128S_SIG_SIZE);
        size_t len_ml{0}, len_slh{0};
        BOOST_REQUIRE(pqc::Sign(pqc::Scheme::ML_DSA_44, sig_ml.data(), &len_ml, sighash.begin(), ml_seckey.data()));
        BOOST_REQUIRE(pqc::Sign(pqc::Scheme::SLH_DSA_SHA2_128S, sig_slh.data(), &len_slh, sighash.begin(), slh_seckey.data()));

        CScriptWitness w;
        w.stack = {sig_slh, slh_pubkey, sig_ml, ml_pubkey, {leaf_both.begin(), leaf_both.end()}, control};
        BOOST_CHECK(VerifyScript(CScript(), spk_both, &w, pq_flags, checker_2, &err));
        BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));
    }

    // The weight budget boundary at the ML-DSA cost of 200. The witness
    // holding one 2420-byte signature and its 1312-byte pubkey funds
    // twenty-three checks; each repetition past the first adds 37 bytes of
    // leaf script (37 of budget) but costs 200, so the twenty-fourth runs
    // out. Same shape as the SLH-DSA boundary test, which pins its cost at
    // eleven against twelve.
    {
        const auto spend_repeats = [&](int n) {
            CScript leaf;
            for (int j = 0; j < n; ++j) {
                leaf = leaf << OP_2DUP << ml_commitment << OP_CHECKPQSIG << OP_VERIFY;
            }
            leaf = leaf << OP_2DROP << OP_1;
            const uint256 hash_leaf = ComputeTapleafHash(TAPROOT_LEAF_TAPSCRIPT, leaf);
            const CScript spk_rep = CScript() << OP_2 << ToByteVector(ComputeTapbranchHash(hash_leaf, hash_b));
            const CTransaction credit_r{BuildCreditingTransaction(spk_rep, amount)};
            CMutableTransaction spend_r = BuildSpendingTransaction(CScript(), CScriptWitness(), credit_r);
            spend_r.vin[0].scriptWitness.stack.push_back({});
            PrecomputedTransactionData txdata_r;
            txdata_r.Init(spend_r, {credit_r.vout[0]});
            const MutableTransactionSignatureChecker checker_r{&spend_r, 0, amount, txdata_r, MissingDataBehavior::FAIL};

            ScriptExecutionData execdata;
            execdata.m_annex_init = true;
            execdata.m_annex_present = false;
            execdata.m_tapleaf_hash_init = true;
            execdata.m_tapleaf_hash = hash_leaf;
            execdata.m_codeseparator_pos_init = true;
            execdata.m_codeseparator_pos = 0xFFFFFFFF;
            uint256 sighash;
            BOOST_REQUIRE(SignatureHashSchnorr(sighash, execdata, spend_r, 0, SIGHASH_DEFAULT, SigVersion::TAPSCRIPT, txdata_r, MissingDataBehavior::FAIL));
            std::vector<unsigned char> sig(pqc::ML_DSA_44_SIG_SIZE);
            size_t sig_len{0};
            BOOST_REQUIRE(pqc::Sign(pqc::Scheme::ML_DSA_44, sig.data(), &sig_len, sighash.begin(), ml_seckey.data()));

            CScriptWitness w;
            w.stack = {sig, ml_pubkey, {leaf.begin(), leaf.end()}, control};
            return VerifyScript(CScript(), spk_rep, &w, pq_flags, checker_r, &err);
        };
        BOOST_CHECK(spend_repeats(23));
        BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));
        BOOST_CHECK(!spend_repeats(24));
        BOOST_CHECK_EQUAL(FormatScriptError(err), FormatScriptError(SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT));
    }
}

BOOST_AUTO_TEST_CASE(script_standard_push)
{
    ScriptError err;
    for (int i=0; i<67000; i++) {
        CScript script;
        script << i;
        BOOST_CHECK_MESSAGE(script.IsPushOnly(), "Number " << i << " is not pure push.");
        BOOST_CHECK_MESSAGE(VerifyScript(script, CScript() << OP_1, nullptr, SCRIPT_VERIFY_MINIMALDATA, BaseSignatureChecker(), &err), "Number " << i << " push is not minimal data.");
        BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));
    }

    for (unsigned int i=0; i<=MAX_SCRIPT_ELEMENT_SIZE; i++) {
        std::vector<unsigned char> data(i, '\111');
        CScript script;
        script << data;
        BOOST_CHECK_MESSAGE(script.IsPushOnly(), "Length " << i << " is not pure push.");
        BOOST_CHECK_MESSAGE(VerifyScript(script, CScript() << OP_1, nullptr, SCRIPT_VERIFY_MINIMALDATA, BaseSignatureChecker(), &err), "Length " << i << " push is not minimal data.");
        BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));
    }
}

BOOST_AUTO_TEST_CASE(script_IsPushOnly_on_invalid_scripts)
{
    // IsPushOnly returns false when given a script containing only pushes that
    // are invalid due to truncation. IsPushOnly() is consensus critical
    // because P2SH evaluation uses it, although this specific behavior should
    // not be consensus critical as the P2SH evaluation would fail first due to
    // the invalid push. Still, it doesn't hurt to test it explicitly.
    static const unsigned char direct[] = { 1 };
    BOOST_CHECK(!CScript(direct, direct+sizeof(direct)).IsPushOnly());
}

BOOST_AUTO_TEST_CASE(script_CheckMinimalPush_boundary)
{
    // Test the boundary at exactly 65535 bytes: must use OP_PUSHDATA2, not OP_PUSHDATA4.
    std::vector<unsigned char> data(65535, '\x42');
    BOOST_CHECK(CheckMinimalPush(data, OP_PUSHDATA2));
    BOOST_CHECK(!CheckMinimalPush(data, OP_PUSHDATA4));
}

BOOST_AUTO_TEST_CASE(script_GetScriptAsm)
{
    BOOST_CHECK_EQUAL("OP_CHECKLOCKTIMEVERIFY", ScriptToAsmStr(CScript() << OP_NOP2, true));
    BOOST_CHECK_EQUAL("OP_CHECKLOCKTIMEVERIFY", ScriptToAsmStr(CScript() << OP_CHECKLOCKTIMEVERIFY, true));
    BOOST_CHECK_EQUAL("OP_CHECKLOCKTIMEVERIFY", ScriptToAsmStr(CScript() << OP_NOP2));
    BOOST_CHECK_EQUAL("OP_CHECKLOCKTIMEVERIFY", ScriptToAsmStr(CScript() << OP_CHECKLOCKTIMEVERIFY));

    std::string derSig("304502207fa7a6d1e0ee81132a269ad84e68d695483745cde8b541e3bf630749894e342a022100c1f7ab20e13e22fb95281a870f3dcf38d782e53023ee313d741ad0cfbc0c5090");
    std::string pubKey("03b0da749730dc9b4b1f4a14d6902877a92541f5368778853d9c4a0cb7802dcfb2");
    std::vector<unsigned char> vchPubKey = ToByteVector(ParseHex(pubKey));

    BOOST_CHECK_EQUAL(derSig + "00 " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "00")) << vchPubKey, true));
    BOOST_CHECK_EQUAL(derSig + "80 " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "80")) << vchPubKey, true));
    BOOST_CHECK_EQUAL(derSig + "[ALL] " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "01")) << vchPubKey, true));
    BOOST_CHECK_EQUAL(derSig + "[NONE] " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "02")) << vchPubKey, true));
    BOOST_CHECK_EQUAL(derSig + "[SINGLE] " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "03")) << vchPubKey, true));
    BOOST_CHECK_EQUAL(derSig + "[ALL|ANYONECANPAY] " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "81")) << vchPubKey, true));
    BOOST_CHECK_EQUAL(derSig + "[NONE|ANYONECANPAY] " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "82")) << vchPubKey, true));
    BOOST_CHECK_EQUAL(derSig + "[SINGLE|ANYONECANPAY] " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "83")) << vchPubKey, true));

    BOOST_CHECK_EQUAL(derSig + "00 " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "00")) << vchPubKey));
    BOOST_CHECK_EQUAL(derSig + "80 " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "80")) << vchPubKey));
    BOOST_CHECK_EQUAL(derSig + "01 " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "01")) << vchPubKey));
    BOOST_CHECK_EQUAL(derSig + "02 " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "02")) << vchPubKey));
    BOOST_CHECK_EQUAL(derSig + "03 " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "03")) << vchPubKey));
    BOOST_CHECK_EQUAL(derSig + "81 " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "81")) << vchPubKey));
    BOOST_CHECK_EQUAL(derSig + "82 " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "82")) << vchPubKey));
    BOOST_CHECK_EQUAL(derSig + "83 " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "83")) << vchPubKey));
}

template <typename T>
CScript ToScript(const T& byte_container)
{
    auto span{MakeUCharSpan(byte_container)};
    return {span.begin(), span.end()};
}

BOOST_AUTO_TEST_CASE(script_byte_array_u8_vector_equivalence)
{
    const CScript scriptPubKey1 = CScript() << "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"_hex_v_u8 << OP_CHECKSIG;
    const CScript scriptPubKey2 = CScript() << "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"_hex << OP_CHECKSIG;
    BOOST_CHECK(scriptPubKey1 == scriptPubKey2);
}

BOOST_AUTO_TEST_CASE(script_FindAndDelete)
{
    // Exercise the FindAndDelete functionality
    CScript s;
    CScript d;
    CScript expect;

    s = CScript() << OP_1 << OP_2;
    d = CScript(); // delete nothing should be a no-op
    expect = s;
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 0);
    BOOST_CHECK(s == expect);

    s = CScript() << OP_1 << OP_2 << OP_3;
    d = CScript() << OP_2;
    expect = CScript() << OP_1 << OP_3;
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 1);
    BOOST_CHECK(s == expect);

    s = CScript() << OP_3 << OP_1 << OP_3 << OP_3 << OP_4 << OP_3;
    d = CScript() << OP_3;
    expect = CScript() << OP_1 << OP_4;
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 4);
    BOOST_CHECK(s == expect);

    s = ToScript("0302ff03"_hex); // PUSH 0x02ff03 onto stack
    d = ToScript("0302ff03"_hex);
    expect = CScript();
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 1);
    BOOST_CHECK(s == expect);

    s = ToScript("0302ff030302ff03"_hex); // PUSH 0x02ff03 PUSH 0x02ff03
    d = ToScript("0302ff03"_hex);
    expect = CScript();
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 2);
    BOOST_CHECK(s == expect);

    s = ToScript("0302ff030302ff03"_hex);
    d = ToScript("02"_hex);
    expect = s; // FindAndDelete matches entire opcodes
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 0);
    BOOST_CHECK(s == expect);

    s = ToScript("0302ff030302ff03"_hex);
    d = ToScript("ff"_hex);
    expect = s;
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 0);
    BOOST_CHECK(s == expect);

    // This is an odd edge case: strip of the push-three-bytes
    // prefix, leaving 02ff03 which is push-two-bytes:
    s = ToScript("0302ff030302ff03"_hex);
    d = ToScript("03"_hex);
    expect = CScript() << "ff03"_hex << "ff03"_hex;
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 2);
    BOOST_CHECK(s == expect);

    // Byte sequence that spans multiple opcodes:
    s = ToScript("02feed5169"_hex); // PUSH(0xfeed) OP_1 OP_VERIFY
    d = ToScript("feed51"_hex);
    expect = s;
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 0); // doesn't match 'inside' opcodes
    BOOST_CHECK(s == expect);

    s = ToScript("02feed5169"_hex); // PUSH(0xfeed) OP_1 OP_VERIFY
    d = ToScript("02feed51"_hex);
    expect = ToScript("69"_hex);
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 1);
    BOOST_CHECK(s == expect);

    s = ToScript("516902feed5169"_hex);
    d = ToScript("feed51"_hex);
    expect = s;
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 0);
    BOOST_CHECK(s == expect);

    s = ToScript("516902feed5169"_hex);
    d = ToScript("02feed51"_hex);
    expect = ToScript("516969"_hex);
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 1);
    BOOST_CHECK(s == expect);

    s = CScript() << OP_0 << OP_0 << OP_1 << OP_1;
    d = CScript() << OP_0 << OP_1;
    expect = CScript() << OP_0 << OP_1; // FindAndDelete is single-pass
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 1);
    BOOST_CHECK(s == expect);

    s = CScript() << OP_0 << OP_0 << OP_1 << OP_0 << OP_1 << OP_1;
    d = CScript() << OP_0 << OP_1;
    expect = CScript() << OP_0 << OP_1; // FindAndDelete is single-pass
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 2);
    BOOST_CHECK(s == expect);

    // Another weird edge case:
    // End with invalid push (not enough data)...
    s = ToScript("0003feed"_hex);
    d = ToScript("03feed"_hex); // ... can remove the invalid push
    expect = ToScript("00"_hex);
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 1);
    BOOST_CHECK(s == expect);

    s = ToScript("0003feed"_hex);
    d = ToScript("00"_hex);
    expect = ToScript("03feed"_hex);
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 1);
    BOOST_CHECK(s == expect);
}

BOOST_AUTO_TEST_CASE(script_HasValidOps)
{
    // Exercise the HasValidOps functionality
    CScript script;
    script = ToScript("76a9141234567890abcdefa1a2a3a4a5a6a7a8a9a0aaab88ac"_hex); // Normal script
    BOOST_CHECK(script.HasValidOps());
    script = ToScript("76a914ff34567890abcdefa1a2a3a4a5a6a7a8a9a0aaab88ac"_hex);
    BOOST_CHECK(script.HasValidOps());
    script = ToScript("ff88ac"_hex); // Script with OP_INVALIDOPCODE explicit
    BOOST_CHECK(!script.HasValidOps());
    script = ToScript("88acc0"_hex); // Script with undefined opcode
    BOOST_CHECK(!script.HasValidOps());
}

BOOST_AUTO_TEST_CASE(bip341_keypath_test_vectors)
{
    UniValue tests;
    tests.read(json_tests::bip341_wallet_vectors);

    const auto& vectors = tests["keyPathSpending"];

    for (const auto& vec : vectors.getValues()) {
        auto txhex = ParseHex(vec["given"]["rawUnsignedTx"].get_str());
        CMutableTransaction tx;
        SpanReader{txhex} >> TX_WITH_WITNESS(tx);
        std::vector<CTxOut> utxos;
        for (const auto& utxo_spent : vec["given"]["utxosSpent"].getValues()) {
            auto script_bytes = ParseHex(utxo_spent["scriptPubKey"].get_str());
            CScript script{script_bytes.begin(), script_bytes.end()};
            CAmount amount{utxo_spent["amountSats"].getInt<int>()};
            utxos.emplace_back(amount, script);
        }

        PrecomputedTransactionData txdata;
        txdata.Init(tx, std::vector<CTxOut>{utxos}, true);

        BOOST_CHECK(txdata.m_bip341_taproot_ready);
        BOOST_CHECK_EQUAL(HexStr(txdata.m_spent_amounts_single_hash), vec["intermediary"]["hashAmounts"].get_str());
        BOOST_CHECK_EQUAL(HexStr(txdata.m_outputs_single_hash), vec["intermediary"]["hashOutputs"].get_str());
        BOOST_CHECK_EQUAL(HexStr(txdata.m_prevouts_single_hash), vec["intermediary"]["hashPrevouts"].get_str());
        BOOST_CHECK_EQUAL(HexStr(txdata.m_spent_scripts_single_hash), vec["intermediary"]["hashScriptPubkeys"].get_str());
        BOOST_CHECK_EQUAL(HexStr(txdata.m_sequences_single_hash), vec["intermediary"]["hashSequences"].get_str());

        for (const auto& input : vec["inputSpending"].getValues()) {
            int txinpos = input["given"]["txinIndex"].getInt<int>();
            int hashtype = input["given"]["hashType"].getInt<int>();

            // Load key.
            auto privkey = ParseHex(input["given"]["internalPrivkey"].get_str());
            CKey key;
            key.Set(privkey.begin(), privkey.end(), true);

            // Load Merkle root.
            uint256 merkle_root;
            if (!input["given"]["merkleRoot"].isNull()) {
                merkle_root = uint256{ParseHex(input["given"]["merkleRoot"].get_str())};
            }

            // Compute and verify (internal) public key.
            XOnlyPubKey pubkey{key.GetPubKey()};
            BOOST_CHECK_EQUAL(HexStr(pubkey), input["intermediary"]["internalPubkey"].get_str());

            // Sign and verify signature.
            FlatSigningProvider provider;
            provider.keys[key.GetPubKey().GetID()] = key;
            MutableTransactionSignatureCreator creator(tx, txinpos, utxos[txinpos].nValue, &txdata, {.sighash_type = hashtype});
            std::vector<unsigned char> signature;
            BOOST_CHECK(creator.CreateSchnorrSig(provider, signature, pubkey, nullptr, &merkle_root, SigVersion::TAPROOT));
            BOOST_CHECK_EQUAL(HexStr(signature), input["expected"]["witness"][0].get_str());

            // We can't observe the tweak used inside the signing logic, so verify by recomputing it.
            BOOST_CHECK_EQUAL(HexStr(pubkey.ComputeTapTweakHash(merkle_root.IsNull() ? nullptr : &merkle_root)), input["intermediary"]["tweak"].get_str());

            // We can't observe the sighash used inside the signing logic, so verify by recomputing it.
            ScriptExecutionData sed;
            sed.m_annex_init = true;
            sed.m_annex_present = false;
            uint256 sighash;
            BOOST_CHECK(SignatureHashSchnorr(sighash, sed, tx, txinpos, hashtype, SigVersion::TAPROOT, txdata, MissingDataBehavior::FAIL));
            BOOST_CHECK_EQUAL(HexStr(sighash), input["intermediary"]["sigHash"].get_str());

            // To verify the sigmsg, hash the expected sigmsg, and compare it with the (expected) sighash.
            BOOST_CHECK_EQUAL(HexStr((HashWriter{HASHER_TAPSIGHASH} << std::span<const uint8_t>{ParseHex(input["intermediary"]["sigMsg"].get_str())}).GetSHA256()), input["intermediary"]["sigHash"].get_str());
        }
    }
}

BOOST_AUTO_TEST_CASE(compute_tapbranch)
{
    constexpr uint256 hash1{"8ad69ec7cf41c2a4001fd1f738bf1e505ce2277acdcaa63fe4765192497f47a7"};
    constexpr uint256 hash2{"f224a923cd0021ab202ab139cc56802ddb92dcfc172b9212261a539df79a112a"};
    constexpr uint256 result{"a64c5b7b943315f9b805d7a7296bedfcfd08919270a1f7a1466e98f8693d8cd9"};
    BOOST_CHECK_EQUAL(ComputeTapbranchHash(hash1, hash2), result);
}

BOOST_AUTO_TEST_CASE(compute_tapleaf)
{
    constexpr uint8_t script[6] = {'f','o','o','b','a','r'};
    constexpr uint256 tlc0{"edbc10c272a1215dcdcc11d605b9027b5ad6ed97cd45521203f136767b5b9c06"};
    constexpr uint256 tlc2{"8b5c4f90ae6bf76e259dbef5d8a59df06359c391b59263741b25eca76451b27a"};

    BOOST_CHECK_EQUAL(ComputeTapleafHash(0xc0, std::span(script)), tlc0);
    BOOST_CHECK_EQUAL(ComputeTapleafHash(0xc2, std::span(script)), tlc2);
}

BOOST_AUTO_TEST_CASE(formatscriptflags)
{
    // quick check that FormatScriptFlags reports any unknown/unexpected bits
    BOOST_CHECK_EQUAL(FormatScriptFlags(SCRIPT_VERIFY_P2SH), "P2SH");
    BOOST_CHECK_EQUAL(FormatScriptFlags(SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_TAPROOT), "P2SH,TAPROOT");
    BOOST_CHECK_EQUAL(FormatScriptFlags(SCRIPT_VERIFY_P2SH | script_verify_flags::from_int(1u<<31)), "P2SH,0x80000000");
    BOOST_CHECK_EQUAL(FormatScriptFlags(SCRIPT_VERIFY_TAPROOT | script_verify_flags::from_int(1u<<27)), "TAPROOT,0x08000000");
    BOOST_CHECK_EQUAL(FormatScriptFlags(SCRIPT_VERIFY_TAPROOT | script_verify_flags::from_int((1u<<28) | (1ull<<58))), "TAPROOT,0x400000010000000");
    BOOST_CHECK_EQUAL(FormatScriptFlags(script_verify_flags::from_int(1u<<26)), "0x04000000");
}

BOOST_AUTO_TEST_SUITE_END()
