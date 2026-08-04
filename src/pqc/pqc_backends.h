// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PQC_PQC_BACKENDS_H
#define BITCOIN_PQC_PQC_BACKENDS_H

#include <cstddef>

/** Per-scheme entry points. Each backend lives in its own translation unit
 *  so that the vendored reference implementations, which disagree about
 *  symbol naming, never meet in one file. Callers go through pqc_verify.h. */
namespace pqc::backend {

bool SlhDsaSeedKeypair(unsigned char* pk, unsigned char* sk, const unsigned char* seed);
bool SlhDsaSign(unsigned char* sig, size_t* sig_len, const unsigned char* msg32, const unsigned char* sk);
bool SlhDsaVerify(const unsigned char* sig, size_t sig_len, const unsigned char* msg32, const unsigned char* pk);

bool MlDsaKeypair(unsigned char* pk, unsigned char* sk);
bool MlDsaSign(unsigned char* sig, size_t* sig_len, const unsigned char* msg32, const unsigned char* sk);
bool MlDsaVerify(const unsigned char* sig, size_t sig_len, const unsigned char* msg32, const unsigned char* pk);

} // namespace pqc::backend

#endif // BITCOIN_PQC_PQC_BACKENDS_H
