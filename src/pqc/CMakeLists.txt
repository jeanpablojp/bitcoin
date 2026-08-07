# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

# Vendored post-quantum signature code (see README.md for provenance).
# Each scheme gets its own translation unit; see the comment in slh_dsa.cpp
# for why the two reference implementations cannot share one.
add_library(bitcoin_pqc STATIC EXCLUDE_FROM_ALL
  pqc_verify.cpp
  randombytes.cpp
  slh_dsa.cpp
  ml_dsa.cpp
  slhdsa/slh_dsa.c
  slhdsa/slh_sha2.c
  slhdsa/sha2_256.c
  slhdsa/sha2_512.c
  dilithium/fips202.c
  dilithium/ntt.c
  dilithium/packing.c
  dilithium/poly.c
  dilithium/polyvec.c
  dilithium/reduce.c
  dilithium/rounding.c
  dilithium/sign.c
  dilithium/symmetric-shake.c
)
target_compile_definitions(bitcoin_pqc PRIVATE DILITHIUM_MODE=2)
target_link_libraries(bitcoin_pqc PRIVATE core_interface bitcoin_crypto)
