# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

# Vendored post-quantum signature code (see README.md for provenance).
add_library(bitcoin_pqc STATIC EXCLUDE_FROM_ALL
  pqc_verify.cpp
  sphincsplus/address.c
  sphincsplus/fors.c
  sphincsplus/hash_sha2.c
  sphincsplus/merkle.c
  sphincsplus/randombytes.c
  sphincsplus/sha2.c
  sphincsplus/sign.c
  sphincsplus/thash_sha2_simple.c
  sphincsplus/utils.c
  sphincsplus/utilsx1.c
  sphincsplus/wots.c
  sphincsplus/wotsx1.c
)
target_compile_definitions(bitcoin_pqc PRIVATE PARAMS=sphincs-sha2-128s)
target_link_libraries(bitcoin_pqc PRIVATE core_interface)
