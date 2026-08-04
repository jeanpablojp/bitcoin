# Vendored post-quantum signature code

Both trees are copied unmodified from libbitcoinpqc at commit
053e954534b13c1dbdc8ef4f9ae4d93bb301bab6
(github.com/cryptoquick/libbitcoinpqc), which vendors the upstream
reference code and pins it.

sphincsplus/: SLH-DSA-SHA2-128s (FIPS 205), upstream commit
7ec789ace6874d875f4bb84cb61b81155398167e, built with
PARAMS=sphincs-sha2-128s. Only the files the sha2-128s "simple"
parameter set needs are here: no haraka, no shake, no robust variants.

dilithium/: ML-DSA-44 (FIPS 204), upstream commit
444cdcc84eb36b66fe27b3a2529ee48f6d8150c2, built with
DILITHIUM_MODE=2. Only the files that build reaches are here.

Beware that reachability is not obvious from the file names when
pruning either tree: sphincsplus/sha2_offsets.h looks unreferenced,
but the parameter header includes it through a relative path.

Neither randombytes.c is vendored: both define the same symbol, so
src/pqc/randombytes.cpp provides the single definition instead. Both
implementations call it, in key generation and in signing, and it
aborts if it is reached with no entropy installed. That is a guard
against vendored code drawing randomness nobody arranged for; the
entry points in pqc_verify.h return false on ordinary misuse instead.
Consensus only ever verifies, which needs no randomness at all.

The upstream licence files sit alongside the sources they cover:
sphincsplus/LICENSE with the SPDX expression and sphincsplus/LICENSES/
with the texts it names, and dilithium/LICENSE.

Consensus code goes through src/pqc/pqc_verify.{h,cpp}. The
per-scheme backends behind it are in separate translation units for
the reason given at the top of slh_dsa.cpp.
