# Vendored post-quantum signature code

slhdsa/: SLH-DSA (FIPS 205), copied unmodified from
pq-code-package/slhdsa-c at commit
174c02e42257f95c210963272877c49dbb50070f. Only the SHA2 half is here,
which is slh_dsa.c, slh_sha2.c and the two SHA-2 cores: the SHAKE
sources and their SHA-3 backing are for parameter sets this build
does not offer. That leaves the six SHA2 sets compiled, of which the
opcode selects SLH-DSA-SHA2-128s at each call through a parameter
pointer, since upstream picks the set at runtime rather than by macro.

test/pqc_acvp_tests.cpp runs NIST's own ACVP cases for that parameter
set against this code: key generation, verification and signing. That
is what backs the FIPS 205 name, and pqc_acvp_ml_dsa_tests.cpp does
the same for FIPS 204 on the verification side.

dilithium/: ML-DSA-44 (FIPS 204), copied unmodified from
libbitcoinpqc at commit 053e954534b13c1dbdc8ef4f9ae4d93bb301bab6
(github.com/cryptoquick/libbitcoinpqc), which vendors upstream commit
444cdcc84eb36b66fe27b3a2529ee48f6d8150c2 and pins it. Built with
DILITHIUM_MODE=2, and only the files that build reaches are here.
Beware that reachability is not obvious from the file names when
pruning: a header can be pulled in through a relative path from a
parameter header rather than by name.

Dilithium's randombytes.c is not vendored: src/pqc/randombytes.cpp
provides that symbol instead. Dilithium calls it in key generation,
and this copy also calls it while signing, and it aborts if it is
reached with no entropy installed. That is a guard against vendored
code drawing randomness nobody arranged for; the entry points in
pqc_verify.h return false on ordinary misuse instead. SLH-DSA reaches
none of it, taking its key seeds as arguments and signing
deterministically. Consensus only ever verifies, which needs no
randomness under either scheme.

The upstream licence files sit alongside the sources they cover:
slhdsa/LICENSE, whose SPDX expression is per file, and
dilithium/LICENSE.

Consensus code goes through src/pqc/pqc_verify.{h,cpp}. The
per-scheme backends behind it are in separate translation units for
the reason given at the top of slh_dsa.cpp.
