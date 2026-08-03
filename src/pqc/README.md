# Vendored post-quantum signature code

sphincsplus/: SLH-DSA-SHA2-128s (FIPS 205) reference implementation,
copied unmodified from the sphincsplus/ref tree vendored in
libbitcoinpqc at commit 053e954534b13c1dbdc8ef4f9ae4d93bb301bab6
(github.com/cryptoquick/libbitcoinpqc), which pins the NIST reference
code at commit 7ec789ace6874d875f4bb84cb61b81155398167e. Built with
PARAMS=sphincs-sha2-128s, the same parameter set libbitcoinpqc uses.

Only the files needed for the sha2-128s "simple" parameter set are
vendored (no haraka, no shake, no robust variants). randombytes.c is
linked for tests only; consensus code calls verification exclusively.

The upstream licence files are vendored alongside the sources:
sphincsplus/LICENSE carries the SPDX expression the reference
implementation ships with, and sphincsplus/LICENSES/ holds the texts
it names.

The wrapper consensus code uses is src/pqc/pqc_verify.{h,cpp}.
