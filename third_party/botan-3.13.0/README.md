# Botan 3.13.0, vendored

This folder holds a minimized amalgamation of the Botan cryptography library, the only implementation of cryptography in TULPAR (RSD-CRY-01e; `docs/design/crypto.md`, Section 5.1). Only the M-CRY crypto core includes it (`tools/deps_rules.json`).

Nothing here is edited by hand. To change it, edit `generate.sh` and run it; it rewrites `botan_all.h`, `botan_all.cpp` and `license.txt` and prints their module list and checksums, which this file then records.

## Source

| Item | Value |
|---|---|
| Repository | `https://github.com/randombit/botan.git` |
| Tag | `3.13.0` |
| Commit | `2a81eef56c96c237e590c27f9a75e60317c9c700` (checked by `generate.sh`) |
| Generated | 28 November 2026, Ubuntu 24.04, GCC 13.3, Python 3.13 |

## Command

```
python3 -I configure.py --amalgamation --minimized-build \
    --enable-modules=ml_dsa,ml_kem,aes,gcm,sha2_64,hmac,hkdf,hmac_drbg \
    --cc=gcc --os=linux --cpu=x86_64 --disable-shared-library --without-documentation \
    --with-build-dir=.
```

## Modules

`configure.py` adds the modules that the requested ones depend on and, in a minimized build, no others:

```
aead aes asn1 base base64 bigint block ctr dilithium_common dilithium_shake enc_padding gcm ghash hash
hex hkdf hmac hmac_drbg kdf keccak_perm keypair kyber_common mac mdx_hash ml_dsa ml_kem modes mp
numbertheory os_utils pem pqcrystals pubkey rng sha2_64 sha3 shake shake_xof sponge stateful_rng
stream utils xof
```

Botan's auto-seeded and system generators (`auto_rng`, `system_rng`) are not in the build, so the only random sources are the ones M-CRY seeds itself. CPU-specific modules such as `aes_ni` are not built either; the results are the same, only slower.

## Checksums (SHA-256)

```
09acbace7c6f80549f65b9b30f7783400de32b183cf2e04ebff8ec0c071b1c9b  botan_all.h
3c04b89342273e27453be76764ab4bf88c3642e5637bf3b0e84cafbbeff8663e  botan_all.cpp
```

Running `generate.sh` twice gave the same checksums.

## Version string

The files come from the git tag, not from the release tarball, whose packaging script stamps the release date and revision. `BOTAN_VERSION_MAJOR`, `BOTAN_VERSION_MINOR` and `BOTAN_VERSION_PATCH` are 3, 13 and 0, but `BOTAN_VERSION_RELEASE_TYPE` is `"unreleased"` and `BOTAN_VERSION_VC_REVISION` is `"unknown"`. The commit above identifies the source.

## Licence

Botan is distributed under the BSD-2-Clause licence (`license.txt`, copied unchanged), which is compatible with TULPAR's GPL-2.0-only.
