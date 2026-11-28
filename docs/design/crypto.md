# TULPAR M-CRY cryptographic core: design

**Status:** DRAFT, awaiting approval (Özgür Can Güngör; Section 5.6, the IV rule and the acknowledgment counter it asks of the TDP formats: Cemre Karabulut; Sections 5.4 and 5.7, the key seeds and the delay table: Çağlar Mesci). No code is written against this document before approval.
**Issues:** TULPAR-57 (RSD-CRY-01, atomic issues TULPAR-280 to TULPAR-286), TULPAR-463 (RSD-SIM-01b), TULPAR-159 (TBR-01).

## 0. Requirements

The RSD (`docs/rsd/TULPAR_RSD.md`) governs. The rows this design answers:

| Identifier | Requirement | Verification in the RSD |
|---|---|---|
| RSD-CRY-01a | "Key establishment for hop and end-to-end sessions and for bundle encapsulation shall use ML-KEM-1024." | "I, T. Configuration check of the suite identifier; crypto unit tests of the handshake and of bundle encapsulation with ML-KEM-1024 test vectors." |
| RSD-CRY-01b | "Bundles, handshake transcripts, link-state advertisements and every other signed record shall be signed with ML-DSA-87." | "I, T. Crypto unit tests: every signed record type verifies under ML-DSA-87; a wrong key produces a real verification failure." |
| RSD-CRY-01c | "Message encryption and integrity shall use AES-256-GCM." | "T. Crypto unit tests: AES-256-GCM encryption and tag verification; a modified ciphertext or associated datum fails verification." |
| RSD-CRY-01d | "Hashing, message authentication and key derivation shall use SHA-384, HMAC-SHA-384 and HKDF-SHA-384." | "T. Crypto unit tests of SHA-384, HMAC-SHA-384 and HKDF-SHA-384 against published test vectors." |
| RSD-CRY-01e | "From Phase 1, every cryptographic operation in the simulation shall be performed with the real algorithm through Botan 3.13.0." | "S, T. Build inspection: Botan 3.13.0 is linked into the crypto target from Phase 1; no stub produces signatures, ciphertexts or tags. Packet traces carry real sizes (4627-byte signatures, 1568-byte ciphertexts)." |
| RSD-CRY-01f | "ML-DSA-87 signing shall run in deterministic mode in the simulation." | "T. Two signatures over the same payload with the same key are byte-identical in simulation runs." |
| RSD-CRY-01g | "Every AES-256-GCM IV shall be constructed deterministically by a fixed rule for its session type, so that no IV repeats under one key." | "T. IV-rule unit tests for hop sessions, end-to-end sessions (including several attempts of one message) and swarm-key broadcasts: no IV repeats under one key (CLM-36)." |
| RSD-SIM-01b | "The delay table shall be produced by a micro-benchmark of ML-DSA-87 signing and verification and ML-KEM-1024 encapsulation and decapsulation on the development machine." | "I. The micro-benchmark report lists the four operations with the development machine, Botan version and repetition count, and the delay table is loaded as a simulation parameter." |

Related rows that this design must not break:

- RSD-SIM-01a (Çağlar Mesci): "Cryptographic processing delays shall be scheduled in simulation time from the micro-benchmark delay table, never from the wall clock during a run."
- RSD-SIM-01c (Çağlar Mesci): "All random streams and generated keys of a run shall be derived from the run seed, with MRG32k3a streams separated by run number and keys seeded by run and node number."
- RSD-CRY-02a: "The key provider shall never export a private key."
- RSD-NET-05e and RSD-HOT-05c, which use AES-256-GCM with one-time keys for bundles to disconnected destinations and for records sealed to headquarters.

TBR-01 ("ML-DSA-87 signing (≈ 0.96 ms) and verification (≈ 0.51 ms) times on the development machine") stands in Section 4.5, Table 4.30 and Section 6.5 until it is "Replaced by the Phase 1 micro-benchmark values". Algorithm sizes are those of Table 2.1.

## 1. Intent

From Phase 1, every signature, ciphertext, tag and hash in a TULPAR run is produced by the real algorithm through Botan 3.13.0, with real sizes, and every run stays reproducible from its seed. Other modules reach cryptography only through M-CRY (Table 4.25, I6: "Sign, verify, session, epoch announcement"). Simulated processing time comes from a table measured once on the development machine, never from the host clock during a run.

## 2. Goals, non-goals, anti-goals

**Goals.**
- An M-CRY interface for SHA-384, HMAC-SHA-384, HKDF-SHA-384, AES-256-GCM, ML-DSA-87 and ML-KEM-1024 that the December work of M-COM (HELLO tags, hop tags) and M-EVS (record identifiers, bundle signatures) can build on.
- Keys, signatures and encapsulations that are identical for the same run seed, run number and node.
- An IV rule under which no AES-256-GCM IV can repeat under one key, restarts included.
- A micro-benchmark, its report and the delay table of RSD-SIM-01b.

**Non-goals.** Sessions and handshakes (RSD-CRY-03, RSD-CMC-04), the key provider (RSD-CRY-02), provisioning (generating the long-term keys and handing them out), key epochs, the canonical-encoding validator (RSD-CRY-02e), the formats of TULPAR-480 and TULPAR-481, scheduling the delays in simulation time (RSD-SIM-01a), and the P-384 comparison baseline of experiment E1. They build on this core later.

**Anti-goals.** Any of these makes the work a failure even if every test passes:
- a Botan type or header visible to a module other than M-CRY;
- cryptographic randomness from any source other than the generators of Section 5.4;
- an agent that can compute another node's key seed;
- a stub that produces a signature, ciphertext or tag;
- benchmark or other wall-clock code inside `module/agent/`.

## 3. Constraints

- **Toolchain** (`CLAUDE.md`): ns-3.49 module, C++23, CMake and Ninja, GCC 13, Ubuntu 24.04 on x86-64, GPL-2.0-only. Botan is BSD-2-Clause, which is compatible with GPL-2.0-only.
- **Dependencies** (`tools/deps_rules.json`): an agent module includes only its own headers, `common/` and M-CRY. The harness includes only `common/`, the agent root and itself, so it reaches M-CRY only through the agent root. `tools/check_static.py` enforces the include graph and keeps wall-clock patterns out of `module/agent/`.
- **Linking:** ns-3 builds `libtulpar` and the module's test library as shared libraries, and the static agent targets are linked into them.
- **CI:** clang-format checks every `*.h` and `*.cc` under `module/`, so vendored code lives outside `module/`. The build job runs only the G0 suite today.
- **Ownership:** `module/CMakeLists.txt` and the CI workflow are shared files of Çağlar Mesci. This design adds only M-CRY's own targets, test and CI step to them.

## 4. Approaches to bringing in Botan

| | Approach | Trade-off | Decision |
|---|---|---|---|
| a | Vendor a minimized Botan 3.13.0 amalgamation (one `.cpp`, one `.h`) under `third_party/`, with the script that generated it | Nobody installs anything, and the Dockerfile and the bootstrap script stay as they are. The repository gains several MB of generated code, which a clean build compiles. | **Chosen** (Özgür Can Güngör, 28 November 2026) |
| b | `scripts/bootstrap.sh` builds Botan 3.13.0 from source into `external/`; CI caches it | Small repository; every member reruns the bootstrap, and the bootstrap script, the CI workflow and the Dockerfile, all shared files of Çağlar Mesci, change | Rejected |
| c | Ubuntu 24.04 system package | Ubuntu 24.04 does not ship Botan 3.13.0, and RSD-CRY-01e names the exact version | Rejected |
| d | CMake `FetchContent` at configure time | A clean configure needs the network, and Botan's Python configure step runs inside the ns-3 build | Rejected |

## 5. Design

### 5.1 Vendored Botan

`third_party/botan-3.13.0/` holds:
- `botan_all.h` and `botan_all.cpp`, the amalgamation;
- `license.txt`, Botan's licence, unchanged;
- `generate.sh`, which clones tag `3.13.0` of `github.com/randombit/botan`, checks that it resolves to commit `2a81eef56c96c237e590c27f9a75e60317c9c700`, runs Botan's `configure.py` with `--amalgamation --minimized-build --enable-modules=ml_dsa,ml_kem,aes,gcm,sha2_64,hmac,hkdf,hmac_drbg` for GCC on Linux x86-64, and copies the two files;
- `README.md`, which records the tag, the commit, the exact command, the module list that `configure.py` reports, the date of generation and the checksums of the two files.

`configure.py` adds the modules these depend on. In a minimized build it loads no other optional module, so Botan's auto-seeded and system generators (modules `auto_rng` and `system_rng`) are not built, and neither are CPU-specific modules such as `aes_ni`; the module list in `README.md` shows this. Nothing in the folder is edited by hand; a change means rerunning `generate.sh`.

### 5.2 Build targets

- **`tulpar_botan`** compiles `botan_all.cpp`. It is compiled with `-O3` and with warnings disabled, whatever the ns-3 build profile, so the tests, every simulation build and the benchmark link the same optimized Botan code. Its include directory is `third_party/botan-3.13.0`.
- **`tulpar_crypto`** is the crypto core of Sections 5.3 to 5.7, a static target in `module/agent/cry/`. It links `tulpar_botan` with a separate `PRIVATE` link, not through the `DEPS` of `tulpar_static_target`, which links publicly. Botan's include directory therefore reaches `tulpar_crypto` and no target that links it. The core links no ns-3 library and registers nothing with ns-3 (no `TypeId`, no log component).
- **`tulpar_cry`**, the agent module, links `tulpar_crypto`. So do the module's test library, which runs the crypto tests, and the benchmark program. A static library linked into both `libtulpar` and the test library exists twice in one process. That is safe for code that registers nothing with ns-3, and the core is a target of its own for this reason.
- Both new targets are declared with `tulpar_static_target` and listed in the `cmake_targets` of `tools/deps_rules.json`. The rules also gain a part `botan` (`third_party/botan-3.13.0`) that only `cry` may include. `tools/check_static.py` then reports any include of `botan_all.h` by quoted name or path outside M-CRY, and any static target outside M-CRY that lists `tulpar_botan` in its `DEPS`, without a change to the checker. M-CRY includes Botan in that form (`#include "botan_all.h"`); an include in angle brackets does not compile elsewhere, because no other target has Botan's include directory. These rules add restrictions and relax none.
- A `static_assert` in the M-CRY source checks `BOTAN_VERSION_MAJOR`, `BOTAN_VERSION_MINOR` and `BOTAN_VERSION_PATCH` against 3, 13 and 0.
- The CMake code finds `third_party/` through the real path of the module directory, because ns-3 sees the module through the link `external/ns-3/contrib/tulpar`.
- CI runs the `tulpar-cry` suite in a step of its own, next to the G0 checks.

### 5.3 M-CRY interface

A new header `module/agent/cry/tulpar-crypto.h` in namespace `ns3::tulpar::crypto` uses only standard types: `Bytes` is `std::vector<std::uint8_t>`, and inputs are `std::span<const std::uint8_t>`. Every random input is an explicit argument, so a test can pass the bytes of a published vector and a caller draws them from a generator of Section 5.4.

| Function or class | Result | Size |
|---|---|---|
| `Sha384(data)` | digest | 48 B |
| `HmacSha384(key, data)` | tag | 48 B |
| `HmacSha384Verify(key, data, tag)` | true if `tag` equals the first bytes of the HMAC, compared in constant time | `tag` of 8 to 48 B (16 B for HELLO, Table 4.26; 8 B per receiver for telemetry, Table 4.29) |
| `HkdfSha384(ikm, salt, info, length)` | key material | `length` B |
| `Aes256GcmSeal(key, iv, aad, plaintext)` | ciphertext followed by the tag | plaintext + 16 B |
| `Aes256GcmOpen(key, iv, aad, sealed)` | plaintext, or nothing if the tag fails | |
| `MlDsa87KeyPair::FromSeed(xi)`, `.PublicKey()`, `.Sign(message)` | key pair from the 32-byte seed ξ of FIPS 204; public key; deterministic signature | 2592 B; 4627 B |
| `MlDsa87Verify(publicKey, message, signature)` | true or false | |
| `MlKem1024KeyPair::FromSeed(dz)`, `.EncapsulationKey()`, `.Decapsulate(ciphertext)` | key pair from the 64-byte seed d ‖ z of FIPS 203; encapsulation key; shared secret (for a modified ciphertext, the implicit-rejection secret of FIPS 203), or nothing for a ciphertext of the wrong size | 1568 B; 32 B |
| `MlKem1024Encapsulate(encapsulationKey, m)` | ciphertext and shared secret from the 32-byte randomness m | 1568 B; 32 B |
| `DeterministicRandom(seed)`, `.Draw(n)` | seeded generator (Section 5.4); `n` bytes | seed 48 B |
| `MakeIv(use, direction, rosterPosition, value)`, `FrameCounter` | IV and frame counters (Section 5.6) | 12 B; 8 B |
| `ParseCryptoDelayTable(text)` | delay table, or an error (Section 5.7) | |

Inside M-CRY, each explicit random input reaches Botan through a generator that returns exactly those bytes and fails if asked for more, so an unexpected draw stops the call instead of using other randomness. Key pairs hold their Botan objects behind a private implementation, so the header includes no Botan file. A key pair is built from its seed, and no function returns private-key bytes (RSD-CRY-02a).

### 5.4 Randomness and key seeds

**Generator.** `DeterministicRandom` is Botan's `HMAC_DRBG` over HMAC-SHA-384, built with the constructor that has no underlying generator. That constructor never reseeds from the operating system, so the output depends only on the 48-byte seed. It is the only source of random bytes in M-CRY: the fixed-bytes generator of Section 5.3 only passes on bytes drawn from it or given by a test, and the Botan build contains no generator that seeds itself (Section 5.1).

**Derivations.** Every derivation is HKDF-SHA-384 (RSD-CRY-01d) with an empty salt and an ASCII label as `info`, in the style of the encodings' domain labels (`docs/design/encodings.md`, K12). Integers are big-endian.

| Value | HKDF-SHA-384 input key material and label | Computed by |
|---|---|---|
| Node seed (48 B) | u32 run seed ‖ u64 run number ‖ u16 roster index; `"TULPAR/1/node-seed"` | Provisioning only |
| ML-DSA-87 seed ξ (32 B) | node seed; `"TULPAR/1/ml-dsa-87-keygen"` | Provisioning |
| ML-KEM-1024 seed d ‖ z (64 B) | node seed; `"TULPAR/1/ml-kem-1024-keygen"` | Provisioning |
| Runtime seed (48 B) | node seed; `"TULPAR/1/runtime"` | Provisioning, which hands it to the node |
| Seed of the generator for purpose p in start s (48 B) | runtime seed; `"TULPAR/1/"` ‖ p ‖ u16 s | The node's M-CRY |

- **Inputs.** The run seed and run number are the harness's run configuration, and the roster index is the vehicle's `VehicleIdentity::index`. Keys are thereby "seeded by run and node number" (RSD-SIM-01c).
- **Only provisioning sees node seeds.** Provisioning generates every long-term key pair before the mission and hands each vehicle only its own key pairs and runtime seed, so no agent can compute another node's keys (AS2; RSD-CRY-02a). Agent code also cannot read the run seed: `tools/deps_rules.json` adds `RngSeedManager` to the patterns forbidden in agent code, which today only the harness uses. Where provisioning runs and the format of what it hands over belong to RSD-CRY-02 and TULPAR-481; the harness reaches M-CRY only through the agent root (Section 3).
- **One generator per purpose.** A new purpose therefore cannot shift the output of an existing one. The first purposes are `ml-kem-1024-encaps`, the randomness m of every encapsulation, and `ml-kem-1024-ephemeral`, the fresh key of handshake message HS1. The session work adds its own, such as handshake nonces.
- **Restarts.** The key provider (later work, RSD-CRY-02) persists a start counter s together with the chain head (RSD-CRY-02c) and increments it at every start of the agent, including a restart after a crash (RSD-SAF-03l). The generators get new seeds at every start, so no random draw repeats after a restart. Section 5.6 uses the same counter.
- **Order.** A run executes its events in one deterministic order, so the sequence of draws from each generator is reproducible.

### 5.5 Deterministic ML-DSA-87 signing

In Botan 3.13.0, an ML-DSA signer created with an empty parameter string signs with the hedged, randomized variant; the parameter `"Deterministic"` selects the deterministic one. M-CRY always passes `"Deterministic"` and signs with Botan's `Null_RNG`, which throws if anything draws from it, so the signer cannot use randomness unnoticed. The FIPS 204 context string is empty: Botan 3.13.0 does not yet support a non-empty context, and record types are already kept apart by the domain labels of the encodings (K12). The RSD records why the simulation signs deterministically while a real vehicle would use hedged signing (Section 4.5, design rationale).

### 5.6 AES-256-GCM IV rule (RSD-CRY-01g)

Every IV is 12 bytes, a 4-byte fixed field followed by an 8-byte value, as in V13.2 Section 7.3. The fixed field is use (1 B) ‖ direction (1 B) ‖ the sender's roster position (u16). The direction is 0 for traffic from the handshake initiator and 1 for traffic from the responder, and 0 where there is no handshake.

| Use | Key | Use code | Roster position | 8-byte value | Why no IV repeats under the key |
|---|---|---|---|---|---|
| Hop frame | Hop-session key of one direction | 1 | Frame sender | Overlay header counter | The sender's counter increases with every frame under the key. |
| End-to-end data (TDP) | End-to-end key of one direction | 2 | Source | Flow (1) ‖ sequence (5) ‖ attempt (2) of the TDP header | (flow, sequence, attempt) is unique per session (V13.2 Section 7.3), and every attempt is encrypted again (V13.2 Section 6.2). |
| End-to-end acknowledgment (ARRIVED, ACCEPTED) | End-to-end key of the acknowledging direction | 3 | Acknowledging endpoint | Acknowledgment counter | The counter increases with every acknowledgment under the key. |
| Swarm-key broadcast (telemetry, digests, bundle fragments) | Swarm key of the epoch | 4 | Frame sender | Overlay header counter | Roster positions are unique in a mission (AS3), and each sender's counter increases. |
| Sealed message (bundle for a disconnected destination, record for headquarters) | Key from one ML-KEM-1024 encapsulation | 5 | 0 | 0 | The key encrypts exactly one message (RSD-NET-05e: "a fresh key per bundle"; RSD-HOT-05c: "sealed once"). |

**Counters.**
- `FrameCounter` produces the overlay header counter, which `docs/design/encodings.md` (Section 4.4) defines as "Strictly increasing per sender and key", and the acknowledgment counter. In start s (Section 5.4), a counter for a new key starts at s · 2^48 and increases by one with every encryption; it refuses to encrypt rather than reach (s + 1) · 2^48. A restart therefore never reuses a counter value, not even under a key that survives the restart, such as the swarm key of the current epoch, and no counter is written to storage per frame.
- Hop-session and end-to-end session keys are held only in memory, so a restarted node opens new sessions.
- TDP keeps (flow, sequence, attempt) unique under one end-to-end key and refuses an attempt number above 65 535 or a sequence number above 2^40 − 1 instead of wrapping.
- The acknowledgment frame (ARRIVED, ACCEPTED; V13.2 Table C.3) gains an 8-byte acknowledgment counter, in clear and covered by its end-to-end tag. The architecture defines no IV for this tag, and without a counter two acknowledgments with the same cumulative sequence would repeat an IV. The field belongs to the TDP formats of TULPAR-480 (Cemre Karabulut).

**MACs.** Only AES-256-GCM takes an IV. HMAC-SHA-384 values, such as the HELLO tag (RSD-CRY-03a) and the key confirmations of the handshake, need none. The per-receiver telemetry MACs (V13.2 Table C.3) are taken to be HMAC-SHA-384, since RSD-CRY-01d assigns message authentication to it; a GMAC under a hop key would need a counter value of its own.

**Result.** Every key has one sender, or separates its senders by roster position, and no sender repeats a value under a key. CLM-36 ("No AES-GCM IV repeats under one key") therefore holds by construction.

**Alternative not chosen.** A swarm key per sender, derived with HKDF from the swarm key and the sender's identifier, would need no roster lookup, but it adds a derivation and a key cache to every receiver and departs further from the architecture.

### 5.7 Processing-delay table (RSD-SIM-01b)

- **Program.** `module/bench/tulpar-crypto-bench.cc` is a plain executable that links `tulpar_crypto` and no ns-3 library. It is built on demand; CI neither builds nor runs it. It measures the four operations of RSD-SIM-01b through the interface of Section 5.3:
  - ML-DSA-87 signing and verification;
  - ML-KEM-1024 encapsulation and decapsulation.
- **Method.** Inputs are prepared outside the timed region from a `DeterministicRandom` with a fixed seed. Signing uses 1000 different 84-byte messages, the size of a bundle's signed part (the label and the 69-byte bundle header, encodings Section 4.2): ML-DSA signing repeats its rejection loop a number of times that depends on the message, so one repeated message would time a single loop count. Verification checks those signatures, encapsulation uses 1000 different values of m, and decapsulation opens the resulting ciphertexts. Each operation runs 100 times to warm up and is then timed 1000 times, one operation per measurement, with `std::chrono::steady_clock`. The program is outside `module/agent/`, so its use of the clock does not reach agent code.
- **Report** (`docs/crypto/benchmark.md`): CPU model, core count, operating system and kernel, compiler with version and flags, Botan version and module list, repetition count, date, and the minimum, median, 95th percentile and maximum of each operation. This covers what the inspection of RSD-SIM-01b asks for. The program runs on an otherwise idle machine.
- **Delay table** (`module/agent/cry/crypto-delays.txt`): one line per operation, giving its median in integer nanoseconds, with comment lines starting with `#`:

  ```
  # TULPAR processing-delay table (RSD-SIM-01b); see docs/crypto/benchmark.md
  ml_dsa_87_sign <median ns>
  ml_dsa_87_verify <median ns>
  ml_kem_1024_encaps <median ns>
  ml_kem_1024_decaps <median ns>
  ```

  The values come only from a run of the program; no estimated value is written into the file.
- **Parser.** `ParseCryptoDelayTable` accepts exactly these four operations, each once, with positive integer values, and returns an error for any other input.
- **Loading.** The harness passes the text of the table to M-CRY through the agent root, and the run stops at start-up if the parser rejects it. How the delays are scheduled in simulation time is RSD-SIM-01a (Çağlar Mesci); this design fixes only the file format and the parser.
- **RSD update.** After the first measured run, a pull request of its own (TULPAR-159) replaces the TBR-01 values in Section 4.5, Table 4.30 and Section 6.5. LIM-11 stays.

### 5.8 Failure handling

Functions that take data from the network never abort the simulation. A wrong-size key, signature or ciphertext, or a failed tag, returns false or nothing; M-CRY catches Botan exceptions and turns them into that result. Decapsulating a modified ML-KEM-1024 ciphertext returns the implicit-rejection secret, as FIPS 203 requires, so the failure shows when the tag under the derived key fails. The crypto core returns configuration errors, such as a malformed delay table or a seed of the wrong size, as errors, and the agent module or the harness stops the run at start-up with `NS_FATAL_ERROR`.

## 6. Verification

The checks live in the ns-3 test suite `tulpar-cry` (`module/test/tulpar-cry-test-suite.cc`) and in the static checks, and they run in CI (Section 5.2). Each algorithm is tested against at least one published vector, and the test records the source of each vector next to it. The sources are:
- SHA-384: the FIPS 180-4 examples published by NIST;
- HMAC-SHA-384: RFC 4231;
- HKDF-SHA-384: Project Wycheproof (`hkdf_sha384_test.json`);
- AES-256-GCM: the AES-256 test cases of the GCM specification, or NIST CAVP;
- ML-KEM-1024: NIST ACVP key-generation and encapsulation vectors, and Project Wycheproof's ML-KEM-1024 decapsulation vectors, which give the key pair as a seed and include implicit rejection;
- ML-DSA-87: NIST ACVP key-generation vectors, and Project Wycheproof's ML-DSA-87 vectors for deterministic signing with an empty context and for verification.

An issue closes only when its whole acceptance criterion passes in CI (`CLAUDE.md`). Where this work covers part of a criterion, the issue stays open until the later check exists.

| Requirement | Check | Method | Closes the issue |
|---|---|---|---|
| RSD-CRY-01a | `RSD-CRY-01a ML-KEM-1024 key generation, encapsulation and decapsulation match published vectors` | T | Partly. The handshake test and the suite-identifier check come with the session work and the formats; bundle encapsulation comes with RSD-NET-05e. |
| RSD-CRY-01b | `RSD-CRY-01b ML-DSA-87 signature verifies and fails under a wrong key`, with the ACVP and Wycheproof vectors | T | Partly. "every signed record type" is tested as the record types are implemented. |
| RSD-CRY-01c | `RSD-CRY-01c AES-256-GCM rejects a modified ciphertext or associated datum`, with the GCM vectors | T | Yes |
| RSD-CRY-01d | `RSD-CRY-01d SHA-384, HMAC-SHA-384 and HKDF-SHA-384 match published vectors` | T | Yes |
| RSD-CRY-01e | `RSD-CRY-01e signatures and ciphertexts have their real sizes`; the version `static_assert`; the static check that only M-CRY includes Botan | T, S | Partly. Packet traces with real sizes come with the first frames that carry signatures and ciphertexts. |
| RSD-CRY-01f | `RSD-CRY-01f deterministic ML-DSA-87 signatures are byte-identical` | T | Partly. The criterion says "in simulation runs", so a run-based check follows when agents sign bundles. |
| RSD-CRY-01g | `RSD-CRY-01g no IV repeats under one key`: hop sessions, end-to-end sessions with several attempts of one message, swarm-key broadcasts from several senders, acknowledgments, sealed messages, and a restart | T | Yes |
| RSD-SIM-01b | `RSD-SIM-01b delay table parser accepts the four operations and rejects malformed input`; inspection of `docs/crypto/benchmark.md` | T, I | Partly. "loaded as a simulation parameter" is shown with RSD-SIM-01a. |

Supporting tests without an acceptance criterion of their own check that the derivations of Section 5.4 give the same bytes for the same inputs and different bytes when the run seed, run number, roster index or start changes.

## 7. Ownership of the changes

| Path | Owner | Change | Approval needed |
|---|---|---|---|
| `module/agent/cry/` | Özgür Can Güngör | Crypto core, delay table | None |
| `module/test/tulpar-cry-test-suite.cc` | Özgür Can Güngör | Tests | None |
| `module/bench/` (new) | Özgür Can Güngör | Benchmark program | None |
| `third_party/botan-3.13.0/` (new) | Özgür Can Güngör | Vendored Botan | None |
| `docs/crypto/` (new) | Özgür Can Güngör | Benchmark report | None |
| `tools/deps_rules.json` | Özgür Can Güngör | Part `botan`; targets `tulpar_botan` and `tulpar_crypto`; the agent-code pattern `RngSeedManager` | None |
| `CLAUDE.md`, `.github/CODEOWNERS` | Özgür Can Güngör | Rows for the new folders | None |
| `module/CMakeLists.txt` | Çağlar Mesci (shared) | The two new targets, the test source and its link, the benchmark program | Çağlar Mesci, or Özgür Can Güngör after two days |
| `.github/workflows/ci.yml` | Çağlar Mesci (shared) | A step that runs the `tulpar-cry` suite | Çağlar Mesci, or Özgür Can Güngör after two days |
| `module/agent/root/`, `module/sim/` | Çağlar Mesci | Passing the delay table to M-CRY, with RSD-SIM-01a | Çağlar Mesci |

## 8. Departures from the architecture

The RSD is silent on how IVs are built, so these departures from V13.2 Section 7.3 are recorded here and are not RSD changes (`CLAUDE.md`).

| No | Architecture | This design | Reason |
|---|---|---|---|
| A1 | Swarm-key IVs use "the 4-byte sender identifier" and an 8-byte counter. | The 4 bytes hold the use, the direction and the sender's 2-byte roster position. | The sender identifier on the air has 8 bytes (Table C.3) and does not fit. Roster positions are unique and fixed by the signed roster (AS3; encodings K10). This resolves the inconsistency recorded in `docs/design/encodings.md`, Section 9. |
| A2 | Hop IVs use "a 4-byte fixed field (node and direction)". | The node is the roster position, and a use code is added. | One layout for every use; the use code keeps the IVs of different uses apart even if a key were ever used for two of them by mistake. |
| A3 | Three ways of building an IV. | Two more: end-to-end acknowledgments and sealed messages. | The acknowledgment frame carries an end-to-end tag (Table C.3), and RSD-NET-05e and RSD-HOT-05c add AES-256-GCM under one-time keys. |
| A4 | Nothing on restarts. | Counters start at s · 2^48 in start s, and the generators get new seeds at every start. | After a restart, neither an IV under a key that survives it, such as the swarm key, nor a random draw may repeat. |

## 9. Delivery

1. **This design** (TULPAR-57).
2. **Vendored Botan, the build targets, the interface and the tests for RSD-CRY-01a to RSD-CRY-01f** (TULPAR-280 to TULPAR-285), with the changes to `module/CMakeLists.txt`, the CI workflow and `tools/deps_rules.json`.
3. **The IV rule and its tests** (TULPAR-286), after Section 5.6 is approved.
4. **The benchmark program, the parser, the first measured report and the delay table** (TULPAR-463). Özgür Can Güngör runs the program on the development machine.
5. **The RSD update that replaces the TBR-01 values** (TULPAR-159), as its own pull request.

## 10. Left to the implementer

- Botan class names, and configure flags beyond the module list (target CPU, operating system and compiler).
- The file layout inside `module/agent/cry/`, and the CMake details of linking the test library.
- The error type of the crypto core, for example `std::expected`.
- The choice of at least one vector per algorithm from the sources in Section 6.
- Whether the benchmark program prints the report or writes it to a file.
