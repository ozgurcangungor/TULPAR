/*
 * Copyright (c) 2026 TULPAR project team
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef TULPAR_CRYPTO_H
#define TULPAR_CRYPTO_H

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace ns3
{
namespace tulpar
{
/**
 * @ingroup tulpar
 * Crypto core of M-CRY (RSD-CRY-01; docs/design/crypto.md). Every operation runs the real
 * algorithm through Botan 3.13.0, which no declaration here exposes. Functions that take data
 * from the network return nothing or false on bad input and never throw.
 */
namespace crypto
{

/// Byte string.
using Bytes = std::vector<std::uint8_t>;

/// Read-only view of a byte string.
using ByteView = std::span<const std::uint8_t>;

constexpr std::size_t kSha384Size = 48;     ///< SHA-384 digest and HMAC-SHA-384 tag (Table 2.1)
constexpr std::size_t kAesGcmKeySize = 32;  ///< AES-256-GCM key (Table 2.1)
constexpr std::size_t kAesGcmIvSize = 12;   ///< AES-256-GCM IV of 96 bits (Table 2.1)
constexpr std::size_t kAesGcmTagSize = 16;  ///< AES-256-GCM tag (Table 2.1)
constexpr std::size_t kHmacMinTagSize = 8;  ///< shortest accepted truncated HMAC tag
constexpr std::size_t kRandomSeedSize = 48; ///< seed of a DeterministicRandom
constexpr std::size_t kMlKemSeedSize = 64;  ///< ML-KEM-1024 key seed d || z (FIPS 203)
constexpr std::size_t kMlKemRandomnessSize = 32;         ///< ML-KEM-1024 encapsulation randomness m
constexpr std::size_t kMlKemEncapsulationKeySize = 1568; ///< ML-KEM-1024 encapsulation key
constexpr std::size_t kMlKemCiphertextSize = 1568;       ///< ML-KEM-1024 ciphertext
constexpr std::size_t kMlKemSharedSecretSize = 32;       ///< ML-KEM-1024 shared secret
constexpr std::size_t kMlDsaSeedSize = 32;               ///< ML-DSA-87 key seed xi (FIPS 204)
constexpr std::size_t kMlDsaPublicKeySize = 2592;        ///< ML-DSA-87 public key
constexpr std::size_t kMlDsaSignatureSize = 4627;        ///< ML-DSA-87 signature

/**
 * Version of the Botan library that this core is linked against (RSD-CRY-01e).
 *
 * @return the version as "major.minor.patch", read from the linked library at run time
 */
std::string LinkedBotanVersion();

} // namespace crypto
} // namespace tulpar
} // namespace ns3

#endif // TULPAR_CRYPTO_H
