/*
 * Copyright (c) 2026 TULPAR project team
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef TULPAR_CRYPTO_H
#define TULPAR_CRYPTO_H

#include <cstddef>
#include <cstdint>
#include <optional>
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

/**
 * SHA-384 digest (RSD-CRY-01d).
 *
 * @param data the message
 * @return the 48-byte digest
 */
Bytes Sha384(ByteView data);

/**
 * HMAC-SHA-384 tag (RFC 2104; RSD-CRY-01d).
 *
 * @param key the key, of any length
 * @param data the message
 * @return the 48-byte tag
 */
Bytes HmacSha384(ByteView key, ByteView data);

/**
 * Check a full or truncated HMAC-SHA-384 tag in constant time (RSD-CRY-01d). HELLO carries
 * 16 bytes of the tag (Table 4.26) and each per-receiver telemetry MAC 8 bytes (Table 4.29).
 *
 * @param key the key
 * @param data the message
 * @param tag the received tag, 8 to 48 bytes
 * @return true if the tag equals the first tag.size() bytes of the HMAC; false otherwise,
 *         including for a tag of another length
 */
bool HmacSha384Verify(ByteView key, ByteView data, ByteView tag);

/**
 * HKDF-SHA-384 key derivation (RFC 5869; RSD-CRY-01d).
 *
 * @param ikm input key material
 * @param salt salt, may be empty
 * @param info context label, may be empty
 * @param length number of bytes to derive, at most 255 * 48
 * @return the derived bytes, or nothing if the length is too large
 */
std::optional<Bytes> HkdfSha384(ByteView ikm, ByteView salt, ByteView info, std::size_t length);

/**
 * Encrypt and authenticate with AES-256-GCM (RSD-CRY-01c). The caller builds the IV by the IV
 * rule of RSD-CRY-01g; this function checks only its length.
 *
 * @param key the 32-byte key
 * @param iv the 12-byte IV
 * @param aad associated data, authenticated but not encrypted
 * @param plaintext the message
 * @return the ciphertext followed by the 16-byte tag, or nothing for a key or IV of another
 *         length
 */
std::optional<Bytes> Aes256GcmSeal(ByteView key, ByteView iv, ByteView aad, ByteView plaintext);

/**
 * Check and decrypt AES-256-GCM output (RSD-CRY-01c).
 *
 * @param key the 32-byte key
 * @param iv the 12-byte IV
 * @param aad associated data
 * @param sealed the ciphertext followed by the 16-byte tag
 * @return the plaintext, or nothing if the tag fails or a length is wrong
 */
std::optional<Bytes> Aes256GcmOpen(ByteView key, ByteView iv, ByteView aad, ByteView sealed);

} // namespace crypto
} // namespace tulpar
} // namespace ns3

#endif // TULPAR_CRYPTO_H
