/*
 * Copyright (c) 2026 TULPAR project team
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef TULPAR_CRYPTO_H
#define TULPAR_CRYPTO_H

#include <cstddef>
#include <cstdint>
#include <memory>
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

/**
 * The seeded generator behind every random input of M-CRY (docs/design/crypto.md, Section 5.4):
 * Botan's HMAC_DRBG over HMAC-SHA-384, built without an underlying generator, so it never
 * reseeds from the operating system and its output depends only on its seed. Move-only.
 */
class DeterministicRandom
{
  public:
    /**
     * Create a generator.
     *
     * @param seed the 48-byte seed
     * @return the generator, or nothing for a seed of another length
     */
    static std::optional<DeterministicRandom> FromSeed(ByteView seed);

    /// Destructor.
    ~DeterministicRandom();

    /**
     * Move constructor.
     *
     * @param other the generator to take over
     */
    DeterministicRandom(DeterministicRandom&& other) noexcept;

    /**
     * Move assignment.
     *
     * @param other the generator to take over
     * @return this generator
     */
    DeterministicRandom& operator=(DeterministicRandom&& other) noexcept;

    DeterministicRandom(const DeterministicRandom&) = delete;
    DeterministicRandom& operator=(const DeterministicRandom&) = delete;

    /**
     * Draw the next bytes of the generator's output.
     *
     * @param n number of bytes; 0 returns nothing and leaves the generator unchanged
     * @return n bytes
     */
    Bytes Draw(std::size_t n);

  private:
    struct Impl;

    /**
     * Constructor.
     *
     * @param impl the seeded Botan generator
     */
    explicit DeterministicRandom(std::unique_ptr<Impl> impl);

    std::unique_ptr<Impl> m_impl; ///< Botan generator, kept out of this header
};

/**
 * ML-KEM-1024 key pair (FIPS 203; RSD-CRY-01a). It is built from its seed, and no function
 * returns its private key (RSD-CRY-02a). Move-only.
 */
class MlKem1024KeyPair
{
  public:
    /**
     * Build the key pair of a seed (ML-KEM.KeyGen_internal of FIPS 203).
     *
     * @param dz the 64-byte seed d || z
     * @return the key pair, or nothing for a seed of another length
     */
    static std::optional<MlKem1024KeyPair> FromSeed(ByteView dz);

    /// Destructor.
    ~MlKem1024KeyPair();

    /**
     * Move constructor.
     *
     * @param other the key pair to take over
     */
    MlKem1024KeyPair(MlKem1024KeyPair&& other) noexcept;

    /**
     * Move assignment.
     *
     * @param other the key pair to take over
     * @return this key pair
     */
    MlKem1024KeyPair& operator=(MlKem1024KeyPair&& other) noexcept;

    MlKem1024KeyPair(const MlKem1024KeyPair&) = delete;
    MlKem1024KeyPair& operator=(const MlKem1024KeyPair&) = delete;

    /**
     * The public half of the key pair.
     *
     * @return the 1568-byte encapsulation key
     */
    Bytes EncapsulationKey() const;

    /**
     * Decapsulate a ciphertext. A modified ciphertext gives the implicit-rejection secret of
     * FIPS 203, not an error: the failure shows when the tag under the derived key fails.
     *
     * @param ciphertext the 1568-byte ciphertext
     * @return the 32-byte shared secret, or nothing for a ciphertext of another length
     */
    std::optional<Bytes> Decapsulate(ByteView ciphertext) const;

  private:
    struct Impl;

    /**
     * Constructor.
     *
     * @param impl the Botan key
     */
    explicit MlKem1024KeyPair(std::unique_ptr<Impl> impl);

    std::unique_ptr<Impl> m_impl; ///< Botan key, kept out of this header
};

/// Result of an ML-KEM-1024 encapsulation.
struct MlKem1024Encapsulation
{
    Bytes ciphertext;   ///< 1568 bytes, for the owner of the encapsulation key
    Bytes sharedSecret; ///< 32 bytes
};

/**
 * Encapsulate a shared secret to an encapsulation key (ML-KEM.Encaps_internal of FIPS 203).
 *
 * @param encapsulationKey the 1568-byte encapsulation key
 * @param m the 32-byte randomness, drawn by the caller from a DeterministicRandom
 * @return the ciphertext and the shared secret, or nothing for a wrong length or for a key that
 *         fails the modulus check of FIPS 203
 */
std::optional<MlKem1024Encapsulation> MlKem1024Encapsulate(ByteView encapsulationKey, ByteView m);

/**
 * ML-DSA-87 key pair (FIPS 204; RSD-CRY-01b). It signs deterministically with the empty context
 * (RSD-CRY-01f), is built from its seed, and no function returns its private key
 * (RSD-CRY-02a). Move-only.
 */
class MlDsa87KeyPair
{
  public:
    /**
     * Build the key pair of a seed (ML-DSA.KeyGen_internal of FIPS 204).
     *
     * @param xi the 32-byte seed
     * @return the key pair, or nothing for a seed of another length
     */
    static std::optional<MlDsa87KeyPair> FromSeed(ByteView xi);

    /// Destructor.
    ~MlDsa87KeyPair();

    /**
     * Move constructor.
     *
     * @param other the key pair to take over
     */
    MlDsa87KeyPair(MlDsa87KeyPair&& other) noexcept;

    /**
     * Move assignment.
     *
     * @param other the key pair to take over
     * @return this key pair
     */
    MlDsa87KeyPair& operator=(MlDsa87KeyPair&& other) noexcept;

    MlDsa87KeyPair(const MlDsa87KeyPair&) = delete;
    MlDsa87KeyPair& operator=(const MlDsa87KeyPair&) = delete;

    /**
     * The public half of the key pair.
     *
     * @return the 2592-byte public key
     */
    Bytes PublicKey() const;

    /**
     * Sign a message deterministically with the empty context (RSD-CRY-01f). The simulation
     * signs deterministically so that runs are reproducible; a real vehicle would use hedged
     * signing (RSD Section 4.5).
     *
     * @param message the message
     * @return the 4627-byte signature
     */
    Bytes Sign(ByteView message) const;

  private:
    struct Impl;

    /**
     * Constructor.
     *
     * @param impl the Botan key
     */
    explicit MlDsa87KeyPair(std::unique_ptr<Impl> impl);

    std::unique_ptr<Impl> m_impl; ///< Botan key, kept out of this header
};

/**
 * Verify an ML-DSA-87 signature made with the empty context (RSD-CRY-01b).
 *
 * @param publicKey the 2592-byte public key
 * @param message the message
 * @param signature the 4627-byte signature
 * @return true if the signature is valid; false otherwise, including for an input of the wrong
 *         length
 */
bool MlDsa87Verify(ByteView publicKey, ByteView message, ByteView signature);

} // namespace crypto
} // namespace tulpar
} // namespace ns3

#endif // TULPAR_CRYPTO_H
