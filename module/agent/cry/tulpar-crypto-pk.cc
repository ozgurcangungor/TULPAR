/*
 * Copyright (c) 2026 TULPAR project team
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "botan_all.h"
#include "tulpar-crypto.h"

#include <algorithm>
#include <exception>
#include <string>
#include <utility>

namespace ns3
{
namespace tulpar
{
namespace crypto
{

namespace
{

/**
 * Generator that hands Botan exactly the bytes it was given, in order, so that an explicit
 * random input of the interface reaches the algorithm unchanged. Asking for more throws.
 */
class FixedBytesRng final : public Botan::RandomNumberGenerator
{
  public:
    /**
     * Constructor.
     *
     * @param bytes the bytes to hand out; they must outlive the generator
     */
    explicit FixedBytesRng(ByteView bytes)
        : m_bytes(bytes)
    {
    }

    bool is_seeded() const override
    {
        return true;
    }

    bool accepts_input() const override
    {
        return false;
    }

    void clear() override
    {
    }

    std::string name() const override
    {
        return "FixedBytesRng";
    }

    /**
     * Whether every byte has been handed out.
     *
     * @return true if Botan drew exactly the bytes given
     */
    bool Consumed() const
    {
        return m_used == m_bytes.size();
    }

  private:
    void fill_bytes_with_input(std::span<std::uint8_t> output,
                               std::span<const std::uint8_t> /* input */) override
    {
        if (output.size() > m_bytes.size() - m_used)
        {
            throw Botan::Invalid_State("FixedBytesRng: more bytes requested than given");
        }
        std::copy_n(m_bytes.begin() + m_used, output.size(), output.begin());
        m_used += output.size();
    }

    ByteView m_bytes;      ///< the bytes to hand out
    std::size_t m_used{0}; ///< number of bytes handed out
};

/**
 * The ML-KEM parameter set of the suite.
 *
 * @return ML-KEM-1024
 */
Botan::ML_KEM_Mode
MlKem1024Mode()
{
    return Botan::ML_KEM_Mode(Botan::ML_KEM_Mode::ML_KEM_1024);
}

/**
 * The ML-DSA parameter set of the suite.
 *
 * @return ML-DSA-87, which Botan names 8x7 after its matrix dimensions
 */
Botan::ML_DSA_Mode
MlDsa87Mode()
{
    return Botan::ML_DSA_Mode(Botan::ML_DSA_Mode::ML_DSA_8x7);
}

} // namespace

/// Botan key behind an MlKem1024KeyPair.
struct MlKem1024KeyPair::Impl
{
    std::unique_ptr<Botan::ML_KEM_PrivateKey> key; ///< private key with its public half
};

MlKem1024KeyPair::MlKem1024KeyPair(std::unique_ptr<Impl> impl)
    : m_impl(std::move(impl))
{
}

MlKem1024KeyPair::~MlKem1024KeyPair() = default;

MlKem1024KeyPair::MlKem1024KeyPair(MlKem1024KeyPair&& other) noexcept = default;

MlKem1024KeyPair& MlKem1024KeyPair::operator=(MlKem1024KeyPair&& other) noexcept = default;

std::optional<MlKem1024KeyPair>
MlKem1024KeyPair::FromSeed(ByteView dz)
{
    if (dz.size() != kMlKemSeedSize)
    {
        return std::nullopt;
    }
    try
    {
        // Botan draws d, then z: exactly the 64 bytes of the seed.
        FixedBytesRng rng(dz);
        auto impl = std::make_unique<Impl>();
        impl->key = std::make_unique<Botan::ML_KEM_PrivateKey>(rng, MlKem1024Mode());
        if (!rng.Consumed())
        {
            return std::nullopt;
        }
        return MlKem1024KeyPair(std::move(impl));
    }
    catch (const std::exception&)
    {
        return std::nullopt;
    }
}

Bytes
MlKem1024KeyPair::EncapsulationKey() const
{
    return m_impl->key->public_key_bits();
}

std::optional<Bytes>
MlKem1024KeyPair::Decapsulate(ByteView ciphertext) const
{
    if (ciphertext.size() != kMlKemCiphertextSize)
    {
        return std::nullopt;
    }
    try
    {
        Botan::Null_RNG noRandomness;
        Botan::PK_KEM_Decryptor decryptor(*m_impl->key, noRandomness, "Raw");
        const auto secret = decryptor.decrypt(ciphertext);
        return Bytes(secret.begin(), secret.end());
    }
    catch (const std::exception&)
    {
        return std::nullopt;
    }
}

std::optional<MlKem1024Encapsulation>
MlKem1024Encapsulate(ByteView encapsulationKey, ByteView m)
{
    if (encapsulationKey.size() != kMlKemEncapsulationKeySize || m.size() != kMlKemRandomnessSize)
    {
        return std::nullopt;
    }
    try
    {
        // Decoding the key applies the modulus check of FIPS 203 and throws if it fails.
        const Botan::ML_KEM_PublicKey key(encapsulationKey, MlKem1024Mode());
        Botan::PK_KEM_Encryptor encryptor(key, "Raw");
        FixedBytesRng rng(m);
        const auto result = encryptor.encrypt(rng);
        if (!rng.Consumed())
        {
            return std::nullopt;
        }
        const auto ciphertext = result.encapsulated_shared_key();
        const auto secret = result.shared_key();
        return MlKem1024Encapsulation{Bytes(ciphertext.begin(), ciphertext.end()),
                                      Bytes(secret.begin(), secret.end())};
    }
    catch (const std::exception&)
    {
        return std::nullopt;
    }
}

/// Botan key behind an MlDsa87KeyPair.
struct MlDsa87KeyPair::Impl
{
    std::unique_ptr<Botan::ML_DSA_PrivateKey> key; ///< private key with its public half
};

MlDsa87KeyPair::MlDsa87KeyPair(std::unique_ptr<Impl> impl)
    : m_impl(std::move(impl))
{
}

MlDsa87KeyPair::~MlDsa87KeyPair() = default;

MlDsa87KeyPair::MlDsa87KeyPair(MlDsa87KeyPair&& other) noexcept = default;

MlDsa87KeyPair& MlDsa87KeyPair::operator=(MlDsa87KeyPair&& other) noexcept = default;

std::optional<MlDsa87KeyPair>
MlDsa87KeyPair::FromSeed(ByteView xi)
{
    if (xi.size() != kMlDsaSeedSize)
    {
        return std::nullopt;
    }
    try
    {
        // Botan draws exactly the 32-byte seed xi.
        FixedBytesRng rng(xi);
        auto impl = std::make_unique<Impl>();
        impl->key = std::make_unique<Botan::ML_DSA_PrivateKey>(rng, MlDsa87Mode());
        if (!rng.Consumed())
        {
            return std::nullopt;
        }
        return MlDsa87KeyPair(std::move(impl));
    }
    catch (const std::exception&)
    {
        return std::nullopt;
    }
}

Bytes
MlDsa87KeyPair::PublicKey() const
{
    return m_impl->key->public_key_bits();
}

Bytes
MlDsa87KeyPair::Sign(ByteView message) const
{
    // "Deterministic" selects the all-zero randomizer of FIPS 204; Null_RNG throws if anything
    // draws from it, so the signer cannot use randomness unnoticed.
    Botan::Null_RNG noRandomness;
    Botan::PK_Signer signer(*m_impl->key, noRandomness, "Deterministic");
    return signer.sign_message(message, noRandomness);
}

bool
MlDsa87Verify(ByteView publicKey, ByteView message, ByteView signature)
{
    if (publicKey.size() != kMlDsaPublicKeySize || signature.size() != kMlDsaSignatureSize)
    {
        return false;
    }
    try
    {
        const Botan::ML_DSA_PublicKey key(publicKey, MlDsa87Mode());
        Botan::PK_Verifier verifier(key, "");
        return verifier.verify_message(message, signature);
    }
    catch (const std::exception&)
    {
        return false;
    }
}

} // namespace crypto
} // namespace tulpar
} // namespace ns3
