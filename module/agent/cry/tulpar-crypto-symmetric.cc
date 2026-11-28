/*
 * Copyright (c) 2026 TULPAR project team
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "botan_all.h"
#include "tulpar-crypto.h"

#include <string>

static_assert(BOTAN_VERSION_MAJOR == 3 && BOTAN_VERSION_MINOR == 13 && BOTAN_VERSION_PATCH == 0,
              "RSD-CRY-01e requires Botan 3.13.0");

namespace ns3
{
namespace tulpar
{
namespace crypto
{

namespace
{

/// SHA-384 block size in bytes; HMAC hashes longer keys first (RFC 2104).
constexpr std::size_t kSha384BlockSize = 128;

/**
 * Run AES-256-GCM in one direction.
 *
 * @param direction encryption or decryption
 * @param key the key
 * @param iv the IV
 * @param aad associated data
 * @param input plaintext, or ciphertext followed by the tag
 * @return the output, or nothing on a wrong length or a failed tag
 */
std::optional<Bytes>
RunAes256Gcm(Botan::Cipher_Dir direction, ByteView key, ByteView iv, ByteView aad, ByteView input)
{
    if (key.size() != kAesGcmKeySize || iv.size() != kAesGcmIvSize)
    {
        return std::nullopt;
    }
    if (direction == Botan::Cipher_Dir::Decryption && input.size() < kAesGcmTagSize)
    {
        return std::nullopt;
    }
    try
    {
        auto mode = Botan::AEAD_Mode::create_or_throw("AES-256/GCM", direction);
        mode->set_key(key);
        mode->set_associated_data(aad);
        mode->start(iv);
        Botan::secure_vector<std::uint8_t> buffer(input.begin(), input.end());
        mode->finish(buffer);
        return Bytes(buffer.begin(), buffer.end());
    }
    catch (const std::exception&)
    {
        // Botan::Invalid_Authentication_Tag for a failed tag; nothing else is expected.
        return std::nullopt;
    }
}

} // namespace

std::string
LinkedBotanVersion()
{
    return std::to_string(Botan::version_major()) + "." + std::to_string(Botan::version_minor()) +
           "." + std::to_string(Botan::version_patch());
}

Bytes
Sha384(ByteView data)
{
    auto hash = Botan::HashFunction::create_or_throw("SHA-384");
    hash->update(data);
    return hash->final_stdvec();
}

Bytes
HmacSha384(ByteView key, ByteView data)
{
    auto mac = Botan::MessageAuthenticationCode::create_or_throw("HMAC(SHA-384)");
    // Hashing a long key here gives the same tag (RFC 2104) and keeps every key length within
    // the 8192 bytes that Botan's HMAC accepts.
    if (key.size() > kSha384BlockSize)
    {
        mac->set_key(Sha384(key));
    }
    else
    {
        mac->set_key(key);
    }
    mac->update(data);
    return mac->final_stdvec();
}

bool
HmacSha384Verify(ByteView key, ByteView data, ByteView tag)
{
    if (tag.size() < kHmacMinTagSize || tag.size() > kSha384Size)
    {
        return false;
    }
    const auto full = HmacSha384(key, data);
    return Botan::constant_time_compare(ByteView(full).first(tag.size()), tag);
}

std::optional<Bytes>
HkdfSha384(ByteView ikm, ByteView salt, ByteView info, std::size_t length)
{
    if (length > 255 * kSha384Size)
    {
        return std::nullopt;
    }
    auto kdf = Botan::KDF::create_or_throw("HKDF(SHA-384)");
    return kdf->derive_key<Bytes>(length, ikm, salt, info);
}

std::optional<Bytes>
Aes256GcmSeal(ByteView key, ByteView iv, ByteView aad, ByteView plaintext)
{
    return RunAes256Gcm(Botan::Cipher_Dir::Encryption, key, iv, aad, plaintext);
}

std::optional<Bytes>
Aes256GcmOpen(ByteView key, ByteView iv, ByteView aad, ByteView sealed)
{
    return RunAes256Gcm(Botan::Cipher_Dir::Decryption, key, iv, aad, sealed);
}

} // namespace crypto
} // namespace tulpar
} // namespace ns3
