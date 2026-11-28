/*
 * Copyright (c) 2026 TULPAR project team
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "tulpar-cry-test-vectors.h"
#include "tulpar-crypto.h"

#include "ns3/test.h"

#include <cstdint>
#include <string>
#include <string_view>

using namespace ns3;
using namespace ns3::tulpar;

namespace
{

/**
 * Decode hexadecimal digits.
 *
 * @param hex an even number of hexadecimal digits, in either case
 * @return the bytes
 */
crypto::Bytes
FromHex(std::string_view hex)
{
    auto nibble = [](char c) -> std::uint8_t {
        if (c >= '0' && c <= '9')
        {
            return static_cast<std::uint8_t>(c - '0');
        }
        if (c >= 'a' && c <= 'f')
        {
            return static_cast<std::uint8_t>(c - 'a' + 10);
        }
        return static_cast<std::uint8_t>(c - 'A' + 10);
    };
    crypto::Bytes out;
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2)
    {
        out.push_back(static_cast<std::uint8_t>((nibble(hex[i]) << 4) | nibble(hex[i + 1])));
    }
    return out;
}

/**
 * The bytes of an ASCII text.
 *
 * @param text the text
 * @return its bytes, without a terminating zero
 */
crypto::Bytes
FromText(std::string_view text)
{
    return crypto::Bytes(text.begin(), text.end());
}

} // namespace

/**
 * @ingroup tulpar-tests
 * RSD-CRY-01e: the crypto core is linked against Botan 3.13.0, checked at run time against the
 * library that was actually linked, not only against its header.
 */
class TulparCryLinkedVersionTestCase : public TestCase
{
  public:
    TulparCryLinkedVersionTestCase()
        : TestCase("RSD-CRY-01e Botan 3.13.0 is linked into the crypto core")
    {
    }

  private:
    void DoRun() override
    {
        NS_TEST_ASSERT_MSG_EQ(crypto::LinkedBotanVersion(),
                              std::string("3.13.0"),
                              "linked Botan version");
    }
};

/**
 * @ingroup tulpar-tests
 * RSD-CRY-01d: SHA-384 against the FIPS 180-4 examples, HMAC-SHA-384 against RFC 4231 and
 * HKDF-SHA-384 against Project Wycheproof.
 */
class TulparCryHashMacKdfTestCase : public TestCase
{
  public:
    TulparCryHashMacKdfTestCase()
        : TestCase("RSD-CRY-01d SHA-384, HMAC-SHA-384 and HKDF-SHA-384 match published vectors")
    {
    }

  private:
    void DoRun() override
    {
        NS_TEST_EXPECT_MSG_EQ(crypto::Sha384(FromText("abc")) ==
                                  FromHex("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded163"
                                          "1a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"),
                              true,
                              "SHA-384 of \"abc\" (FIPS 180-4 example)");
        NS_TEST_EXPECT_MSG_EQ(
            crypto::Sha384(FromText("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
                                    "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")) ==
                FromHex("09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712"
                        "fcc7c71a557e2db966c3e9fa91746039"),
            true,
            "SHA-384 of the two-block message (FIPS 180-4 example)");
        NS_TEST_EXPECT_MSG_EQ(crypto::Sha384({}) ==
                                  FromHex("38b060a751ac96384cd9327eb1b1e36a21fdb71114be0743"
                                          "4c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"),
                              true,
                              "SHA-384 of the empty message");

        NS_TEST_EXPECT_MSG_EQ(crypto::HmacSha384(crypto::Bytes(20, 0x0b), FromText("Hi There")) ==
                                  FromHex("afd03944d84895626b0825f4ab46907f15f9dadbe4101ec6"
                                          "82aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6"),
                              true,
                              "HMAC-SHA-384, RFC 4231 test case 1");
        NS_TEST_EXPECT_MSG_EQ(
            crypto::HmacSha384(FromText("Jefe"), FromText("what do ya want for nothing?")) ==
                FromHex("af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e"
                        "8e2240ca5e69e2c78b3239ecfab21649"),
            true,
            "HMAC-SHA-384, RFC 4231 test case 2");
        const auto longKeyData = FromText("Test Using Larger Than Block-Size Key - Hash Key First");
        NS_TEST_EXPECT_MSG_EQ(crypto::HmacSha384(crypto::Bytes(131, 0xaa), longKeyData) ==
                                  FromHex("4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f"
                                          "3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952"),
                              true,
                              "HMAC-SHA-384, RFC 4231 test case 6 (key longer than a block)");
        // Expected value from Python's hmac module; Botan alone refuses keys over 8192 bytes.
        NS_TEST_EXPECT_MSG_EQ(crypto::HmacSha384(crypto::Bytes(10000, 0xaa), longKeyData) ==
                                  FromHex("afeb4a2b30470793f9b183ce248349b824b35139d1461bb5"
                                          "3c18cffc4e3ea9b2a591ada0d3f1d6928b6adaf0f0f4b27d"),
                              true,
                              "HMAC-SHA-384 with a 10000-byte key");

        const auto key5 = crypto::Bytes(20, 0x0c);
        const auto data5 = FromText("Test With Truncation");
        auto tag5 = FromHex("3abf34c3503b2a23a46efc619baef897");
        NS_TEST_EXPECT_MSG_EQ(crypto::HmacSha384Verify(key5, data5, tag5),
                              true,
                              "16-byte tag of RFC 4231 test case 5 verifies");
        NS_TEST_EXPECT_MSG_EQ(
            crypto::HmacSha384Verify(key5, data5, crypto::ByteView(tag5).first(7)),
            false,
            "a tag shorter than 8 bytes is rejected");
        auto longTag = crypto::HmacSha384(key5, data5);
        longTag.push_back(0);
        NS_TEST_EXPECT_MSG_EQ(crypto::HmacSha384Verify(key5, data5, longTag),
                              false,
                              "a tag longer than 48 bytes is rejected");
        tag5.back() ^= 0x01;
        NS_TEST_EXPECT_MSG_EQ(crypto::HmacSha384Verify(key5, data5, tag5),
                              false,
                              "a modified tag is rejected");

        const auto okm = crypto::HkdfSha384(FromHex(vectors::kWpHkdfIkm),
                                            FromHex(vectors::kWpHkdfSalt),
                                            FromHex(vectors::kWpHkdfInfo),
                                            48);
        NS_TEST_ASSERT_MSG_EQ(okm.has_value(), true, "HKDF-SHA-384 derives 48 bytes");
        NS_TEST_EXPECT_MSG_EQ(*okm == FromHex(vectors::kWpHkdfOkm),
                              true,
                              "HKDF-SHA-384, Wycheproof tcId 70");
        NS_TEST_EXPECT_MSG_EQ(
            crypto::HkdfSha384(FromHex(vectors::kWpHkdfIkm), {}, {}, 255 * crypto::kSha384Size + 1)
                .has_value(),
            false,
            "HKDF-SHA-384 refuses more than 255 hash lengths");
    }
};

/**
 * @ingroup tulpar-tests
 * RSD-CRY-01c: AES-256-GCM against Test Case 16 of the GCM specification (McGrew and Viega), and
 * rejection of every modified input.
 */
class TulparCryAesGcmTestCase : public TestCase
{
  public:
    TulparCryAesGcmTestCase()
        : TestCase("RSD-CRY-01c AES-256-GCM rejects a modified ciphertext or associated datum")
    {
    }

  private:
    void DoRun() override
    {
        const auto key =
            FromHex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        const auto iv = FromHex("cafebabefacedbaddecaf888");
        const auto aad = FromHex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        const auto plaintext =
            FromHex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                    "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
        const auto ciphertextAndTag =
            FromHex("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
                    "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662"
                    "76fc6ece0f4e1768cddf8853bb2d551b");

        const auto sealed = crypto::Aes256GcmSeal(key, iv, aad, plaintext);
        NS_TEST_ASSERT_MSG_EQ(sealed.has_value(), true, "sealing Test Case 16");
        NS_TEST_EXPECT_MSG_EQ(*sealed == ciphertextAndTag,
                              true,
                              "ciphertext and tag of Test Case 16");
        const auto opened = crypto::Aes256GcmOpen(key, iv, aad, *sealed);
        NS_TEST_ASSERT_MSG_EQ(opened.has_value(), true, "opening Test Case 16");
        NS_TEST_EXPECT_MSG_EQ(*opened == plaintext, true, "plaintext of Test Case 16");

        auto badCiphertext = *sealed;
        badCiphertext.front() ^= 0x01;
        NS_TEST_EXPECT_MSG_EQ(crypto::Aes256GcmOpen(key, iv, aad, badCiphertext).has_value(),
                              false,
                              "a modified ciphertext fails");
        auto badAad = aad;
        badAad.back() ^= 0x01;
        NS_TEST_EXPECT_MSG_EQ(crypto::Aes256GcmOpen(key, iv, badAad, *sealed).has_value(),
                              false,
                              "a modified associated datum fails");
        auto badTag = *sealed;
        badTag.back() ^= 0x01;
        NS_TEST_EXPECT_MSG_EQ(crypto::Aes256GcmOpen(key, iv, aad, badTag).has_value(),
                              false,
                              "a modified tag fails");

        const auto shortKey = crypto::ByteView(key).first(31);
        NS_TEST_EXPECT_MSG_EQ(crypto::Aes256GcmSeal(shortKey, iv, aad, plaintext).has_value(),
                              false,
                              "a 31-byte key is refused for sealing");
        NS_TEST_EXPECT_MSG_EQ(crypto::Aes256GcmOpen(shortKey, iv, aad, *sealed).has_value(),
                              false,
                              "a 31-byte key is refused for opening");
        NS_TEST_EXPECT_MSG_EQ(
            crypto::Aes256GcmSeal(key, crypto::Bytes(16, 0), aad, plaintext).has_value(),
            false,
            "a 16-byte IV is refused");
        NS_TEST_EXPECT_MSG_EQ(
            crypto::Aes256GcmOpen(key, iv, aad, crypto::ByteView(*sealed).first(15)).has_value(),
            false,
            "input shorter than a tag is refused");

        const auto tagOnly = crypto::Aes256GcmSeal(key, iv, {}, {});
        NS_TEST_ASSERT_MSG_EQ(tagOnly.has_value(), true, "sealing the empty message");
        NS_TEST_EXPECT_MSG_EQ(tagOnly->size(), crypto::kAesGcmTagSize, "empty message gives a tag");
        const auto empty = crypto::Aes256GcmOpen(key, iv, {}, *tagOnly);
        NS_TEST_ASSERT_MSG_EQ(empty.has_value(), true, "opening the empty message");
        NS_TEST_EXPECT_MSG_EQ(empty->empty(), true, "the empty message opens to empty");
    }
};

/**
 * @ingroup tulpar-tests
 * The seeded generator of docs/design/crypto.md, Section 5.4: HMAC_DRBG over HMAC-SHA-384 whose
 * output depends only on its seed. Supporting test, no acceptance criterion of its own.
 */
class TulparCryDeterministicRandomTestCase : public TestCase
{
  public:
    TulparCryDeterministicRandomTestCase()
        : TestCase("DeterministicRandom gives the same bytes for the same seed")
    {
    }

  private:
    void DoRun() override
    {
        auto first = crypto::DeterministicRandom::FromSeed(crypto::Bytes(48, 0x11));
        auto second = crypto::DeterministicRandom::FromSeed(crypto::Bytes(48, 0x11));
        NS_TEST_ASSERT_MSG_EQ((first.has_value() && second.has_value()), true, "48-byte seeds");

        NS_TEST_EXPECT_MSG_EQ(first->Draw(0).empty(), true, "a draw of 0 bytes is empty");
        const auto drawn = first->Draw(64);
        // Expected value from an independent Python implementation of NIST SP 800-90A
        // HMAC_DRBG with SHA-384, instantiated with the seed as its seed material.
        NS_TEST_EXPECT_MSG_EQ(drawn == FromHex("2cbe9a2cf7ccd6a75037198f2f9e8d567c1833fa20cca4c2"
                                               "4f5e901cafd7414b7afd97b7423056c156ed2ed9febd0393"
                                               "b1b2008cd63b4fa5437355e9979fe15b"),
                              true,
                              "first 64 bytes are those of HMAC_DRBG with SHA-384");
        NS_TEST_EXPECT_MSG_EQ(
            second->Draw(64) == drawn,
            true,
            "the same seed gives the same bytes, and a draw of 0 changes nothing");
        const auto large = first->Draw(200000);
        NS_TEST_EXPECT_MSG_EQ(large.size(), 200000U, "a draw above the per-request limit");
        NS_TEST_EXPECT_MSG_EQ(second->Draw(200000) == large, true, "large draws agree");

        auto other = crypto::DeterministicRandom::FromSeed(crypto::Bytes(48, 0x12));
        NS_TEST_ASSERT_MSG_EQ(other.has_value(), true, "another 48-byte seed");
        NS_TEST_EXPECT_MSG_EQ(other->Draw(64) == drawn, false, "another seed gives other bytes");

        NS_TEST_EXPECT_MSG_EQ(
            crypto::DeterministicRandom::FromSeed(crypto::Bytes(47, 0x11)).has_value(),
            false,
            "a 47-byte seed is refused");
        NS_TEST_EXPECT_MSG_EQ(
            crypto::DeterministicRandom::FromSeed(crypto::Bytes(49, 0x11)).has_value(),
            false,
            "a 49-byte seed is refused");
    }
};

/**
 * @ingroup tulpar-tests
 * RSD-CRY-01a: ML-KEM-1024 key generation and encapsulation against NIST ACVP, decapsulation
 * (including implicit rejection) against Project Wycheproof, and refusal of malformed inputs.
 */
class TulparCryMlKemTestCase : public TestCase
{
  public:
    TulparCryMlKemTestCase()
        : TestCase("RSD-CRY-01a ML-KEM-1024 key generation, encapsulation and decapsulation match "
                   "published vectors")
    {
    }

  private:
    void DoRun() override
    {
        auto dz = FromHex(vectors::kAcvpMlKemKeyGenD);
        const auto z = FromHex(vectors::kAcvpMlKemKeyGenZ);
        dz.insert(dz.end(), z.begin(), z.end());
        const auto acvpPair = crypto::MlKem1024KeyPair::FromSeed(dz);
        NS_TEST_ASSERT_MSG_EQ(acvpPair.has_value(), true, "key pair from ACVP keyGen tcId 51");
        NS_TEST_EXPECT_MSG_EQ(acvpPair->EncapsulationKey() == FromHex(vectors::kAcvpMlKemKeyGenEk),
                              true,
                              "encapsulation key of ACVP keyGen tcId 51");

        const auto encapsulated = crypto::MlKem1024Encapsulate(FromHex(vectors::kAcvpMlKemEncapEk),
                                                               FromHex(vectors::kAcvpMlKemEncapM));
        NS_TEST_ASSERT_MSG_EQ(encapsulated.has_value(), true, "ACVP encapDecap tcId 51");
        NS_TEST_EXPECT_MSG_EQ(encapsulated->ciphertext == FromHex(vectors::kAcvpMlKemEncapC),
                              true,
                              "ciphertext of ACVP encapDecap tcId 51");
        NS_TEST_EXPECT_MSG_EQ(encapsulated->sharedSecret == FromHex(vectors::kAcvpMlKemEncapK),
                              true,
                              "shared secret of ACVP encapDecap tcId 51");

        struct Decapsulation
        {
            std::string_view seed;
            std::string_view ek;
            std::string_view c;
            std::string_view k;
            const char* what;
        };

        for (const auto& v : {Decapsulation{vectors::kWpMlKemValidSeed,
                                            vectors::kWpMlKemValidEk,
                                            vectors::kWpMlKemValidC,
                                            vectors::kWpMlKemValidK,
                                            "Wycheproof tcId 2"},
                              Decapsulation{vectors::kWpMlKemRejectSeed,
                                            vectors::kWpMlKemRejectEk,
                                            vectors::kWpMlKemRejectC,
                                            vectors::kWpMlKemRejectK,
                                            "Wycheproof tcId 194, implicit rejection"}})
        {
            const auto pair = crypto::MlKem1024KeyPair::FromSeed(FromHex(v.seed));
            NS_TEST_ASSERT_MSG_EQ(pair.has_value(), true, v.what);
            NS_TEST_EXPECT_MSG_EQ(pair->EncapsulationKey() == FromHex(v.ek), true, v.what);
            const auto secret = pair->Decapsulate(FromHex(v.c));
            NS_TEST_ASSERT_MSG_EQ(secret.has_value(), true, v.what);
            NS_TEST_EXPECT_MSG_EQ(*secret == FromHex(v.k), true, v.what);
        }

        const auto pair = crypto::MlKem1024KeyPair::FromSeed(FromHex(vectors::kWpMlKemValidSeed));
        NS_TEST_ASSERT_MSG_EQ(pair.has_value(), true, "key pair of Wycheproof tcId 2");
        const auto m = crypto::Bytes(32, 0x07);
        const auto own = crypto::MlKem1024Encapsulate(pair->EncapsulationKey(), m);
        NS_TEST_ASSERT_MSG_EQ(own.has_value(), true, "encapsulation to an own key");
        const auto opened = pair->Decapsulate(own->ciphertext);
        NS_TEST_ASSERT_MSG_EQ(opened.has_value(), true, "decapsulation of an own ciphertext");
        NS_TEST_EXPECT_MSG_EQ(*opened == own->sharedSecret, true, "round trip gives one secret");

        NS_TEST_EXPECT_MSG_EQ(
            crypto::MlKem1024KeyPair::FromSeed(crypto::ByteView(dz).first(63)).has_value(),
            false,
            "a 63-byte seed is refused");
        NS_TEST_EXPECT_MSG_EQ(
            pair->Decapsulate(crypto::ByteView(own->ciphertext).first(1567)).has_value(),
            false,
            "a 1567-byte ciphertext is refused");
        const auto ek = pair->EncapsulationKey();
        NS_TEST_EXPECT_MSG_EQ(
            crypto::MlKem1024Encapsulate(crypto::ByteView(ek).first(1567), m).has_value(),
            false,
            "a 1567-byte encapsulation key is refused");
        NS_TEST_EXPECT_MSG_EQ(crypto::MlKem1024Encapsulate(ek, crypto::Bytes(31, 0x07)).has_value(),
                              false,
                              "31 bytes of randomness are refused");
        NS_TEST_EXPECT_MSG_EQ(
            crypto::MlKem1024Encapsulate(FromHex(vectors::kAcvpMlKemBadEk), m).has_value(),
            false,
            "an encapsulation key failing the modulus check (ACVP tcId 159) is refused");
    }
};

/**
 * @ingroup tulpar-tests
 * RSD-CRY-01b: ML-DSA-87 key generation against NIST ACVP, verification against Project
 * Wycheproof, and a real verification failure under a wrong key.
 */
class TulparCryMlDsaVerifyTestCase : public TestCase
{
  public:
    TulparCryMlDsaVerifyTestCase()
        : TestCase("RSD-CRY-01b ML-DSA-87 signature verifies and fails under a wrong key")
    {
    }

  private:
    void DoRun() override
    {
        const auto acvpPair =
            crypto::MlDsa87KeyPair::FromSeed(FromHex(vectors::kAcvpMlDsaKeyGenSeed));
        NS_TEST_ASSERT_MSG_EQ(acvpPair.has_value(), true, "key pair from ACVP keyGen tcId 51");
        NS_TEST_EXPECT_MSG_EQ(acvpPair->PublicKey() == FromHex(vectors::kAcvpMlDsaKeyGenPk),
                              true,
                              "public key of ACVP keyGen tcId 51");

        const auto publicKey = FromHex(vectors::kWpMlDsaPk);
        const auto message = FromHex(vectors::kWpMlDsaMsg);
        NS_TEST_EXPECT_MSG_EQ(
            crypto::MlDsa87Verify(publicKey, message, FromHex(vectors::kWpMlDsaSig)),
            true,
            "Wycheproof verify tcId 1");
        NS_TEST_EXPECT_MSG_EQ(
            crypto::MlDsa87Verify(publicKey, message, FromHex(vectors::kWpMlDsaShortSig)),
            false,
            "Wycheproof verify tcId 6, short signature");
        NS_TEST_EXPECT_MSG_EQ(
            crypto::MlDsa87Verify(publicKey, message, FromHex(vectors::kWpMlDsaFlippedSig)),
            false,
            "Wycheproof verify tcId 8, bit flip in c_tilde");
        NS_TEST_EXPECT_MSG_EQ(crypto::MlDsa87Verify(crypto::ByteView(publicKey).first(2591),
                                                    message,
                                                    FromHex(vectors::kWpMlDsaSig)),
                              false,
                              "a 2591-byte public key is refused");

        const auto pair = crypto::MlDsa87KeyPair::FromSeed(FromHex(vectors::kWpMlDsaSeed));
        NS_TEST_ASSERT_MSG_EQ(pair.has_value(), true, "key pair of the Wycheproof seed");
        const auto text = FromText("TULPAR");
        const auto signature = pair->Sign(text);
        NS_TEST_EXPECT_MSG_EQ(crypto::MlDsa87Verify(pair->PublicKey(), text, signature),
                              true,
                              "a signature verifies under its own key");
        NS_TEST_EXPECT_MSG_EQ(crypto::MlDsa87Verify(acvpPair->PublicKey(), text, signature),
                              false,
                              "a wrong key produces a real verification failure");
        NS_TEST_EXPECT_MSG_EQ(crypto::MlDsa87Verify(pair->PublicKey(), {}, pair->Sign({})),
                              true,
                              "the empty message signs and verifies");
        NS_TEST_EXPECT_MSG_EQ(crypto::MlDsa87KeyPair::FromSeed(crypto::Bytes(31, 0x2a)).has_value(),
                              false,
                              "a 31-byte seed is refused");
    }
};

/**
 * @ingroup tulpar-tests
 * RSD-CRY-01f: deterministic ML-DSA-87 signing reproduces the Project Wycheproof signature made
 * with the all-zero randomizer, and two signatures of one message are byte-identical.
 */
class TulparCryMlDsaDeterministicTestCase : public TestCase
{
  public:
    TulparCryMlDsaDeterministicTestCase()
        : TestCase("RSD-CRY-01f deterministic ML-DSA-87 signatures are byte-identical")
    {
    }

  private:
    void DoRun() override
    {
        const auto pair = crypto::MlDsa87KeyPair::FromSeed(FromHex(vectors::kWpMlDsaSeed));
        NS_TEST_ASSERT_MSG_EQ(pair.has_value(), true, "key pair of the Wycheproof seed");
        NS_TEST_EXPECT_MSG_EQ(pair->PublicKey() == FromHex(vectors::kWpMlDsaPk),
                              true,
                              "public key of Wycheproof sign testGroups[0]");
        const auto message = FromHex(vectors::kWpMlDsaMsg);
        const auto first = pair->Sign(message);
        NS_TEST_EXPECT_MSG_EQ(first == FromHex(vectors::kWpMlDsaSig),
                              true,
                              "deterministic signature of Wycheproof sign tcId 1");
        NS_TEST_EXPECT_MSG_EQ(pair->Sign(message) == first,
                              true,
                              "a second signature of the message is byte-identical");
    }
};

/**
 * @ingroup tulpar-tests
 * RSD-CRY-01e: signatures, keys, ciphertexts and secrets have the real sizes of RSD Table 2.1.
 */
class TulparCrySizesTestCase : public TestCase
{
  public:
    TulparCrySizesTestCase()
        : TestCase("RSD-CRY-01e signatures and ciphertexts have their real sizes")
    {
    }

  private:
    void DoRun() override
    {
        const auto signer = crypto::MlDsa87KeyPair::FromSeed(FromHex(vectors::kWpMlDsaSeed));
        NS_TEST_ASSERT_MSG_EQ(signer.has_value(), true, "ML-DSA-87 key pair");
        NS_TEST_EXPECT_MSG_EQ(signer->Sign(FromText("TULPAR")).size(), 4627U, "signature");
        NS_TEST_EXPECT_MSG_EQ(signer->PublicKey().size(), 2592U, "ML-DSA-87 public key");

        const auto kem = crypto::MlKem1024KeyPair::FromSeed(FromHex(vectors::kWpMlKemValidSeed));
        NS_TEST_ASSERT_MSG_EQ(kem.has_value(), true, "ML-KEM-1024 key pair");
        NS_TEST_EXPECT_MSG_EQ(kem->EncapsulationKey().size(), 1568U, "encapsulation key");
        const auto encapsulated =
            crypto::MlKem1024Encapsulate(kem->EncapsulationKey(), crypto::Bytes(32, 0x07));
        NS_TEST_ASSERT_MSG_EQ(encapsulated.has_value(), true, "ML-KEM-1024 encapsulation");
        NS_TEST_EXPECT_MSG_EQ(encapsulated->ciphertext.size(), 1568U, "ciphertext");
        NS_TEST_EXPECT_MSG_EQ(encapsulated->sharedSecret.size(), 32U, "shared secret");
    }
};

/**
 * @ingroup tulpar-tests
 * Crypto unit tests of M-CRY (RSD-CRY-01).
 */
class TulparCryTestSuite : public TestSuite
{
  public:
    TulparCryTestSuite()
        : TestSuite("tulpar-cry", Type::UNIT)
    {
        AddTestCase(new TulparCryLinkedVersionTestCase, Duration::QUICK);
        AddTestCase(new TulparCryHashMacKdfTestCase, Duration::QUICK);
        AddTestCase(new TulparCryAesGcmTestCase, Duration::QUICK);
        AddTestCase(new TulparCryDeterministicRandomTestCase, Duration::QUICK);
        AddTestCase(new TulparCryMlKemTestCase, Duration::QUICK);
        AddTestCase(new TulparCryMlDsaVerifyTestCase, Duration::QUICK);
        AddTestCase(new TulparCryMlDsaDeterministicTestCase, Duration::QUICK);
        AddTestCase(new TulparCrySizesTestCase, Duration::QUICK);
    }
};

static TulparCryTestSuite g_tulparCryTestSuite; ///< static instance of the suite
