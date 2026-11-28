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
    }
};

static TulparCryTestSuite g_tulparCryTestSuite; ///< static instance of the suite
