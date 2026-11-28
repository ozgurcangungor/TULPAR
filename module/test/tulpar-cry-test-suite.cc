/*
 * Copyright (c) 2026 TULPAR project team
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "tulpar-crypto.h"

#include "ns3/test.h"

#include <string>

using namespace ns3;
using namespace ns3::tulpar;

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
 * Crypto unit tests of M-CRY (RSD-CRY-01).
 */
class TulparCryTestSuite : public TestSuite
{
  public:
    TulparCryTestSuite()
        : TestSuite("tulpar-cry", Type::UNIT)
    {
        AddTestCase(new TulparCryLinkedVersionTestCase, Duration::QUICK);
    }
};

static TulparCryTestSuite g_tulparCryTestSuite; ///< static instance of the suite
