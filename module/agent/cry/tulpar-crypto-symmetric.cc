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

std::string
LinkedBotanVersion()
{
    return std::to_string(Botan::version_major()) + "." + std::to_string(Botan::version_minor()) +
           "." + std::to_string(Botan::version_patch());
}

} // namespace crypto
} // namespace tulpar
} // namespace ns3
