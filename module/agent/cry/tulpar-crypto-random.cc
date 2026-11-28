/*
 * Copyright (c) 2026 TULPAR project team
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "botan_all.h"
#include "tulpar-crypto.h"

#include <utility>

namespace ns3
{
namespace tulpar
{
namespace crypto
{

/// Botan generator behind a DeterministicRandom.
struct DeterministicRandom::Impl
{
    /// HMAC_DRBG over HMAC-SHA-384 without an underlying generator: it never reseeds itself.
    Botan::HMAC_DRBG drbg{Botan::MessageAuthenticationCode::create_or_throw("HMAC(SHA-384)")};
};

DeterministicRandom::DeterministicRandom(std::unique_ptr<Impl> impl)
    : m_impl(std::move(impl))
{
}

DeterministicRandom::~DeterministicRandom() = default;

DeterministicRandom::DeterministicRandom(DeterministicRandom&& other) noexcept = default;

DeterministicRandom& DeterministicRandom::operator=(DeterministicRandom&& other) noexcept = default;

std::optional<DeterministicRandom>
DeterministicRandom::FromSeed(ByteView seed)
{
    if (seed.size() != kRandomSeedSize)
    {
        return std::nullopt;
    }
    auto impl = std::make_unique<Impl>();
    impl->drbg.initialize_with(seed);
    return DeterministicRandom(std::move(impl));
}

Bytes
DeterministicRandom::Draw(std::size_t n)
{
    Bytes out(n);
    // Botan treats a request for 0 bytes as new input and changes its state, so it is not asked.
    if (n > 0)
    {
        m_impl->drbg.randomize(out);
    }
    return out;
}

} // namespace crypto
} // namespace tulpar
} // namespace ns3
