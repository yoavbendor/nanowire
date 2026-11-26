// SPDX-License-Identifier: Apache-2.0
// nanowire/detail/checksum.hpp — INTERNAL. The RFC 1071 Internet checksum (one's-complement sum of
// 16-bit big-endian words) used by the IPv4 header and the UDP / TCP pseudo-header checksums.
//
// Forwards to <nanom/checksum.hpp> (`nanom::inet::*`), preserving the internal seam signatures
// for nanowire callers. Not part of the public API.
#ifndef NANOWIRE_DETAIL_CHECKSUM_HPP_INCLUDED
#define NANOWIRE_DETAIL_CHECKSUM_HPP_INCLUDED

#include <nanom/checksum.hpp>

#include <cstddef>
#include <cstdint>
#include <span>

namespace nanowire::detail {

/// Unfolded one's-complement accumulation of `b` as big-endian 16-bit words (odd tail padded
/// with zero). `odd_start` says the span begins on an odd byte of the logical stream (its first
/// byte is a low-order byte), so a sum may be accumulated over several spans.
constexpr std::uint64_t csum_add(std::uint64_t acc, std::span<const std::byte> b, bool odd_start = false) noexcept {
  nanom::inet::sum s;
  if (odd_start) {
    const std::byte zero{0};
    s.add(std::span<const std::byte>(&zero, 1));
  }
  s.add(b);
  return acc + s.folded();
}

/// Fold an accumulator to 16 bits (no complement).
constexpr std::uint16_t csum_fold(std::uint64_t acc) noexcept {
  nanom::inet::sum s;
  s.add32(std::uint32_t(acc >> 32)).add32(std::uint32_t(acc));
  return s.folded();
}

/// The Internet checksum field value of `b` (complemented fold).
constexpr std::uint16_t internet_checksum(std::span<const std::byte> b, std::uint64_t initial = 0) noexcept {
  if (initial == 0) return nanom::inet::checksum(b);
  nanom::inet::sum s;
  s.add_folded(csum_fold(initial)).add(b);
  return s.checksum();
}

/// RFC 1624 incremental update: new checksum after one 16-bit word changed from `old_word` to
/// `new_word` (HC' = ~(~HC + ~m + m')).
constexpr std::uint16_t checksum_update16(std::uint16_t hc, std::uint16_t old_word, std::uint16_t new_word) noexcept {
  return nanom::inet::update16(hc, old_word, new_word);
}

}  // namespace nanowire::detail

#endif  // NANOWIRE_DETAIL_CHECKSUM_HPP_INCLUDED
