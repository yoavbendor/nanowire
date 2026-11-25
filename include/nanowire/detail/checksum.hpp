// SPDX-License-Identifier: Apache-2.0
// nanowire/detail/checksum.hpp — INTERNAL. The RFC 1071 Internet checksum (one's-complement sum of
// 16-bit big-endian words) used by the IPv4 header and the UDP / TCP pseudo-header checksums.
//
// nanom is gaining include/nanom/checksum.hpp (Internet checksum incl. incremental RFC 1624 update,
// AUTOSAR CRCs). This header is the single seam: once nanowire's pinned nanom has it, these
// functions forward to nanom and every caller stays unchanged. Not part of the public API.
#ifndef NANOWIRE_DETAIL_CHECKSUM_HPP_INCLUDED
#define NANOWIRE_DETAIL_CHECKSUM_HPP_INCLUDED

#include <cstddef>
#include <cstdint>
#include <span>

namespace nanowire::detail {

/// Unfolded one's-complement accumulation of `b` as big-endian 16-bit words (odd tail padded
/// with zero). `odd_start` says the span begins on an odd byte of the logical stream (its first
/// byte is a low-order byte), so a sum may be accumulated over several spans.
constexpr std::uint64_t csum_add(std::uint64_t acc, std::span<const std::byte> b, bool odd_start = false) noexcept {
  std::size_t i = 0;
  if (odd_start && !b.empty()) acc += std::uint8_t(b[i++]);
  for (; i + 1 < b.size(); i += 2) acc += (std::uint64_t(std::uint8_t(b[i])) << 8) | std::uint8_t(b[i + 1]);
  if (i < b.size()) acc += std::uint64_t(std::uint8_t(b[i])) << 8;
  return acc;
}

/// Fold an accumulator to 16 bits (no complement).
constexpr std::uint16_t csum_fold(std::uint64_t acc) noexcept {
  while (acc >> 16) acc = (acc & 0xffff) + (acc >> 16);
  return std::uint16_t(acc);
}

/// The Internet checksum field value of `b` (complemented fold).
constexpr std::uint16_t internet_checksum(std::span<const std::byte> b, std::uint64_t initial = 0) noexcept {
  return std::uint16_t(~csum_fold(csum_add(initial, b)));
}

/// RFC 1624 incremental update: new checksum after one 16-bit word changed from `old_word` to
/// `new_word` (HC' = ~(~HC + ~m + m')).
constexpr std::uint16_t checksum_update16(std::uint16_t hc, std::uint16_t old_word, std::uint16_t new_word) noexcept {
  std::uint64_t acc = std::uint16_t(~hc);
  acc += std::uint16_t(~old_word);
  acc += new_word;
  return std::uint16_t(~csum_fold(acc));
}

}  // namespace nanowire::detail

#endif  // NANOWIRE_DETAIL_CHECKSUM_HPP_INCLUDED
