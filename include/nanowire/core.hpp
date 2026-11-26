// SPDX-License-Identifier: Apache-2.0
// nanowire/core.hpp — the vocabulary every protocol header shares:
//
//   * byte spans (`bytes`, `mut_bytes`) and address value types (mac_addr, ipv4_addr, ipv6_addr)
//     with constexpr text parsing (`ip4("10.0.0.1")`, `mac("02:00:00:00:00:01")`);
//   * unaligned big-endian load/store helpers (the hot-path primitives of the packet walk);
//   * the "one definition" bridge to nanom: a protocol's fixed header is declared ONCE as a
//     NANOM_DESCRIBE'd wire struct (be<> / ubits<> fields) in namespace `nanowire::wire`, and
//       - views read fields through `field<W, "name">(p)` (nanom's own field decode),
//       - builders write it with nanom::emit (computed lengths / checksums via nanom::computed),
//       - crafting templates patch single fields in place with `patch<W, "name">(p, v)` and find
//         them with `field_offset_v<W, "name">` / `field_bits_v<W, "name">`;
//   * the build-side layer protocol (`build_ctx`) that frame composition (build.hpp) drives.
//
// Nothing here allocates. All views are non-owning: the bytes must outlive them.
#ifndef NANOWIRE_CORE_HPP_INCLUDED
#define NANOWIRE_CORE_HPP_INCLUDED

#include <nanom/emit.hpp>
#include <nanom/nanom.hpp>

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace nanowire {

namespace nm = nanom;

using u8  = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;

/// Read-only bytes (a packet, a header, a payload). Views never own memory.
using bytes = std::span<const std::byte>;
/// Writable bytes (a build target).
using mut_bytes = std::span<std::byte>;

using mac_addr  = std::array<u8, 6>;
using ipv4_addr = std::array<u8, 4>;
using ipv6_addr = std::array<u8, 16>;

/// View any contiguous byte-like range as `bytes` (std::vector<std::uint8_t>, std::array, string).
template <class R>
  requires requires(const R& r) { std::data(r); std::size(r); } && (sizeof(*std::data(std::declval<const R&>())) == 1)
inline bytes as_bytes(const R& r) noexcept {
  return {reinterpret_cast<const std::byte*>(std::data(r)), std::size(r)};
}

// ---------------------------------------------------------------------------------------------
// unaligned loads / stores (network byte order unless named _le)
// ---------------------------------------------------------------------------------------------
namespace detail {
[[gnu::always_inline]] constexpr u16 be16(const std::byte* p) noexcept {
  if consteval {
    return u16((u16(u8(p[0])) << 8) | u8(p[1]));
  } else {
    u16 v;
    std::memcpy(&v, p, 2);
    if constexpr (std::endian::native == std::endian::little) v = std::byteswap(v);
    return v;
  }
}
[[gnu::always_inline]] constexpr u32 be32(const std::byte* p) noexcept {
  if consteval {
    return (u32(u8(p[0])) << 24) | (u32(u8(p[1])) << 16) | (u32(u8(p[2])) << 8) | u32(u8(p[3]));
  } else {
    u32 v;
    std::memcpy(&v, p, 4);
    if constexpr (std::endian::native == std::endian::little) v = std::byteswap(v);
    return v;
  }
}
[[gnu::always_inline]] constexpr u16 le16(const std::byte* p) noexcept {
  return u16(u8(p[0]) | (u16(u8(p[1])) << 8));
}
[[gnu::always_inline]] constexpr u32 le32(const std::byte* p) noexcept {
  return u32(u8(p[0])) | (u32(u8(p[1])) << 8) | (u32(u8(p[2])) << 16) | (u32(u8(p[3])) << 24);
}
constexpr void put_be16(std::byte* p, u16 v) noexcept {
  p[0] = std::byte(v >> 8);
  p[1] = std::byte(v);
}
constexpr void put_be32(std::byte* p, u32 v) noexcept {
  p[0] = std::byte(v >> 24);
  p[1] = std::byte(v >> 16);
  p[2] = std::byte(v >> 8);
  p[3] = std::byte(v);
}
constexpr void put_le16(std::byte* p, u16 v) noexcept {
  p[0] = std::byte(v);
  p[1] = std::byte(v >> 8);
}
constexpr void put_le32(std::byte* p, u32 v) noexcept {
  p[0] = std::byte(v);
  p[1] = std::byte(v >> 8);
  p[2] = std::byte(v >> 16);
  p[3] = std::byte(v >> 24);
}
/// Copy `src` to `dst` (non-overlapping): memcpy at run time, a byte loop in constant evaluation.
[[gnu::always_inline]] constexpr void copy_bytes(std::byte* dst, bytes src) noexcept {
  if consteval {
    for (std::size_t i = 0; i < src.size(); ++i) dst[i] = src[i];
  } else {
    if (!src.empty()) std::memcpy(dst, src.data(), src.size());
  }
}
template <std::size_t N>
constexpr std::array<u8, N> load_array(const std::byte* p) noexcept {
  std::array<u8, N> a{};
  for (std::size_t i = 0; i < N; ++i) a[i] = u8(p[i]);
  return a;
}
template <std::size_t N>
constexpr void store_array(std::byte* p, const std::array<u8, N>& a) noexcept {
  for (std::size_t i = 0; i < N; ++i) p[i] = std::byte(a[i]);
}
}  // namespace detail

// ---------------------------------------------------------------------------------------------
// address text parsing / formatting (constexpr; used for literals in tests and builders)
// ---------------------------------------------------------------------------------------------
namespace detail {
constexpr int hexval(char c) noexcept {
  return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
}
}  // namespace detail

/// "10.0.0.1" -> ipv4_addr; nullopt when malformed.
constexpr std::optional<ipv4_addr> parse_ipv4(std::string_view s) noexcept {
  ipv4_addr a{};
  std::size_t i = 0;
  for (int k = 0; k < 4; ++k) {
    if (k > 0) {
      if (i >= s.size() || s[i] != '.') return std::nullopt;
      ++i;
    }
    unsigned v = 0, digits = 0;
    const std::size_t start = i;
    while (i < s.size() && s[i] >= '0' && s[i] <= '9' && digits < 4) v = v * 10 + unsigned(s[i++] - '0'), ++digits;
    if (digits == 0 || (digits > 1 && s[start] == '0') || v > 255) return std::nullopt;
    a[k] = u8(v);
  }
  if (i != s.size()) return std::nullopt;
  return a;
}
/// "fd00::1" / full forms -> ipv6_addr (RFC 4291 text, no embedded IPv4); nullopt when malformed.
constexpr std::optional<ipv6_addr> parse_ipv6(std::string_view s) noexcept {
  std::array<u16, 8> head{}, tail{};
  std::size_t nh = 0, nt = 0, i = 0;
  bool gap = false;
  if (s.starts_with("::")) {
    gap = true;
    i = 2;
  }
  while (i < s.size()) {
    unsigned v = 0, digits = 0;
    while (i < s.size() && detail::hexval(s[i]) >= 0 && digits < 5) v = (v << 4) | unsigned(detail::hexval(s[i++])), ++digits;
    if (digits == 0 || digits > 4) return std::nullopt;
    if (gap) {
      if (nt >= 8) return std::nullopt;
      tail[nt++] = u16(v);
    } else {
      if (nh >= 8) return std::nullopt;
      head[nh++] = u16(v);
    }
    if (i == s.size()) break;
    if (s[i] != ':') return std::nullopt;
    ++i;
    if (i < s.size() && s[i] == ':') {
      if (gap) return std::nullopt;
      gap = true;
      ++i;
    } else if (i == s.size()) {
      return std::nullopt;
    }
  }
  if (nh + nt > 8 || (!gap && nh != 8) || (gap && nh + nt == 8)) return std::nullopt;
  ipv6_addr a{};
  for (std::size_t k = 0; k < nh; ++k) a[2 * k] = u8(head[k] >> 8), a[2 * k + 1] = u8(head[k]);
  for (std::size_t k = 0; k < nt; ++k) {
    const std::size_t w = 8 - nt + k;
    a[2 * w] = u8(tail[k] >> 8), a[2 * w + 1] = u8(tail[k]);
  }
  return a;
}
/// "02:00:00:00:00:01" (or '-' separated) -> mac_addr; nullopt when malformed.
constexpr std::optional<mac_addr> parse_mac(std::string_view s) noexcept {
  if (s.size() != 17) return std::nullopt;
  mac_addr m{};
  for (std::size_t k = 0; k < 6; ++k) {
    const int h = detail::hexval(s[3 * k]), l = detail::hexval(s[3 * k + 1]);
    if (h < 0 || l < 0 || (k < 5 && s[3 * k + 2] != ':' && s[3 * k + 2] != '-')) return std::nullopt;
    m[k] = u8(h * 16 + l);
  }
  return m;
}

/// Literal helpers: ip4("10.0.0.1"), ip6("fd00::1"), mac("02:00:00:00:00:01"). consteval: a
/// malformed literal is a compile error. Use parse_ipv4 / parse_ipv6 / parse_mac at run time.
consteval ipv4_addr ip4(std::string_view s) { auto a = parse_ipv4(s); if (!a) throw "nanowire: malformed IPv4 literal"; return *a; }
consteval ipv6_addr ip6(std::string_view s) { auto a = parse_ipv6(s); if (!a) throw "nanowire: malformed IPv6 literal"; return *a; }
consteval mac_addr  mac(std::string_view s) { auto a = parse_mac(s);  if (!a) throw "nanowire: malformed MAC literal"; return *a; }

inline std::string to_string(const ipv4_addr& a) {
  return std::to_string(a[0]) + '.' + std::to_string(a[1]) + '.' + std::to_string(a[2]) + '.' + std::to_string(a[3]);
}
inline std::string to_string(const mac_addr& a) {
  static constexpr char hx[] = "0123456789abcdef";
  std::string s;
  for (std::size_t i = 0; i < 6; ++i) {
    if (i) s += ':';
    s += hx[a[i] >> 4];
    s += hx[a[i] & 15];
  }
  return s;
}
inline std::string to_string(const ipv6_addr& a) {  // uncompressed lower-case groups
  static constexpr char hx[] = "0123456789abcdef";
  std::string s;
  for (std::size_t i = 0; i < 16; i += 2) {
    if (i) s += ':';
    const unsigned v = (unsigned(a[i]) << 8) | a[i + 1];
    bool started = false;
    for (int sh = 12; sh >= 0; sh -= 4) {
      const unsigned d = (v >> sh) & 15;
      if (d || started || sh == 0) s += hx[d], started = true;
    }
  }
  return s;
}

// ---------------------------------------------------------------------------------------------
// the nanom bridge: field access / patching by name on a described wire struct
// ---------------------------------------------------------------------------------------------

/// Bit offset of field `Name` within wire struct W (msb0 from the struct start).
template <nm::Described W, nm::fixed_string Name>
inline constexpr std::size_t field_bit_offset_v = [] {
  constexpr std::size_t I = nm::field_index<W, Name>();
  static_assert(I != std::size_t(-1), "nanowire: no such field in this wire struct");
  return nm::field_bit_offsets<W>()[I];
}();
/// Byte offset of the byte holding field `Name`'s first bit.
template <nm::Described W, nm::fixed_string Name>
inline constexpr std::size_t field_offset_v = field_bit_offset_v<W, Name> / 8;
/// Width of field `Name` in bits.
template <nm::Described W, nm::fixed_string Name>
inline constexpr std::size_t field_bits_v = [] {
  constexpr std::size_t I = nm::field_index<W, Name>();
  static_assert(I != std::size_t(-1), "nanowire: no such field in this wire struct");
  return nm::wire_bits_v<nm::field_type_t<W, I>>;
}();

/// Decode one field of wire struct W whose encoding starts at `p` (nanom's own decode; a be<u16>
/// lowers to one load + bswap). The caller guarantees wire_size_v<W> readable bytes at p.
template <nm::Described W, nm::fixed_string Name>
[[gnu::always_inline]] constexpr auto field(const std::byte* p) noexcept {
  return nm::view<W>{p, std::endian::big}.template get<Name>();
}

/// Overwrite one field in place (template patching): be<> fields, ubits<> / ibits<> fields (other
/// bits of shared bytes are preserved), plain integrals, byte arrays. Returns false when the value
/// does not fit.
template <nm::Described W, nm::fixed_string Name, class V>
constexpr bool patch(std::byte* p, const V& value) noexcept {
  return nm::mut_view<W>{p, std::endian::big}.template set<Name>(value).has_value();
}

/// Encode a wire struct (computed fields applied) into `out`; returns bytes written or 0 on error.
template <nm::Described W>
constexpr std::size_t emit_wire(const W& w, std::byte* out, bytes after = {}) noexcept {
  auto r = nm::emit(w, std::span<std::byte>(out, nm::wire_size_v<W>), nm::emit_ctx{after}, std::endian::big);
  return r ? *r : 0;
}

// ---------------------------------------------------------------------------------------------
// constants shared by several layers
// ---------------------------------------------------------------------------------------------
namespace ethertype {
inline constexpr u16 ipv4 = 0x0800, arp = 0x0806, vlan = 0x8100, qinq = 0x88A8, vlan_9100 = 0x9100,
                     ipv6 = 0x86DD, ptp = 0x88F7, lldp = 0x88CC;
}
namespace ip_proto {
inline constexpr u8 hopopt = 0, icmp = 1, igmp = 2, tcp = 6, udp = 17, ipv6_route = 43, ipv6_frag = 44,
                    esp = 50, ah = 51, icmpv6 = 58, no_next = 59, ipv6_opts = 60, mobility = 135,
                    hip = 139, shim6 = 140;
}
namespace port {
inline constexpr u16 someip_sd = 30490;
}

// ---------------------------------------------------------------------------------------------
// build-side layer protocol (driven by build.hpp)
// ---------------------------------------------------------------------------------------------
/// What frame composition tells a layer while writing it. `after` is the number of bytes that
/// follow this layer's own bytes up to the end of the frame (the "payload" for length fields).
/// `next_ethertype` / `next_ip_proto` describe the following layer (0 when it has none), so an
/// eth / vlan / ipv4 builder left at its default derives its type / protocol field.
/// A default-constructed build_ctx (after = 0, nothing next) is valid for every builder.
struct build_ctx {
  std::size_t after = 0;
  u16 next_ethertype = 0;
  u8 next_ip_proto = 0;
  bool has_next_ip_proto = false;
  // Message Type bits the next layer asks the SOME/IP header before it to set (someip_tp: the TP
  // flag 0x20), so someip{} / someip_tp{} stacked as two layers form a TP segment.
  u8 next_someip_type_flags = 0;
  // Bytes of the SOME/IP-SD entry layers (static `sd_entry_layer`) right after this layer: what an
  // sd_header{} derives its entries_length from.
  std::size_t sd_entries_after = 0;
  // enclosing L3 (for UDP / TCP pseudo-header checksums), as offsets into the frame
  std::byte* frame = nullptr;
  std::size_t l3_off = 0;
  u8 l3_version = 0;  // 0 none, 4, 6
};

}  // namespace nanowire

#endif  // NANOWIRE_CORE_HPP_INCLUDED
