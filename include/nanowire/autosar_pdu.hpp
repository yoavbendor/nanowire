// SPDX-License-Identifier: Apache-2.0
// nanowire/autosar_pdu.hpp — AUTOSAR PDUs carried over IP:
//
//   * PDU-over-IP (Socket Adaptor "SoAd PDU header"): each PDU is [PDU ID:32][length:32][data],
//     several back to back in one UDP / TCP payload (big-endian).
//   * Container PDUs (IpduM): contained PDUs each prefixed with a SHORT header [ID:24][DLC:8] or a
//     LONG header [ID:32][DLC:32]; the header layout and byte order are ECU configuration, so they
//     are passed in at run time (ipdum_config). Parsing stops at the end, at a header that does not
//     fit, or (configurable, default on) at an all-zero header, which marks unused / padding bytes.
//
//   wire::soad_pdu_hdr / wire::ipdum_short_hdr / wire::ipdum_long_hdr   layouts (big-endian)
//   wire::ipdum_short_hdr_le / wire::ipdum_long_hdr_le                   little-endian layouts
//   ipdum_hdr_t<header, byte order>                                      picks one of the four
//   pdu_view, soad_pdus, ipdum_pdus                                       zero-copy readers / ranges
//   pdu, soad_pdu, soad_pdu_header, ipdum_container                       builders
//   ipdum_short_header(_le), ipdum_long_header(_le)                       one contained-PDU header
//                                                                         as a fixed-size layer
//   ipdum_pdu_header                                                      the same, layout chosen by
//                                                                         an ipdum_config at run time
#ifndef NANOWIRE_AUTOSAR_PDU_HPP_INCLUDED
#define NANOWIRE_AUTOSAR_PDU_HPP_INCLUDED

#include <nanowire/core.hpp>

namespace nanowire::wire {
struct soad_pdu_hdr {
  nm::be<u32> pdu_id;
  nm::be<u32> length;
};
struct ipdum_short_hdr {
  nm::ubits<24> id;
  u8 dlc;
};
struct ipdum_long_hdr {
  nm::be<u32> id;
  nm::be<u32> dlc;
};
// Little-endian contained-PDU headers (IpduM byte order is ECU configuration).
struct ipdum_short_hdr_le {
  nm::le_uint<3> id;
  u8 dlc;
};
struct ipdum_long_hdr_le {
  nm::le<u32> id;
  nm::le<u32> dlc;
};
}  // namespace nanowire::wire

NANOM_DESCRIBE(nanowire::wire::soad_pdu_hdr, pdu_id, length);
NANOM_DESCRIBE(nanowire::wire::ipdum_short_hdr, id, dlc);
NANOM_DESCRIBE(nanowire::wire::ipdum_long_hdr, id, dlc);
NANOM_DESCRIBE(nanowire::wire::ipdum_short_hdr_le, id, dlc);
NANOM_DESCRIBE(nanowire::wire::ipdum_long_hdr_le, id, dlc);

namespace nanowire {

static_assert(nm::wire_size_v<wire::soad_pdu_hdr> == 8 && nm::wire_size_v<wire::ipdum_short_hdr> == 4 &&
              nm::wire_size_v<wire::ipdum_long_hdr> == 8 && nm::wire_size_v<wire::ipdum_short_hdr_le> == 4 &&
              nm::wire_size_v<wire::ipdum_long_hdr_le> == 8);

/// One PDU found in a datagram or a container: its ID and its data (a view).
struct pdu_view {
  u32 id;
  bytes data;
};

/// Zero-copy range over SoAd PDU-over-IP records. Yields only complete PDUs; well_formed() says
/// whether the payload was consumed exactly.
class soad_pdus {
 public:
  constexpr explicit soad_pdus(bytes b) noexcept : b_(b) {}
  class iterator {
   public:
    using value_type = pdu_view;
    using difference_type = std::ptrdiff_t;
    constexpr iterator() = default;
    constexpr explicit iterator(bytes rest) noexcept : rest_(rest) { step_ = next_size(rest_); }
    constexpr pdu_view operator*() const noexcept {
      return {field<wire::soad_pdu_hdr, "pdu_id">(rest_.data()), rest_.subspan(8, step_ - 8)};
    }
    constexpr iterator& operator++() noexcept { rest_ = rest_.subspan(step_); step_ = next_size(rest_); return *this; }
    constexpr iterator operator++(int) noexcept { auto t = *this; ++*this; return t; }
    constexpr bool operator==(std::default_sentinel_t) const noexcept { return step_ == 0; }

   private:
    bytes rest_{};
    std::size_t step_ = 0;
  };
  constexpr iterator begin() const noexcept { return iterator(b_); }
  constexpr std::default_sentinel_t end() const noexcept { return {}; }
  constexpr bytes rest() const noexcept {
    bytes r = b_;
    while (std::size_t n = next_size(r)) r = r.subspan(n);
    return r;
  }
  constexpr bool well_formed() const noexcept { return rest().empty(); }
  static constexpr std::size_t next_size(bytes r) noexcept {
    if (r.size() < 8) return 0;
    const u32 l = detail::be32(r.data() + 4);
    return std::size_t(l) <= r.size() - 8 ? 8 + std::size_t(l) : 0;
  }

 private:
  bytes b_;
};

enum class ipdum_header : u8 { short_header, long_header };

/// The wire struct of one contained-PDU header for a header kind and byte order:
/// ipdum_hdr_t<short_header, big> = wire::ipdum_short_hdr, <long_header, little> = wire::ipdum_long_hdr_le, ...
template <ipdum_header H, std::endian E>
using ipdum_hdr_t = std::conditional_t<
    H == ipdum_header::short_header,
    std::conditional_t<E == std::endian::big, wire::ipdum_short_hdr, wire::ipdum_short_hdr_le>,
    std::conditional_t<E == std::endian::big, wire::ipdum_long_hdr, wire::ipdum_long_hdr_le>>;

/// Container PDU layout (ECU configuration).
struct ipdum_config {
  ipdum_header header = ipdum_header::short_header;
  std::endian byte_order = std::endian::big;
  bool stop_at_zero_header = true;  // an all-zero header marks the unused rest of the container
  constexpr std::size_t header_size() const noexcept { return header == ipdum_header::short_header ? 4 : 8; }
};

/// Zero-copy range over the PDUs inside one container PDU.
class ipdum_pdus {
 public:
  constexpr ipdum_pdus(bytes b, ipdum_config cfg = {}) noexcept : b_(b), cfg_(cfg) {}
  struct header {
    u32 id;
    u32 dlc;
  };
  static constexpr header read_header(const std::byte* p, const ipdum_config& c) noexcept {
    const bool be = c.byte_order == std::endian::big;
    if (c.header == ipdum_header::short_header) {
      if (be) return {field<wire::ipdum_short_hdr, "id">(p), u8(p[3])};
      return {field<wire::ipdum_short_hdr_le, "id">(p), u8(p[3])};
    }
    if (be) return {field<wire::ipdum_long_hdr, "id">(p), field<wire::ipdum_long_hdr, "dlc">(p)};
    return {field<wire::ipdum_long_hdr_le, "id">(p), field<wire::ipdum_long_hdr_le, "dlc">(p)};
  }
  /// Size of the contained PDU record at the start of r (header + DLC), or 0 to stop.
  static constexpr std::size_t next_size(bytes r, const ipdum_config& c) noexcept {
    const std::size_t h = c.header_size();
    if (r.size() < h) return 0;
    const header hd = read_header(r.data(), c);
    if (c.stop_at_zero_header && hd.id == 0 && hd.dlc == 0) return 0;
    return std::size_t(hd.dlc) <= r.size() - h ? h + std::size_t(hd.dlc) : 0;
  }
  class iterator {
   public:
    using value_type = pdu_view;
    using difference_type = std::ptrdiff_t;
    constexpr iterator() = default;
    constexpr iterator(bytes rest, ipdum_config c) noexcept : rest_(rest), c_(c) { step_ = next_size(rest_, c_); }
    constexpr pdu_view operator*() const noexcept {
      const std::size_t h = c_.header_size();
      return {read_header(rest_.data(), c_).id, rest_.subspan(h, step_ - h)};
    }
    constexpr iterator& operator++() noexcept {
      rest_ = rest_.subspan(step_);
      step_ = next_size(rest_, c_);
      return *this;
    }
    constexpr iterator operator++(int) noexcept { auto t = *this; ++*this; return t; }
    constexpr bool operator==(std::default_sentinel_t) const noexcept { return step_ == 0; }

   private:
    bytes rest_{};
    ipdum_config c_{};
    std::size_t step_ = 0;
  };
  constexpr iterator begin() const noexcept { return iterator(b_, cfg_); }
  constexpr std::default_sentinel_t end() const noexcept { return {}; }
  /// Unconsumed tail (padding after an all-zero header, or a record that did not fit).
  constexpr bytes rest() const noexcept {
    bytes r = b_;
    while (std::size_t n = next_size(r, cfg_)) r = r.subspan(n);
    return r;
  }
  /// Consumed exactly, or the tail is all-zero padding.
  constexpr bool well_formed() const noexcept {
    const bytes r = rest();
    if (r.empty()) return true;
    if (!cfg_.stop_at_zero_header) return false;
    for (auto b : r)
      if (b != std::byte{0}) return false;
    return true;
  }

 private:
  bytes b_;
  ipdum_config cfg_;
};

// ---------------------------------------------------------------------------------------------
// builders
// ---------------------------------------------------------------------------------------------

/// A PDU value (ID + data view) used by the container builder.
struct pdu {
  u32 id = 0;
  bytes data{};
};

/// One complete PDU-over-IP record [id][length = data.size()][data]. Several soad_pdu layers in a
/// row build a multi-PDU datagram.
struct soad_pdu {
  u32 id = 0;
  bytes data{};
  std::optional<u32> length{};  // override
  constexpr std::size_t size() const noexcept { return 8 + data.size(); }
  constexpr bool write(std::byte* p, const build_ctx&) const noexcept {
    if (!length && data.size() > 0xffffffffu) return false;
    if (emit_wire(wire::soad_pdu_hdr{id, length ? *length : u32(data.size())}, p) != 8) return false;
    for (std::size_t i = 0; i < data.size(); ++i) p[8 + i] = data[i];
    return true;
  }
};

/// Only the PDU-over-IP header; its length covers every following layer (e.g. a container).
struct soad_pdu_header {
  u32 id = 0;
  static constexpr std::size_t size() noexcept { return 8; }
  constexpr bool write(std::byte* p, const build_ctx& c) const noexcept {
    return c.after <= 0xffffffffu && emit_wire(wire::soad_pdu_hdr{id, u32(c.after)}, p) == 8;
  }
};

/// One contained-PDU header as a layer of its own (fixed size, one wire struct): the SHORT header
/// [ID:24][DLC:8] (wire::ipdum_short_hdr, or wire::ipdum_short_hdr_le for little-endian ECUs).
/// `dlc` defaults to the bytes after it in the frame (the contained PDU's data); a DLC over 255
/// must be given explicitly (malformed crafting) or the write fails.
template <std::endian E>
struct basic_ipdum_short_header {
  using wire_type = ipdum_hdr_t<ipdum_header::short_header, E>;
  static constexpr std::endian byte_order = E;
  u32 id = 0;
  std::optional<u8> dlc{};
  static constexpr std::size_t size() noexcept { return 4; }
  constexpr bool write(std::byte* p, const build_ctx& c = {}) const noexcept {
    if (id > 0xFFFFFF || (!dlc && c.after > 0xFF)) return false;
    return emit_wire(wire_type{id, dlc ? *dlc : u8(c.after)}, p) == 4;
  }
};
/// The LONG header [ID:32][DLC:32] (wire::ipdum_long_hdr / wire::ipdum_long_hdr_le); `dlc`
/// defaults to the bytes after it.
template <std::endian E>
struct basic_ipdum_long_header {
  using wire_type = ipdum_hdr_t<ipdum_header::long_header, E>;
  static constexpr std::endian byte_order = E;
  u32 id = 0;
  std::optional<u32> dlc{};
  static constexpr std::size_t size() noexcept { return 8; }
  constexpr bool write(std::byte* p, const build_ctx& c = {}) const noexcept {
    if (!dlc && c.after > 0xFFFFFFFFu) return false;
    return emit_wire(wire_type{id, dlc ? *dlc : u32(c.after)}, p) == 8;
  }
};
using ipdum_short_header = basic_ipdum_short_header<std::endian::big>;
using ipdum_short_header_le = basic_ipdum_short_header<std::endian::little>;
using ipdum_long_header = basic_ipdum_long_header<std::endian::big>;
using ipdum_long_header_le = basic_ipdum_long_header<std::endian::little>;

/// One contained-PDU header whose layout and byte order come from an ipdum_config at run time
/// (size() = config.header_size()). A convenience; frame templates use the four typed headers.
struct ipdum_pdu_header {
  ipdum_config config{};
  u32 id = 0;
  std::optional<u32> dlc{};
  constexpr std::size_t size() const noexcept { return config.header_size(); }
  constexpr bool write(std::byte* p, const build_ctx& c = {}) const noexcept {
    const bool be = config.byte_order == std::endian::big;
    if (config.header == ipdum_header::short_header) {
      if (dlc && *dlc > 0xFF) return false;
      const std::optional<u8> d = dlc ? std::optional<u8>(u8(*dlc)) : std::nullopt;
      return be ? ipdum_short_header{id, d}.write(p, c) : ipdum_short_header_le{id, d}.write(p, c);
    }
    return be ? ipdum_long_header{id, dlc}.write(p, c) : ipdum_long_header_le{id, dlc}.write(p, c);
  }
};

/// A container PDU: each contained PDU with its header, then zero padding up to `min_size`.
struct ipdum_container {
  ipdum_config config{};
  std::span<const pdu> pdus{};
  std::size_t min_size = 0;

  constexpr std::size_t content_size() const noexcept {
    std::size_t n = 0;
    for (const auto& x : pdus) n += config.header_size() + x.data.size();
    return n;
  }
  constexpr std::size_t size() const noexcept { return content_size() < min_size ? min_size : content_size(); }
  constexpr bool write(std::byte* p, const build_ctx& = {}) const noexcept {
    std::byte* q = p;
    for (const auto& x : pdus) {
      if (config.header == ipdum_header::short_header && x.data.size() > 0xFF) return false;
      const ipdum_pdu_header h{config, x.id, std::nullopt};
      build_ctx hc{};
      hc.after = x.data.size();
      if (!h.write(q, hc)) return false;
      q += h.size();
      detail::copy_bytes(q, x.data);
      q += x.data.size();
    }
    for (std::byte* e = p + size(); q < e; ++q) *q = std::byte{0};
    return true;
  }
};

}  // namespace nanowire

#endif  // NANOWIRE_AUTOSAR_PDU_HPP_INCLUDED
