// SPDX-License-Identifier: Apache-2.0
// nanowire/transport.hpp — UDP and TCP (header only; no stream reassembly).
//
//   wire::udp_hdr / wire::tcp_hdr   layouts (UDP length is a nanom computed field)
//   udp_view / tcp_view             zero-copy readers
//   udp / tcp                       builders; their pseudo-header checksums are filled in by frame
//                                   composition (build.hpp) once the payload is in place, using
//                                   the enclosing IPv4 / IPv6 header.
#ifndef NANOWIRE_TRANSPORT_HPP_INCLUDED
#define NANOWIRE_TRANSPORT_HPP_INCLUDED

#include <nanowire/core.hpp>
#include <nanowire/detail/checksum.hpp>
#include <nanowire/ip.hpp>

namespace nanowire::wire {
struct udp_hdr {
  nm::be<u16> src_port, dst_port, length, checksum;
};
struct tcp_hdr {
  nm::be<u16> src_port, dst_port;
  nm::be<u32> seq, ack;
  nm::ubits<4> data_offset;
  nm::ubits<3> reserved;
  nm::ubits<9> flags;  // NS CWR ECE URG ACK PSH RST SYN FIN
  nm::be<u16> window, checksum, urgent;
};
}  // namespace nanowire::wire

NANOM_DESCRIBE(nanowire::wire::udp_hdr, src_port, dst_port, length, checksum);
NANOM_DESCRIBE(nanowire::wire::tcp_hdr, src_port, dst_port, seq, ack, data_offset, reserved, flags, window, checksum,
               urgent);

template <>
struct nanom::computed<nanowire::wire::udp_hdr> {
  static constexpr auto fields = std::tuple{nanom::calc<"length">(
      [](const nanowire::wire::udp_hdr&, const nanom::emit_ctx& c) { return 8 + c.payload.size(); })};
};

namespace nanowire {

static_assert(nm::wire_size_v<wire::udp_hdr> == 8 && nm::wire_size_v<wire::tcp_hdr> == 20);

namespace tcp_flag {
inline constexpr u16 fin = 0x001, syn = 0x002, rst = 0x004, psh = 0x008, ack = 0x010, urg = 0x020, ece = 0x040,
                     cwr = 0x080, ns = 0x100;
}

class udp_view {
 public:
  static constexpr std::size_t size = 8;
  static constexpr std::optional<udp_view> parse(bytes b) noexcept {
    if (b.size() < size) return std::nullopt;
    return udp_view(b.data(), b.size());
  }
  constexpr udp_view(const std::byte* p, std::size_t n) noexcept : p_(p), n_(n) {}  // unchecked
  constexpr u16 src_port() const noexcept { return field<wire::udp_hdr, "src_port">(p_); }
  constexpr u16 dst_port() const noexcept { return field<wire::udp_hdr, "dst_port">(p_); }
  constexpr u16 length() const noexcept { return field<wire::udp_hdr, "length">(p_); }
  constexpr u16 checksum() const noexcept { return field<wire::udp_hdr, "checksum">(p_); }
  constexpr bytes header() const noexcept { return {p_, size}; }
  /// Payload bounded by the length field (when sane) and the available bytes.
  constexpr bytes payload() const noexcept {
    const std::size_t l = length();
    const std::size_t end = (l >= 8 && l <= n_) ? l : n_;
    return {p_ + 8, end - 8};
  }
  constexpr bool truncated() const noexcept { return length() > n_; }

 private:
  const std::byte* p_;
  std::size_t n_;
};

class tcp_view {
 public:
  static constexpr std::size_t min_size = 20;
  /// Validates once: >= 20 bytes, 5 <= data_offset, data_offset*4 <= available.
  static constexpr std::optional<tcp_view> parse(bytes b) noexcept {
    if (b.size() < min_size) return std::nullopt;
    const std::size_t h = std::size_t(u8(b[12]) >> 4) * 4;
    if (h < 20 || h > b.size()) return std::nullopt;
    return tcp_view(b.data(), b.size());
  }
  constexpr tcp_view(const std::byte* p, std::size_t n) noexcept : p_(p), n_(n) {}  // unchecked
  constexpr u16 src_port() const noexcept { return field<wire::tcp_hdr, "src_port">(p_); }
  constexpr u16 dst_port() const noexcept { return field<wire::tcp_hdr, "dst_port">(p_); }
  constexpr u32 seq() const noexcept { return field<wire::tcp_hdr, "seq">(p_); }
  constexpr u32 ack() const noexcept { return field<wire::tcp_hdr, "ack">(p_); }
  constexpr u8 data_offset() const noexcept { return field<wire::tcp_hdr, "data_offset">(p_); }
  constexpr std::size_t header_size() const noexcept { return std::size_t(data_offset()) * 4; }
  constexpr u16 flags() const noexcept { return field<wire::tcp_hdr, "flags">(p_); }
  constexpr bool has(u16 flag) const noexcept { return (flags() & flag) != 0; }
  constexpr u16 window() const noexcept { return field<wire::tcp_hdr, "window">(p_); }
  constexpr u16 checksum() const noexcept { return field<wire::tcp_hdr, "checksum">(p_); }
  constexpr u16 urgent() const noexcept { return field<wire::tcp_hdr, "urgent">(p_); }
  constexpr bytes header() const noexcept { return {p_, header_size()}; }
  constexpr bytes options() const noexcept { return {p_ + 20, header_size() - 20}; }
  constexpr bytes payload() const noexcept { return {p_ + header_size(), n_ - header_size()}; }

 private:
  const std::byte* p_;
  std::size_t n_;
};

// ---------------------------------------------------------------------------------------------
// pseudo-header checksum (shared by UDP / TCP builders and verification)
// ---------------------------------------------------------------------------------------------
namespace detail {
/// One's-complement sum of the IPv4 / IPv6 pseudo header for an upper-layer segment of `len`
/// bytes. `l3` starts at the IP header (version from its first nibble). For IPv6 the destination
/// is the FINAL one (RFC 8200 8.1): segment[0] of an SRv6 Segment Routing Header in the chain.
constexpr u64 pseudo_header_sum(bytes l3, u8 proto, std::size_t len) noexcept {
  u64 acc = 0;
  if (l3.size() >= 20 && (u8(l3[0]) >> 4) == 4) {
    acc = csum_add(acc, l3.subspan(12, 8));
  } else if (l3.size() >= 40) {
    acc = csum_add(acc, l3.subspan(8, 16));
    bytes dst = l3.subspan(24, 16);
    u8 nh = u8(l3[6]);
    std::size_t off = 40;
    for (unsigned k = 0; k < 64 && is_ipv6_extension(nh); ++k) {
      const std::size_t n = ipv6_ext_view::length_of(nh, l3.subspan(off));
      if (n == 0) break;
      if (nh == ip_proto::ipv6_route && u8(l3[off + 2]) == 4 && n >= 24) dst = l3.subspan(off + 8, 16);
      nh = u8(l3[off]);
      off += n;
    }
    acc = csum_add(acc, dst);
  }
  return acc + proto + (len & 0xffff) + (len >> 16);
}
}  // namespace detail

/// Verify a UDP / TCP checksum given the enclosing IP datagram (`l3`, from the IP header on) and
/// the whole L4 segment. A UDP checksum of 0 over IPv4 means "not computed" and verifies.
constexpr bool l4_checksum_ok(bytes l3, u8 proto, bytes segment) noexcept {
  if (proto == ip_proto::udp && segment.size() >= 8 && detail::be16(segment.data() + 6) == 0 && !l3.empty() &&
      (u8(l3[0]) >> 4) == 4)
    return true;
  return detail::internet_checksum(segment, detail::pseudo_header_sum(l3, proto, segment.size())) == 0;
}

// ---------------------------------------------------------------------------------------------
// builders
// ---------------------------------------------------------------------------------------------

/// UDP header. length is derived (computed field). checksum: nullopt = compute over the pseudo
/// header (the default; 0xFFFF is sent for a computed 0), a value = write it verbatim (0 = none).
struct udp {
  u16 src_port = 0;
  u16 dst_port = 0;
  std::optional<u16> length{};
  std::optional<u16> checksum{};

  static constexpr std::size_t size() noexcept { return 8; }
  static constexpr u8 ip_protocol() noexcept { return ip_proto::udp; }
  constexpr bool write(std::byte* p, const build_ctx& c) const noexcept {
    if (c.after + 8 > 0xffff && !length) return false;
    wire::udp_hdr h{src_port, dst_port, 0, checksum ? *checksum : u16(0)};
    if (emit_wire(h, p, bytes(p + 8, c.after)) != 8) return false;
    if (length) detail::put_be16(p + 4, *length);
    return true;
  }
  /// Second pass (after the payload is written): the pseudo-header checksum.
  constexpr void finalize(std::byte* p, const build_ctx& c) const noexcept {
    if (checksum || c.l3_version == 0) return;
    const bytes seg(p, 8 + c.after);
    detail::put_be16(p + 6, 0);
    const bytes l3(c.frame + c.l3_off, std::size_t(p + seg.size() - (c.frame + c.l3_off)));
    u16 s = detail::internet_checksum(seg, detail::pseudo_header_sum(l3, ip_proto::udp, seg.size()));
    detail::put_be16(p + 6, s == 0 ? u16(0xffff) : s);
  }
};

/// TCP header (no options unless given; raw option bytes padded with zeros to 4-byte units).
struct tcp {
  u16 src_port = 0;
  u16 dst_port = 0;
  u32 seq = 0;
  u32 ack = 0;
  u16 flags = tcp_flag::ack;
  u16 window = 65535;
  u16 urgent = 0;
  bytes options{};
  std::optional<u16> checksum{};

  constexpr std::size_t size() const noexcept { return 20 + ((options.size() + 3) & ~std::size_t(3)); }
  static constexpr u8 ip_protocol() noexcept { return ip_proto::tcp; }
  constexpr bool write(std::byte* p, const build_ctx&) const noexcept {
    const std::size_t h = size();
    if (h > 60 || flags > 0x1ff) return false;
    wire::tcp_hdr w{src_port, dst_port, seq, ack, {u8(h / 4)}, {0}, {flags}, window, checksum ? *checksum : u16(0),
                    urgent};
    if (emit_wire(w, p) != 20) return false;
    for (std::size_t i = 20; i < h; ++i) p[i] = i - 20 < options.size() ? options[i - 20] : std::byte{0};
    return true;
  }
  constexpr void finalize(std::byte* p, const build_ctx& c) const noexcept {
    if (checksum || c.l3_version == 0) return;
    const bytes seg(p, size() + c.after);
    detail::put_be16(p + 16, 0);
    const bytes l3(c.frame + c.l3_off, std::size_t(p + seg.size() - (c.frame + c.l3_off)));
    detail::put_be16(p + 16, detail::internet_checksum(seg, detail::pseudo_header_sum(l3, ip_proto::tcp, seg.size())));
  }
};

}  // namespace nanowire

#endif  // NANOWIRE_TRANSPORT_HPP_INCLUDED
