// SPDX-License-Identifier: Apache-2.0
// nanowire/packet.hpp — the packet view: ONE pass over a captured frame computes every layer
// offset (L2 end incl. the VLAN stack, L3, the IPv6 extension chain, L4, L4 payload) without
// allocating; typed views are then handed out on demand:
//
//   auto pkt = nanowire::packet::parse(frame);          // frame: std::span<const std::byte>
//   if (auto ip = pkt.ipv4()) use(ip->src(), ip->dst());
//   if (auto m = pkt.someip()) use(m->service_id(), m->method_id(), m->session_id());
//   for (auto m : pkt.someip_all()) ...                // several messages in one datagram
//
// Gates (same as nanom_shark's walk): an IPv4 / IPv6 fragment with a non-zero offset carries no
// L4 header (is_fragment() is set and l4() is none); a first fragment (offset 0, More set) does,
// and its L4 payload is the part captured in this fragment. Lengths are bounded by the IP total /
// payload length (so Ethernet padding is excluded) and by the captured bytes, never beyond.
// Malformed or truncated layers simply end the walk: the outer layers stay available.
//
// sizeof(packet) is 48 bytes; parse() is noexcept, branch-light and touches only header bytes.
#ifndef NANOWIRE_PACKET_HPP_INCLUDED
#define NANOWIRE_PACKET_HPP_INCLUDED

#include <nanowire/ethernet.hpp>
#include <nanowire/ip.hpp>
#include <nanowire/someip.hpp>
#include <nanowire/transport.hpp>

namespace nanowire {

/// pcap / pcapng LINKTYPE_ values the walk understands.
enum class link_type : u32 { ethernet = 1, raw = 101, ipv4 = 228, ipv6 = 229 };

enum class l3_kind : u8 { none, ipv4, ipv6, other };
enum class l4_kind : u8 { none, udp, tcp, other };

class packet {
 public:
  /// Walk a frame. Never fails: layers that are absent, truncated or malformed are reported as
  /// none, everything before them stays usable.
  static constexpr packet parse(bytes frame, link_type lt = link_type::ethernet) noexcept {
    packet k;
    k.p_ = frame.data();
    k.n_ = u32(frame.size() > 0xffffffffu ? 0xffffffffu : frame.size());
    const std::byte* p = k.p_;
    const u32 n = k.n_;
    u32 off = 0;
    u16 et;
    if (lt == link_type::ethernet) {
      if (n < 14) return k;
      k.flags_ |= has_eth;
      et = detail::be16(p + 12);
      off = 14;
      while (is_vlan_tpid(et)) {
        if (n - off < 4) {
          k.ethertype_ = et;
          k.l3_off_ = off;
          return k;
        }
        et = detail::be16(p + off + 2);
        off += 4;
        ++k.vlans_;
      }
    } else if (lt == link_type::raw || lt == link_type::ipv4 || lt == link_type::ipv6) {
      if (n < 1) return k;
      const u8 v = u8(p[0]) >> 4;
      et = v == 4 ? ethertype::ipv4 : v == 6 ? ethertype::ipv6 : 0;
    } else {
      return k;
    }
    k.ethertype_ = et;
    k.l3_off_ = off;

    u32 l4 = 0, l3_end = n;
    u8 proto;
    if (et == ethertype::ipv4) {
      if (n - off < 20) return k;
      const u8 vh = u8(p[off]);
      const u32 hl = u32(vh & 15) * 4;
      if ((vh >> 4) != 4 || hl < 20 || hl > n - off) return k;
      const u32 tl = detail::be16(p + off + 2);
      if (tl < hl) {
        k.l3_ = l3_kind::ipv4;
        k.l3_end_ = n;
        k.flags_ |= malformed;
        return k;
      }
      l3_end = tl <= n - off ? off + tl : n;
      k.l3_ = l3_kind::ipv4;
      proto = u8(p[off + 9]);
      const u16 fo = detail::be16(p + off + 6);
      if (fo & 0x3fff) {
        k.flags_ |= fragment;
        if (fo & 0x1fff) {
          k.l3_end_ = l3_end;
          k.proto_ = proto;
          k.l4_off_ = off + hl;
          return k;
        }
      }
      l4 = off + hl;
    } else if (et == ethertype::ipv6) {
      if (n - off < 40 || (u8(p[off]) >> 4) != 6) return k;
      const u32 pl = detail::be16(p + off + 4);
      l3_end = (pl != 0 && pl <= n - off - 40) ? off + 40 + pl : n;
      k.l3_ = l3_kind::ipv6;
      proto = u8(p[off + 6]);
      l4 = off + 40;
      for (unsigned guard = 0; guard < 64 && is_ipv6_extension(proto); ++guard) {
        if (l3_end - l4 < 8) {  // every extension header is at least 8 bytes
          k.l3_end_ = l3_end;
          k.proto_ = proto;
          k.l4_off_ = l4;
          k.flags_ |= malformed;
          return k;
        }
        u32 len;
        if (proto == ip_proto::ipv6_frag) {
          k.frag6_off_ = u16(l4 - off);
          k.flags_ |= fragment;
          len = 8;
          if (detail::be16(p + l4 + 2) & 0xfff8) {  // non-first fragment: data, not headers
            k.l3_end_ = l3_end;
            k.proto_ = u8(p[l4]);
            k.l4_off_ = l4 + 8;
            return k;
          }
        } else if (proto == ip_proto::ah) {
          len = (u32(u8(p[l4 + 1])) + 2) * 4;
        } else {
          len = (u32(u8(p[l4 + 1])) + 1) * 8;
        }
        if (len > l3_end - l4) {
          k.l3_end_ = l3_end;
          k.proto_ = proto;
          k.l4_off_ = l4;
          k.flags_ |= malformed;
          return k;
        }
        proto = u8(p[l4]);
        l4 += len;
      }
    } else {
      if (et != 0) k.l3_ = l3_kind::other;
      k.l3_end_ = n;
      return k;
    }
    k.l3_end_ = l3_end;
    k.proto_ = proto;
    k.l4_off_ = l4;

    if (proto == ip_proto::udp) {
      if (l3_end - l4 < 8) return k;
      const u32 ul = detail::be16(p + l4 + 4);
      k.l4_ = l4_kind::udp;
      k.pay_off_ = l4 + 8;
      k.pay_end_ = (ul >= 8 && ul <= l3_end - l4) ? l4 + ul : l3_end;
    } else if (proto == ip_proto::tcp) {
      if (l3_end - l4 < 20) return k;
      const u32 hl = u32(u8(p[l4 + 12]) >> 4) * 4;
      if (hl < 20 || hl > l3_end - l4) {
        k.flags_ |= malformed;
        return k;
      }
      k.l4_ = l4_kind::tcp;
      k.pay_off_ = l4 + hl;
      k.pay_end_ = l3_end;
    } else {
      k.l4_ = l4_kind::other;
      k.pay_off_ = l4;
      k.pay_end_ = l3_end;
    }
    return k;
  }

  // ---- whole frame / L2 ----
  constexpr bytes data() const noexcept { return {p_, n_}; }
  constexpr std::size_t size() const noexcept { return n_; }
  constexpr std::optional<ethernet_view> eth() const noexcept {
    if (!(flags_ & has_eth)) return std::nullopt;
    return ethernet_view(p_);
  }
  constexpr std::size_t vlan_count() const noexcept { return vlans_; }
  /// The i-th VLAN tag, outermost first (precondition: i < vlan_count()).
  constexpr vlan_view vlan(std::size_t i) const noexcept { return vlan_view(p_ + 14 + 4 * i); }
  /// The innermost EtherType (after every VLAN tag).
  constexpr u16 ethertype() const noexcept { return ethertype_; }
  /// Offset where L3 starts (= end of the L2 header incl. VLAN tags).
  constexpr std::size_t l3_offset() const noexcept { return l3_off_; }

  // ---- L3 ----
  constexpr l3_kind l3() const noexcept { return l3_; }
  constexpr std::optional<ipv4_view> ipv4() const noexcept {
    if (l3_ != l3_kind::ipv4) return std::nullopt;
    return ipv4_view(p_ + l3_off_, l3_end_ - l3_off_);
  }
  constexpr std::optional<ipv6_view> ipv6() const noexcept {
    if (l3_ != l3_kind::ipv6) return std::nullopt;
    return ipv6_view(p_ + l3_off_, l3_end_ - l3_off_);
  }
  /// The L3 datagram bytes (bounded by the IP length field and the capture).
  constexpr bytes l3_bytes() const noexcept { return {p_ + l3_off_, (l3_end_ > l3_off_ ? l3_end_ : l3_off_) - l3_off_}; }
  /// Upper-layer protocol number (after the IPv6 extension chain); 0 without IP.
  constexpr u8 ip_protocol() const noexcept { return proto_; }
  /// IPv4 MF / non-zero offset, or an IPv6 Fragment header in the chain.
  constexpr bool is_fragment() const noexcept { return (flags_ & fragment) != 0; }
  /// Some layer was malformed (inconsistent length fields); the walk stopped there.
  constexpr bool is_malformed() const noexcept { return (flags_ & malformed) != 0; }
  constexpr std::optional<ipv6_fragment_view> ipv6_fragment() const noexcept {
    if (!frag6_off_) return std::nullopt;
    return ipv6_fragment_view(p_ + l3_off_ + frag6_off_);
  }
  /// The fragment's data (bytes after the IPv4 header / IPv6 Fragment header up to the L3 end):
  /// what a reassembler stores. Empty when not a fragment.
  constexpr bytes fragment_data() const noexcept {
    if (!is_fragment()) return {};
    const u32 s = frag6_off_ ? l3_off_ + frag6_off_ + 8 : l4_off_;
    return {p_ + s, l3_end_ - s};
  }

  // ---- L4 ----
  constexpr l4_kind l4() const noexcept { return l4_; }
  constexpr std::size_t l4_offset() const noexcept { return l4_off_; }
  constexpr std::optional<udp_view> udp() const noexcept {
    if (l4_ != l4_kind::udp) return std::nullopt;
    return udp_view(p_ + l4_off_, l3_end_ - l4_off_);
  }
  constexpr std::optional<tcp_view> tcp() const noexcept {
    if (l4_ != l4_kind::tcp) return std::nullopt;
    return tcp_view(p_ + l4_off_, l3_end_ - l4_off_);
  }
  constexpr u16 src_port() const noexcept {
    return (l4_ == l4_kind::udp || l4_ == l4_kind::tcp) ? detail::be16(p_ + l4_off_) : u16(0);
  }
  constexpr u16 dst_port() const noexcept {
    return (l4_ == l4_kind::udp || l4_ == l4_kind::tcp) ? detail::be16(p_ + l4_off_ + 2) : u16(0);
  }
  /// The L4 payload (UDP: bounded by the UDP length; TCP: after data_offset).
  constexpr bytes payload() const noexcept { return {p_ + pay_off_, pay_end_ - pay_off_}; }
  constexpr std::size_t payload_offset() const noexcept { return pay_off_; }

  // ---- L5 (interpretation chosen by the caller, typically by port) ----
  /// The L4 payload read as one SOME/IP message (the first, if several are packed).
  constexpr std::optional<someip_view> someip() const noexcept {
    if (pay_end_ - pay_off_ < 16 || detail::be32(p_ + pay_off_ + 4) < 8) return std::nullopt;
    return someip_view(p_ + pay_off_, pay_end_ - pay_off_);
  }
  constexpr someip_messages someip_all() const noexcept { return someip_messages(payload()); }

 private:
  static constexpr u8 has_eth = 1, fragment = 2, malformed = 4;
  const std::byte* p_ = nullptr;
  u32 n_ = 0;
  u32 l3_off_ = 0, l3_end_ = 0, l4_off_ = 0, pay_off_ = 0, pay_end_ = 0;
  u16 ethertype_ = 0, frag6_off_ = 0;
  l3_kind l3_ = l3_kind::none;
  l4_kind l4_ = l4_kind::none;
  u8 proto_ = 0, vlans_ = 0, flags_ = 0;
};

}  // namespace nanowire

#endif  // NANOWIRE_PACKET_HPP_INCLUDED
