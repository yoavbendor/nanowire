// SPDX-License-Identifier: Apache-2.0
// nanowire/ethernet.hpp — Ethernet II and IEEE 802.1Q / 802.1ad (QinQ) VLAN tags.
//
//   wire::eth_hdr / wire::vlan_tag   the layouts (single definition, NANOM_DESCRIBE'd)
//   ethernet_view / vlan_view        zero-copy readers
//   eth / vlan                       builders (value structs with defaults)
//
// A VLAN tag on the wire is TPID + TCI; the TPID sits in the PREVIOUS header's EtherType field, so
// a vlan_view covers [TCI:2][inner EtherType:2] and the builder's `tpid` is written by the layer
// before it (eth / an outer vlan derive their type field from it). QinQ = vlan{.tpid=0x88A8} then
// vlan{}.
#ifndef NANOWIRE_ETHERNET_HPP_INCLUDED
#define NANOWIRE_ETHERNET_HPP_INCLUDED

#include <nanowire/core.hpp>

namespace nanowire::wire {
struct eth_hdr {
  std::array<u8, 6> dst, src;
  nm::be<u16> ethertype;
};
struct vlan_tag {
  nm::ubits<3> pcp;
  nm::ubits<1> dei;
  nm::ubits<12> vid;
  nm::be<u16> ethertype;  // inner EtherType (or the next tag's TPID)
};
}  // namespace nanowire::wire

NANOM_DESCRIBE(nanowire::wire::eth_hdr, dst, src, ethertype);
NANOM_DESCRIBE(nanowire::wire::vlan_tag, pcp, dei, vid, ethertype);

namespace nanowire {

static_assert(nm::wire_size_v<wire::eth_hdr> == 14 && nm::wire_size_v<wire::vlan_tag> == 4);

/// True for the EtherTypes that announce a VLAN tag (802.1Q, 802.1ad, legacy 0x9100).
constexpr bool is_vlan_tpid(u16 et) noexcept {
  return et == ethertype::vlan || et == ethertype::qinq || et == ethertype::vlan_9100;
}

class ethernet_view {
 public:
  static constexpr std::size_t size = 14;
  static constexpr std::optional<ethernet_view> parse(bytes b) noexcept {
    if (b.size() < size) return std::nullopt;
    return ethernet_view(b.data());
  }
  constexpr explicit ethernet_view(const std::byte* p) noexcept : p_(p) {}  // unchecked
  constexpr mac_addr dst() const noexcept { return detail::load_array<6>(p_); }
  constexpr mac_addr src() const noexcept { return detail::load_array<6>(p_ + 6); }
  /// The outer EtherType (a VLAN TPID when tagged).
  constexpr u16 ethertype() const noexcept { return field<wire::eth_hdr, "ethertype">(p_); }
  constexpr bytes header() const noexcept { return {p_, size}; }
  constexpr const std::byte* data() const noexcept { return p_; }

 private:
  const std::byte* p_;
};

class vlan_view {
 public:
  static constexpr std::size_t size = 4;
  static constexpr std::optional<vlan_view> parse(bytes b) noexcept {
    if (b.size() < size) return std::nullopt;
    return vlan_view(b.data());
  }
  constexpr explicit vlan_view(const std::byte* p) noexcept : p_(p) {}  // unchecked
  constexpr u8 pcp() const noexcept { return field<wire::vlan_tag, "pcp">(p_); }
  constexpr bool dei() const noexcept { return field<wire::vlan_tag, "dei">(p_) != 0; }
  constexpr u16 vid() const noexcept { return field<wire::vlan_tag, "vid">(p_); }
  constexpr u16 tci() const noexcept { return detail::be16(p_); }
  /// The EtherType that follows this tag.
  constexpr u16 ethertype() const noexcept { return field<wire::vlan_tag, "ethertype">(p_); }
  constexpr bytes header() const noexcept { return {p_, size}; }

 private:
  const std::byte* p_;
};

// ---------------------------------------------------------------------------------------------
// builders
// ---------------------------------------------------------------------------------------------

/// Ethernet II header. `type` defaults to the next layer's EtherType (0x0800 before an ipv4{}, the
/// tag's TPID before a vlan{}); set it to override.
struct eth {
  mac_addr dst{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  mac_addr src{0x02, 0, 0, 0, 0, 0x01};
  std::optional<u16> type{};

  constexpr std::size_t size() const noexcept { return 14; }
  constexpr bool write(std::byte* p, const build_ctx& c) const noexcept {
    wire::eth_hdr h{dst, src, type ? *type : c.next_ethertype};
    return emit_wire(h, p) == 14;
  }
};

/// One VLAN tag. `tpid` is what the PREVIOUS layer writes as its EtherType (0x8100 = 802.1Q,
/// 0x88A8 = 802.1ad S-tag for the outer tag of a QinQ stack). `type` (the inner EtherType)
/// defaults to the next layer's.
struct vlan {
  u16 vid = 0;
  u8 pcp = 0;
  bool dei = false;
  u16 tpid = ethertype::vlan;
  std::optional<u16> type{};

  constexpr std::size_t size() const noexcept { return 4; }
  constexpr u16 ethertype() const noexcept { return tpid; }
  constexpr bool write(std::byte* p, const build_ctx& c) const noexcept {
    if (vid > 0xfff || pcp > 7) return false;
    wire::vlan_tag t{{pcp}, {u8(dei)}, {vid}, type ? *type : c.next_ethertype};
    return emit_wire(t, p) == 4;
  }
};

}  // namespace nanowire

#endif  // NANOWIRE_ETHERNET_HPP_INCLUDED
