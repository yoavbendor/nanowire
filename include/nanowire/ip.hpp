// SPDX-License-Identifier: Apache-2.0
// nanowire/ip.hpp — IPv4 (with options) and IPv6 (with the extension-header chain: Hop-by-Hop,
// Routing incl. the SRv6 Segment Routing Header, Fragment, Destination Options, AH).
//
//   wire::ipv4_hdr / wire::ipv6_hdr / wire::ipv6_frag_hdr / wire::ipv6_srh_hdr   layouts
//   ipv4_view (+ ipv4_options range) / ipv6_view (+ ipv6_ext_range, ipv6_fragment_view,
//   ipv6_routing_view)                                                           zero-copy readers
//   ipv4 / ipv6 / ipv6_frag / ipv6_hbh / ipv6_dstopts / ipv6_srh                 builders
//
// IPv4 total_length and header checksum are nanom computed fields of wire::ipv4_hdr (see the
// nanom::computed specialization below), so the same definition that parses the header derives
// them when it is written and `ipv4_view::checksum_ok()` verifies them on read.
#ifndef NANOWIRE_IP_HPP_INCLUDED
#define NANOWIRE_IP_HPP_INCLUDED

#include <nanowire/core.hpp>
#include <nanowire/detail/checksum.hpp>

namespace nanowire::wire {
struct ipv4_hdr {
  nm::ubits<4> version;
  nm::ubits<4> ihl;
  nm::ubits<6> dscp;
  nm::ubits<2> ecn;
  nm::be<u16> total_length;
  nm::be<u16> identification;
  nm::ubits<1> reserved;
  nm::ubits<1> df;
  nm::ubits<1> mf;
  nm::ubits<13> frag_offset;  // in 8-byte units
  u8 ttl;
  u8 protocol;
  nm::be<u16> checksum;
  std::array<u8, 4> src, dst;
};
struct ipv6_hdr {
  nm::ubits<4> version;
  nm::ubits<8> traffic_class;
  nm::ubits<20> flow_label;
  nm::be<u16> payload_length;
  u8 next_header;
  u8 hop_limit;
  std::array<u8, 16> src, dst;
};
struct ipv6_frag_hdr {
  u8 next_header;
  u8 reserved;
  nm::ubits<13> offset;  // in 8-byte units
  nm::ubits<2> res;
  nm::ubits<1> more;
  nm::be<u32> identification;
};
struct ipv6_srh_hdr {  // Routing header fixed part; SRH (routing_type 4) segment list follows
  u8 next_header;
  u8 hdr_ext_len;
  u8 routing_type;
  u8 segments_left;
  u8 last_entry;
  u8 flags;
  nm::be<u16> tag;
};
}  // namespace nanowire::wire

NANOM_DESCRIBE(nanowire::wire::ipv4_hdr, version, ihl, dscp, ecn, total_length, identification, reserved, df, mf,
               frag_offset, ttl, protocol, checksum, src, dst);
NANOM_DESCRIBE(nanowire::wire::ipv6_hdr, version, traffic_class, flow_label, payload_length, next_header, hop_limit,
               src, dst);
NANOM_DESCRIBE(nanowire::wire::ipv6_frag_hdr, next_header, reserved, offset, res, more, identification);
NANOM_DESCRIBE(nanowire::wire::ipv6_srh_hdr, next_header, hdr_ext_len, routing_type, segments_left, last_entry,
               flags, tag);

// IPv4's derived fields, declared once on the wire struct: emit fills them, verify_computed checks
// them. ctx.payload is everything after the fixed 20 bytes (options first, then the upper layer).
template <>
struct nanom::computed<nanowire::wire::ipv4_hdr> {
  static constexpr auto fields = std::tuple{
      nanom::calc<"total_length">(
          [](const nanowire::wire::ipv4_hdr&, const nanom::emit_ctx& c) { return 20 + c.payload.size(); }),
      nanom::checksum<"checksum">([](std::span<const std::byte> hdr, const nanom::emit_ctx& c) {
        const std::size_t hl = static_cast<std::size_t>(std::to_integer<unsigned>(hdr[0]) & 0x0fu) * 4;
        const std::size_t opt = hl > 20 ? hl - 20 : 0;
        const std::uint64_t acc = nanowire::detail::csum_add(0, hdr);
        return nanowire::detail::internet_checksum(c.payload.first(std::min(opt, c.payload.size())), acc);
      }),
  };
};

namespace nanowire {

static_assert(nm::wire_size_v<wire::ipv4_hdr> == 20 && nm::wire_size_v<wire::ipv6_hdr> == 40 &&
              nm::wire_size_v<wire::ipv6_frag_hdr> == 8 && nm::wire_size_v<wire::ipv6_srh_hdr> == 8);

// ---------------------------------------------------------------------------------------------
// IPv4
// ---------------------------------------------------------------------------------------------

/// One IPv4 option: type octet and its value (without type/length octets; empty for NOP).
struct ipv4_option {
  u8 type;
  bytes value;
  constexpr bool copied() const noexcept { return (type & 0x80) != 0; }
  constexpr u8 number() const noexcept { return type & 0x1f; }
};

/// Zero-copy range over IPv4 option TLVs. Stops at End-of-Option-List or at a malformed option
/// (well_formed() then reports false).
class ipv4_options {
 public:
  constexpr explicit ipv4_options(bytes b) noexcept : b_(b) {}
  class iterator {
   public:
    using value_type = ipv4_option;
    using difference_type = std::ptrdiff_t;
    constexpr iterator() = default;
    constexpr explicit iterator(bytes rest) noexcept : rest_(rest) { load(); }
    constexpr ipv4_option operator*() const noexcept { return cur_; }
    constexpr iterator& operator++() noexcept { rest_ = rest_.subspan(step_); load(); return *this; }
    constexpr iterator operator++(int) noexcept { auto t = *this; ++*this; return t; }
    constexpr bool operator==(std::default_sentinel_t) const noexcept { return step_ == 0; }

   private:
    constexpr void load() noexcept {
      step_ = 0;
      if (rest_.empty()) return;
      const u8 t = u8(rest_[0]);
      if (t == 0) return;  // EOL
      if (t == 1) { cur_ = {1, {}}; step_ = 1; return; }
      if (rest_.size() < 2) return;
      const u8 l = u8(rest_[1]);
      if (l < 2 || l > rest_.size()) return;
      cur_ = {t, rest_.subspan(2, l - 2)};
      step_ = l;
    }
    bytes rest_{};
    ipv4_option cur_{};
    std::size_t step_ = 0;
  };
  constexpr iterator begin() const noexcept { return iterator(b_); }
  constexpr std::default_sentinel_t end() const noexcept { return {}; }
  /// True when the walk consumed every byte up to an EOL / the end without a malformed option.
  constexpr bool well_formed() const noexcept {
    std::size_t i = 0;
    while (i < b_.size()) {
      const u8 t = u8(b_[i]);
      if (t == 0) return true;
      if (t == 1) { ++i; continue; }
      if (i + 2 > b_.size()) return false;
      const u8 l = u8(b_[i + 1]);
      if (l < 2 || i + l > b_.size()) return false;
      i += l;
    }
    return true;
  }

 private:
  bytes b_;
};

class ipv4_view {
 public:
  static constexpr std::size_t min_size = 20;
  /// Validates once: >= 20 bytes, version 4, 5 <= ihl, ihl*4 <= available.
  static constexpr std::optional<ipv4_view> parse(bytes b) noexcept {
    if (b.size() < min_size) return std::nullopt;
    const u8 v = u8(b[0]);
    if ((v >> 4) != 4 || (v & 15) < 5 || std::size_t(v & 15) * 4 > b.size()) return std::nullopt;
    return ipv4_view(b.data(), b.size());
  }
  /// Unchecked: `n` available bytes from p, already validated by the caller.
  constexpr ipv4_view(const std::byte* p, std::size_t n) noexcept : p_(p), n_(n) {}

  constexpr u8 version() const noexcept { return field<wire::ipv4_hdr, "version">(p_); }
  constexpr u8 ihl() const noexcept { return field<wire::ipv4_hdr, "ihl">(p_); }
  constexpr std::size_t header_size() const noexcept { return std::size_t(ihl()) * 4; }
  constexpr u8 dscp() const noexcept { return field<wire::ipv4_hdr, "dscp">(p_); }
  constexpr u8 ecn() const noexcept { return field<wire::ipv4_hdr, "ecn">(p_); }
  constexpr u16 total_length() const noexcept { return field<wire::ipv4_hdr, "total_length">(p_); }
  constexpr u16 identification() const noexcept { return field<wire::ipv4_hdr, "identification">(p_); }
  constexpr bool df() const noexcept { return field<wire::ipv4_hdr, "df">(p_) != 0; }
  constexpr bool mf() const noexcept { return field<wire::ipv4_hdr, "mf">(p_) != 0; }
  /// Fragment offset in 8-byte units (frag_offset_bytes() for bytes).
  constexpr u16 frag_offset() const noexcept { return field<wire::ipv4_hdr, "frag_offset">(p_); }
  constexpr u32 frag_offset_bytes() const noexcept { return u32(frag_offset()) * 8; }
  constexpr bool is_fragment() const noexcept { return (detail::be16(p_ + 6) & 0x3fff) != 0; }
  constexpr u8 ttl() const noexcept { return u8(p_[8]); }
  constexpr u8 protocol() const noexcept { return u8(p_[9]); }
  constexpr u16 checksum() const noexcept { return field<wire::ipv4_hdr, "checksum">(p_); }
  constexpr ipv4_addr src() const noexcept { return detail::load_array<4>(p_ + 12); }
  constexpr ipv4_addr dst() const noexcept { return detail::load_array<4>(p_ + 16); }

  constexpr bytes header() const noexcept { return {p_, header_size()}; }
  constexpr bytes options_bytes() const noexcept { return {p_ + 20, header_size() - 20}; }
  constexpr ipv4_options options() const noexcept { return ipv4_options(options_bytes()); }
  /// The datagram payload: after the header, bounded by total_length and by the captured bytes.
  constexpr bytes payload() const noexcept {
    const std::size_t h = header_size(), tl = total_length();
    const std::size_t end = (tl >= h && tl <= n_) ? tl : n_;
    return {p_ + h, end - h};
  }
  /// total_length claims more bytes than were captured (snaplen cut / truncated datagram).
  constexpr bool truncated() const noexcept { return total_length() > n_; }
  /// Header checksum verifies (sums to zero over header incl. options).
  constexpr bool checksum_ok() const noexcept { return detail::internet_checksum(header()) == 0; }

 private:
  const std::byte* p_;
  std::size_t n_;
};

// ---------------------------------------------------------------------------------------------
// IPv6 and its extension headers
// ---------------------------------------------------------------------------------------------

/// The next-header values the extension walk descends (everything else ends the chain: an
/// upper-layer protocol, ESP (opaque), or No Next Header).
constexpr bool is_ipv6_extension(u8 nh) noexcept {
  return nh == ip_proto::hopopt || nh == ip_proto::ipv6_route || nh == ip_proto::ipv6_frag ||
         nh == ip_proto::ipv6_opts || nh == ip_proto::ah || nh == ip_proto::mobility || nh == ip_proto::hip ||
         nh == ip_proto::shim6;
}

class ipv6_fragment_view {
 public:
  static constexpr std::size_t size = 8;
  constexpr explicit ipv6_fragment_view(const std::byte* p) noexcept : p_(p) {}
  constexpr u8 next_header() const noexcept { return u8(p_[0]); }
  /// Offset in 8-byte units (offset_bytes() for bytes).
  constexpr u16 offset() const noexcept { return field<wire::ipv6_frag_hdr, "offset">(p_); }
  constexpr u32 offset_bytes() const noexcept { return u32(offset()) * 8; }
  constexpr bool more() const noexcept { return field<wire::ipv6_frag_hdr, "more">(p_) != 0; }
  constexpr u32 identification() const noexcept { return field<wire::ipv6_frag_hdr, "identification">(p_); }

 private:
  const std::byte* p_;
};

/// Routing header; segments are the SRv6 segment list when routing_type() == 4.
class ipv6_routing_view {
 public:
  constexpr ipv6_routing_view(const std::byte* p, std::size_t len) noexcept : p_(p), len_(len) {}
  constexpr u8 next_header() const noexcept { return u8(p_[0]); }
  constexpr u8 routing_type() const noexcept { return u8(p_[2]); }
  constexpr u8 segments_left() const noexcept { return u8(p_[3]); }
  constexpr bool is_srh() const noexcept { return routing_type() == 4; }
  constexpr u8 last_entry() const noexcept { return u8(p_[4]); }
  constexpr u8 flags() const noexcept { return u8(p_[5]); }
  constexpr u16 tag() const noexcept { return field<wire::ipv6_srh_hdr, "tag">(p_); }
  /// Number of SRv6 segments that fit the header (min(last_entry + 1, room)).
  constexpr std::size_t segment_count() const noexcept {
    if (!is_srh() || len_ < 8) return 0;
    const std::size_t room = (len_ - 8) / 16, want = std::size_t(last_entry()) + 1;
    return want < room ? want : room;
  }
  constexpr ipv6_addr segment(std::size_t i) const noexcept { return detail::load_array<16>(p_ + 8 + 16 * i); }
  /// SRH TLVs after the segment list.
  constexpr bytes tlvs() const noexcept {
    const std::size_t s = 8 + 16 * segment_count();
    return s <= len_ ? bytes{p_ + s, len_ - s} : bytes{};
  }

 private:
  const std::byte* p_;
  std::size_t len_;
};

/// One Hop-by-Hop / Destination option ([type][len][value]; Pad1 has no length octet).
struct ipv6_option {
  u8 type;
  bytes value;
};
/// Zero-copy range over Hop-by-Hop / Destination Options TLVs (RFC 8200 4.2).
class ipv6_options {
 public:
  constexpr explicit ipv6_options(bytes b) noexcept : b_(b) {}
  class iterator {
   public:
    using value_type = ipv6_option;
    using difference_type = std::ptrdiff_t;
    constexpr iterator() = default;
    constexpr explicit iterator(bytes rest) noexcept : rest_(rest) { load(); }
    constexpr ipv6_option operator*() const noexcept { return cur_; }
    constexpr iterator& operator++() noexcept { rest_ = rest_.subspan(step_); load(); return *this; }
    constexpr iterator operator++(int) noexcept { auto t = *this; ++*this; return t; }
    constexpr bool operator==(std::default_sentinel_t) const noexcept { return step_ == 0; }

   private:
    constexpr void load() noexcept {
      step_ = 0;
      if (rest_.empty()) return;
      const u8 t = u8(rest_[0]);
      if (t == 0) { cur_ = {0, {}}; step_ = 1; return; }
      if (rest_.size() < 2 || std::size_t(u8(rest_[1])) + 2 > rest_.size()) return;
      cur_ = {t, rest_.subspan(2, u8(rest_[1]))};
      step_ = 2 + std::size_t(u8(rest_[1]));
    }
    bytes rest_{};
    ipv6_option cur_{};
    std::size_t step_ = 0;
  };
  constexpr iterator begin() const noexcept { return iterator(b_); }
  constexpr std::default_sentinel_t end() const noexcept { return {}; }

 private:
  bytes b_;
};

/// One extension header in the chain: `type` is the protocol number that announced it.
class ipv6_ext_view {
 public:
  constexpr ipv6_ext_view(u8 type, bytes h) noexcept : type_(type), h_(h) {}
  constexpr u8 type() const noexcept { return type_; }
  constexpr u8 next_header() const noexcept { return u8(h_[0]); }
  constexpr bytes header() const noexcept { return h_; }
  constexpr std::size_t size() const noexcept { return h_.size(); }
  constexpr std::optional<ipv6_fragment_view> fragment() const noexcept {
    if (type_ != ip_proto::ipv6_frag) return std::nullopt;
    return ipv6_fragment_view(h_.data());
  }
  constexpr std::optional<ipv6_routing_view> routing() const noexcept {
    if (type_ != ip_proto::ipv6_route) return std::nullopt;
    return ipv6_routing_view(h_.data(), h_.size());
  }
  /// Hop-by-Hop / Destination Options TLVs (empty range for other header types).
  constexpr ipv6_options options() const noexcept {
    if (type_ != ip_proto::hopopt && type_ != ip_proto::ipv6_opts) return ipv6_options({});
    return ipv6_options(h_.subspan(2));
  }

  /// Size of the extension header starting at `b` announced as `type`, or 0 when it does not fit.
  static constexpr std::size_t length_of(u8 type, bytes b) noexcept {
    if (b.size() < 2) return 0;
    std::size_t n;
    if (type == ip_proto::ipv6_frag) n = 8;
    else if (type == ip_proto::ah) n = (std::size_t(u8(b[1])) + 2) * 4;
    else n = (std::size_t(u8(b[1])) + 1) * 8;
    return n <= b.size() ? n : 0;
  }

 private:
  u8 type_;
  bytes h_;
};

/// Zero-copy walk of the extension-header chain that follows a 40-byte IPv6 header. Bounded
/// (at most 64 headers) and bounds-checked; stops at the first non-extension next-header.
class ipv6_ext_range {
 public:
  constexpr ipv6_ext_range(u8 first_nh, bytes after_base) noexcept : nh_(first_nh), b_(after_base) {}
  class iterator {
   public:
    using value_type = ipv6_ext_view;
    using difference_type = std::ptrdiff_t;
    constexpr iterator() = default;
    constexpr iterator(u8 nh, bytes rest) noexcept : nh_(nh), rest_(rest) { load(); }
    constexpr ipv6_ext_view operator*() const noexcept { return ipv6_ext_view(nh_, rest_.first(len_)); }
    constexpr iterator& operator++() noexcept {
      const bool stop = (nh_ == ip_proto::ipv6_frag && (detail::be16(rest_.data() + 2) & 0xfff8) != 0);
      nh_ = u8(rest_[0]);
      rest_ = rest_.subspan(len_);
      ++count_;
      if (stop) len_ = 0;
      else load();
      return *this;
    }
    constexpr iterator operator++(int) noexcept { auto t = *this; ++*this; return t; }
    constexpr bool operator==(std::default_sentinel_t) const noexcept { return len_ == 0; }

   private:
    constexpr void load() noexcept {
      len_ = (count_ < 64 && is_ipv6_extension(nh_)) ? ipv6_ext_view::length_of(nh_, rest_) : 0;
    }
    u8 nh_ = 0;
    bytes rest_{};
    std::size_t len_ = 0;
    unsigned count_ = 0;
  };
  constexpr iterator begin() const noexcept { return iterator(nh_, b_); }
  constexpr std::default_sentinel_t end() const noexcept { return {}; }

  /// Where the chain ends: the upper-layer protocol number and its offset relative to the start
  /// of `after_base`. `complete` is false when a header was truncated / the walk was cut.
  struct tail {
    u8 protocol;
    std::size_t offset;
    bool complete;
  };
  constexpr tail upper_layer() const noexcept {
    u8 nh = nh_;
    std::size_t off = 0;
    for (unsigned k = 0; k < 64 && is_ipv6_extension(nh); ++k) {
      const std::size_t n = ipv6_ext_view::length_of(nh, b_.subspan(off));
      if (n == 0) return {nh, off, false};
      const bool non_first_frag = (nh == ip_proto::ipv6_frag && (detail::be16(b_.data() + off + 2) & 0xfff8) != 0);
      nh = u8(b_[off]);
      off += n;
      if (non_first_frag) return {nh, off, true};
    }
    return {nh, off, !is_ipv6_extension(nh)};
  }

 private:
  u8 nh_;
  bytes b_;
};

class ipv6_view {
 public:
  static constexpr std::size_t min_size = 40;
  /// Validates once: >= 40 bytes and version 6.
  static constexpr std::optional<ipv6_view> parse(bytes b) noexcept {
    if (b.size() < min_size || (u8(b[0]) >> 4) != 6) return std::nullopt;
    return ipv6_view(b.data(), b.size());
  }
  constexpr ipv6_view(const std::byte* p, std::size_t n) noexcept : p_(p), n_(n) {}  // unchecked

  constexpr u8 version() const noexcept { return field<wire::ipv6_hdr, "version">(p_); }
  constexpr u8 traffic_class() const noexcept { return field<wire::ipv6_hdr, "traffic_class">(p_); }
  constexpr u32 flow_label() const noexcept { return field<wire::ipv6_hdr, "flow_label">(p_); }
  constexpr u16 payload_length() const noexcept { return field<wire::ipv6_hdr, "payload_length">(p_); }
  constexpr u8 next_header() const noexcept { return u8(p_[6]); }
  constexpr u8 hop_limit() const noexcept { return u8(p_[7]); }
  constexpr ipv6_addr src() const noexcept { return detail::load_array<16>(p_ + 8); }
  constexpr ipv6_addr dst() const noexcept { return detail::load_array<16>(p_ + 24); }
  constexpr bytes header() const noexcept { return {p_, 40}; }

  /// Everything after the 40-byte header (extension headers + upper layer), bounded by
  /// payload_length and the captured bytes (payload_length 0 = jumbogram: to the end).
  constexpr bytes payload() const noexcept {
    const std::size_t pl = payload_length();
    const std::size_t end = (pl != 0 && 40 + pl <= n_) ? 40 + pl : n_;
    return {p_ + 40, end - 40};
  }
  constexpr bool truncated() const noexcept { return 40 + std::size_t(payload_length()) > n_; }
  constexpr ipv6_ext_range extensions() const noexcept { return ipv6_ext_range(next_header(), payload()); }
  /// The Fragment header, if the chain has one.
  constexpr std::optional<ipv6_fragment_view> fragment() const noexcept {
    for (auto e : extensions())
      if (auto f = e.fragment()) return f;
    return std::nullopt;
  }
  /// Upper-layer protocol after the chain, and its bytes.
  constexpr u8 upper_protocol() const noexcept { return extensions().upper_layer().protocol; }
  constexpr bytes upper_payload() const noexcept {
    const auto t = extensions().upper_layer();
    return payload().subspan(t.offset);
  }

 private:
  const std::byte* p_;
  std::size_t n_;
};

// ---------------------------------------------------------------------------------------------
// builders
// ---------------------------------------------------------------------------------------------

/// IPv4 header. total_length, ihl and checksum are derived (nanom computed fields) unless
/// overridden; `protocol` defaults to the next layer's (17 before udp{}, 6 before tcp{}).
/// `options` are raw option bytes, zero-padded (EOL) to a multiple of 4 (max 40).
struct ipv4 {
  ipv4_addr src{};
  ipv4_addr dst{};
  u8 ttl = 64;
  u8 dscp = 0;
  u8 ecn = 0;
  u16 id = 0;
  bool df = false;
  bool mf = false;
  u16 frag_offset = 0;  // 8-byte units
  std::optional<u8> protocol{};
  bytes options{};
  std::optional<u16> total_length{};  // override (e.g. to craft a malformed datagram)
  std::optional<u16> checksum{};      // override

  constexpr std::size_t options_size() const noexcept { return (options.size() + 3) & ~std::size_t(3); }
  constexpr std::size_t size() const noexcept { return 20 + options_size(); }
  static constexpr u16 ethertype() noexcept { return nanowire::ethertype::ipv4; }
  constexpr bool write(std::byte* p, const build_ctx& c) const noexcept {
    const std::size_t on = options_size();
    if (on > 40 || dscp > 63 || ecn > 3 || frag_offset > 0x1fff) return false;
    for (std::size_t i = 0; i < on; ++i) p[20 + i] = i < options.size() ? options[i] : std::byte{0};
    wire::ipv4_hdr h{};
    h.version = 4;
    h.ihl = u8(size() / 4);
    h.dscp = dscp;
    h.ecn = ecn;
    h.identification = id;
    h.df = u8(df);
    h.mf = u8(mf);
    h.frag_offset = frag_offset;
    h.ttl = ttl;
    h.protocol = protocol ? *protocol : c.next_ip_proto;
    h.src = src;
    h.dst = dst;
    if (!total_length && c.after > 0xffffu - (20 + on)) return false;
    if (emit_wire(h, p, total_length ? bytes(p + 20, on) : bytes(p + 20, on + c.after)) != 20) return false;
    if (total_length) {
      detail::put_be16(p + 2, *total_length);
      if (!checksum) {
        detail::put_be16(p + 10, 0);
        detail::put_be16(p + 10, detail::internet_checksum(bytes(p, 20 + on)));
      }
    }
    if (checksum) detail::put_be16(p + 10, *checksum);
    return true;
  }
};

/// IPv6 header. payload_length and next_header are derived unless overridden.
struct ipv6 {
  ipv6_addr src{};
  ipv6_addr dst{};
  u8 traffic_class = 0;
  u32 flow_label = 0;
  u8 hop_limit = 64;
  std::optional<u8> next_header{};
  std::optional<u16> payload_length{};

  static constexpr std::size_t size() noexcept { return 40; }
  static constexpr u16 ethertype() noexcept { return nanowire::ethertype::ipv6; }
  constexpr bool write(std::byte* p, const build_ctx& c) const noexcept {
    if (flow_label > 0xfffff || (c.after > 0xffff && !payload_length)) return false;
    wire::ipv6_hdr h{};
    h.version = 6;
    h.traffic_class = traffic_class;
    h.flow_label = flow_label;
    h.payload_length = payload_length ? *payload_length : u16(c.after);
    h.next_header = next_header ? *next_header : (c.has_next_ip_proto ? c.next_ip_proto : ip_proto::no_next);
    h.hop_limit = hop_limit;
    h.src = src;
    h.dst = dst;
    return emit_wire(h, p) == 40;
  }
};

/// IPv6 Fragment extension header.
struct ipv6_frag {
  u16 offset = 0;  // 8-byte units
  bool more = false;
  u32 id = 0;
  std::optional<u8> next_header{};

  static constexpr std::size_t size() noexcept { return 8; }
  static constexpr u8 ip_protocol() noexcept { return ip_proto::ipv6_frag; }
  constexpr bool write(std::byte* p, const build_ctx& c) const noexcept {
    if (offset > 0x1fff) return false;
    wire::ipv6_frag_hdr h{next_header ? *next_header : (c.has_next_ip_proto ? c.next_ip_proto : ip_proto::no_next), 0,
                          {offset}, {0}, {u8(more)}, id};
    return emit_wire(h, p) == 8;
  }
};

namespace detail {
/// Hop-by-Hop / Destination Options header body: options then PadN/Pad1 to a multiple of 8.
constexpr std::size_t opts_ext_size(bytes options) noexcept { return (2 + options.size() + 7) & ~std::size_t(7); }
constexpr bool write_opts_ext(std::byte* p, u8 nh, bytes options) noexcept {
  const std::size_t n = opts_ext_size(options);
  if (n > 2048) return false;
  p[0] = std::byte(nh);
  p[1] = std::byte(n / 8 - 1);
  for (std::size_t i = 0; i < options.size(); ++i) p[2 + i] = options[i];
  std::size_t pad = n - 2 - options.size(), at = 2 + options.size();
  if (pad == 1) {
    p[at] = std::byte{0};  // Pad1
  } else if (pad >= 2) {
    p[at] = std::byte{1};  // PadN
    p[at + 1] = std::byte(pad - 2);
    for (std::size_t i = 2; i < pad; ++i) p[at + i] = std::byte{0};
  }
  return true;
}
}  // namespace detail

/// Hop-by-Hop Options header (raw option TLVs, padded with Pad1/PadN to 8-byte units).
struct ipv6_hbh {
  bytes options{};
  std::optional<u8> next_header{};
  constexpr std::size_t size() const noexcept { return detail::opts_ext_size(options); }
  static constexpr u8 ip_protocol() noexcept { return ip_proto::hopopt; }
  constexpr bool write(std::byte* p, const build_ctx& c) const noexcept {
    return detail::write_opts_ext(
        p, next_header ? *next_header : (c.has_next_ip_proto ? c.next_ip_proto : ip_proto::no_next), options);
  }
};
/// Destination Options header.
struct ipv6_dstopts {
  bytes options{};
  std::optional<u8> next_header{};
  constexpr std::size_t size() const noexcept { return detail::opts_ext_size(options); }
  static constexpr u8 ip_protocol() noexcept { return ip_proto::ipv6_opts; }
  constexpr bool write(std::byte* p, const build_ctx& c) const noexcept {
    return detail::write_opts_ext(
        p, next_header ? *next_header : (c.has_next_ip_proto ? c.next_ip_proto : ip_proto::no_next), options);
  }
};

/// SRv6 Segment Routing Header (Routing type 4). `segments` in wire order (segments[0] is the
/// final segment). last_entry defaults to segments.size() - 1.
struct ipv6_srh {
  std::span<const ipv6_addr> segments{};
  u8 segments_left = 0;
  u8 flags = 0;
  u16 tag = 0;
  std::optional<u8> last_entry{};
  std::optional<u8> next_header{};
  constexpr std::size_t size() const noexcept { return 8 + 16 * segments.size(); }
  static constexpr u8 ip_protocol() noexcept { return ip_proto::ipv6_route; }
  constexpr bool write(std::byte* p, const build_ctx& c) const noexcept {
    if (segments.empty() || segments.size() > 127) return false;
    wire::ipv6_srh_hdr h{next_header ? *next_header : (c.has_next_ip_proto ? c.next_ip_proto : ip_proto::no_next),
                         u8(segments.size() * 2),
                         4,
                         segments_left,
                         last_entry ? *last_entry : u8(segments.size() - 1),
                         flags,
                         tag};
    if (emit_wire(h, p) != 8) return false;
    for (std::size_t i = 0; i < segments.size(); ++i) detail::store_array(p + 8 + 16 * i, segments[i]);
    return true;
  }
};

}  // namespace nanowire

#endif  // NANOWIRE_IP_HPP_INCLUDED
