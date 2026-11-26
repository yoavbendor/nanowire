// SPDX-License-Identifier: Apache-2.0
// nanowire/someip_sd.hpp — SOME/IP Service Discovery (AUTOSAR PRS_SOMEIPServiceDiscovery): the SD
// header, entries (service / eventgroup) and options (configuration, load balancing, IPv4 / IPv6
// endpoint, multicast and SD-endpoint).
//
//   wire::sd_header / sd_service_entry / sd_eventgroup_entry / sd_options_length /
//   sd_option_hdr / sd_ipv4_option / sd_ipv6_option / sd_load_balancing_option   layouts
//   sd_view, sd_entry_view, sd_option_view, sd_entries, sd_options,
//   sd_config_items                                                    zero-copy readers / ranges
//   someip_sd (+ someip_sd_header())                                   builder: a whole SD payload
//   sd_header, sd_service_entry, sd_eventgroup_entry, sd_options_length,
//   sd_ipv4_option, sd_ipv6_option, sd_load_balancing_option           fixed-size builders, one per
//                                                                      wire struct (frame templates)
//   sd_entry, sd_option                                                runtime-typed conveniences
//
// The fixed-size layers stack like any others:
//   someip_sd_header(7), sd_header{}, sd_service_entry::offer_service(0x1234, 1, 1, 0).with_options(0, 1),
//   sd_options_length{}, sd_ipv4_option::endpoint(ip4("10.0.0.1"), ip_proto::udp, 30501)
// sd_header's entries_length covers the entry layers right after it; sd_options_length covers
// everything after it.
//
// An SD message is a SOME/IP message with Message ID 0xFFFF8100; its payload is
//   [flags:8][reserved:24][entries_length:32][entries: n * 16][options_length:32][options]
// Each entry references options by two runs (index_1, num_options_1) / (index_2, num_options_2)
// into the message's option array; sd_view::for_each_option(entry, f) resolves them.
#ifndef NANOWIRE_SOMEIP_SD_HPP_INCLUDED
#define NANOWIRE_SOMEIP_SD_HPP_INCLUDED

#include <nanowire/someip.hpp>

namespace nanowire::wire {
struct sd_header {
  u8 flags;
  std::array<u8, 3> reserved;
  nm::be<u32> entries_length;
};
struct sd_service_entry {
  u8 type, index_1, index_2;
  nm::ubits<4> num_options_1, num_options_2;
  nm::be<u16> service_id, instance_id;
  u8 major_version;
  nm::ubits<24> ttl;
  nm::be<u32> minor_version;
};
struct sd_eventgroup_entry {
  u8 type, index_1, index_2;
  nm::ubits<4> num_options_1, num_options_2;
  nm::be<u16> service_id, instance_id;
  u8 major_version;
  nm::ubits<24> ttl;
  nm::ubits<12> reserved;  // legacy: bit 7 of the second byte = Initial Data Requested
  nm::ubits<4> counter;
  nm::be<u16> eventgroup_id;
};
struct sd_options_length {  // the word between the entries array and the options array
  nm::be<u32> length;
};
struct sd_option_hdr {
  nm::be<u16> length;  // bytes after the type octet (the reserved octet included)
  u8 type;
  u8 reserved;  // bit 7: discardable flag
};
struct sd_ipv4_option {  // endpoint / multicast / SD endpoint (length 9)
  nm::be<u16> length;
  u8 type, reserved;
  std::array<u8, 4> address;
  u8 reserved2, l4_proto;
  nm::be<u16> port;
};
struct sd_ipv6_option {  // length 21
  nm::be<u16> length;
  u8 type, reserved;
  std::array<u8, 16> address;
  u8 reserved2, l4_proto;
  nm::be<u16> port;
};
struct sd_load_balancing_option {  // length 5
  nm::be<u16> length;
  u8 type, reserved;
  nm::be<u16> priority, weight;
};
}  // namespace nanowire::wire

NANOM_DESCRIBE(nanowire::wire::sd_header, flags, reserved, entries_length);
NANOM_DESCRIBE(nanowire::wire::sd_service_entry, type, index_1, index_2, num_options_1, num_options_2, service_id,
               instance_id, major_version, ttl, minor_version);
NANOM_DESCRIBE(nanowire::wire::sd_eventgroup_entry, type, index_1, index_2, num_options_1, num_options_2, service_id,
               instance_id, major_version, ttl, reserved, counter, eventgroup_id);
NANOM_DESCRIBE(nanowire::wire::sd_options_length, length);
NANOM_DESCRIBE(nanowire::wire::sd_option_hdr, length, type, reserved);
NANOM_DESCRIBE(nanowire::wire::sd_ipv4_option, length, type, reserved, address, reserved2, l4_proto, port);
NANOM_DESCRIBE(nanowire::wire::sd_ipv6_option, length, type, reserved, address, reserved2, l4_proto, port);
NANOM_DESCRIBE(nanowire::wire::sd_load_balancing_option, length, type, reserved, priority, weight);

namespace nanowire {

static_assert(nm::wire_size_v<wire::sd_header> == 8 && nm::wire_size_v<wire::sd_service_entry> == 16 &&
              nm::wire_size_v<wire::sd_eventgroup_entry> == 16 && nm::wire_size_v<wire::sd_ipv4_option> == 12 &&
              nm::wire_size_v<wire::sd_ipv6_option> == 24 && nm::wire_size_v<wire::sd_load_balancing_option> == 8 &&
              nm::wire_size_v<wire::sd_options_length> == 4);

namespace sd_flag {
inline constexpr u8 reboot = 0x80, unicast = 0x40, explicit_initial_data_control = 0x20;
}
namespace sd_entry_type {
inline constexpr u8 find_service = 0x00, offer_service = 0x01, subscribe_eventgroup = 0x06,
                    subscribe_eventgroup_ack = 0x07;
}
namespace sd_option_type {
inline constexpr u8 configuration = 0x01, load_balancing = 0x02, ipv4_endpoint = 0x04, ipv6_endpoint = 0x06,
                    ipv4_multicast = 0x14, ipv6_multicast = 0x16, ipv4_sd_endpoint = 0x24, ipv6_sd_endpoint = 0x26;
}

/// One SD entry (16 bytes). Service entries (types 0, 1) carry minor_version; eventgroup
/// entries (types 6, 7) carry counter + eventgroup_id in the last word.
class sd_entry_view {
 public:
  static constexpr std::size_t size = 16;
  constexpr explicit sd_entry_view(const std::byte* p) noexcept : p_(p) {}
  constexpr u8 type() const noexcept { return u8(p_[0]); }
  constexpr bool is_service() const noexcept { return type() <= 0x01; }
  constexpr bool is_eventgroup() const noexcept { return type() == 0x06 || type() == 0x07; }
  constexpr u8 index_1() const noexcept { return u8(p_[1]); }
  constexpr u8 index_2() const noexcept { return u8(p_[2]); }
  constexpr u8 num_options_1() const noexcept { return field<wire::sd_service_entry, "num_options_1">(p_); }
  constexpr u8 num_options_2() const noexcept { return field<wire::sd_service_entry, "num_options_2">(p_); }
  constexpr u16 service_id() const noexcept { return field<wire::sd_service_entry, "service_id">(p_); }
  constexpr u16 instance_id() const noexcept { return field<wire::sd_service_entry, "instance_id">(p_); }
  constexpr u8 major_version() const noexcept { return u8(p_[8]); }
  constexpr u32 ttl() const noexcept { return field<wire::sd_service_entry, "ttl">(p_); }
  /// TTL 0 turns Offer into StopOffer, Subscribe into StopSubscribe, Ack into Nack.
  constexpr bool is_stop() const noexcept { return ttl() == 0; }
  constexpr u32 minor_version() const noexcept { return field<wire::sd_service_entry, "minor_version">(p_); }
  constexpr u8 counter() const noexcept { return field<wire::sd_eventgroup_entry, "counter">(p_); }
  constexpr u16 eventgroup_id() const noexcept { return field<wire::sd_eventgroup_entry, "eventgroup_id">(p_); }
  constexpr bool initial_data_requested() const noexcept { return (u8(p_[13]) & 0x80) != 0; }
  constexpr bytes raw() const noexcept { return {p_, size}; }

 private:
  const std::byte* p_;
};

/// A decoded endpoint / multicast / SD-endpoint option.
struct sd_endpoint {
  u8 option_type;
  bool is_v6;
  ipv4_addr v4;  // valid when !is_v6
  ipv6_addr v6;  // valid when is_v6
  u8 l4_proto;   // 6 TCP, 17 UDP
  u16 port;
};
struct sd_load_balancing {
  u16 priority;
  u16 weight;
};

/// Items of a configuration option: a sequence of [len:8][chars] strings ending with a 0 length.
/// Each item is typically "key=value" (or "key" alone); sd_config_items yields the raw string.
class sd_config_items {
 public:
  constexpr explicit sd_config_items(bytes b) noexcept : b_(b) {}
  class iterator {
   public:
    using value_type = std::string_view;
    using difference_type = std::ptrdiff_t;
    constexpr iterator() = default;
    constexpr explicit iterator(bytes rest) noexcept : rest_(rest) { load(); }
    std::string_view operator*() const noexcept {
      return {reinterpret_cast<const char*>(rest_.data() + 1), step_ - 1};
    }
    constexpr iterator& operator++() noexcept { rest_ = rest_.subspan(step_); load(); return *this; }
    constexpr iterator operator++(int) noexcept { auto t = *this; ++*this; return t; }
    constexpr bool operator==(std::default_sentinel_t) const noexcept { return step_ == 0; }

   private:
    constexpr void load() noexcept {
      step_ = 0;
      if (rest_.empty() || u8(rest_[0]) == 0 || std::size_t(u8(rest_[0])) + 1 > rest_.size()) return;
      step_ = std::size_t(u8(rest_[0])) + 1;
    }
    bytes rest_{};
    std::size_t step_ = 0;
  };
  constexpr iterator begin() const noexcept { return iterator(b_); }
  constexpr std::default_sentinel_t end() const noexcept { return {}; }
  /// Key and value of an item ("key=value" -> {"key","value"}; "key" -> {"key",""}).
  static constexpr std::pair<std::string_view, std::string_view> split(std::string_view item) noexcept {
    const auto eq = item.find('=');
    if (eq == std::string_view::npos) return {item, {}};
    return {item.substr(0, eq), item.substr(eq + 1)};
  }

 private:
  bytes b_;
};

/// One SD option: [length:16][type:8][reserved:8][body: length-1 bytes].
class sd_option_view {
 public:
  constexpr explicit sd_option_view(bytes whole) noexcept : b_(whole) {}  // whole = 3 + length bytes
  constexpr u16 length() const noexcept { return detail::be16(b_.data()); }
  constexpr u8 type() const noexcept { return u8(b_[2]); }
  constexpr u8 reserved() const noexcept { return b_.size() > 3 ? u8(b_[3]) : 0; }
  constexpr bool discardable() const noexcept { return (reserved() & 0x80) != 0; }
  /// Bytes after the reserved octet.
  constexpr bytes body() const noexcept { return b_.size() > 4 ? b_.subspan(4) : bytes{}; }
  constexpr bytes raw() const noexcept { return b_; }

  constexpr bool is_endpoint_like() const noexcept {
    const u8 t = type();
    return t == 0x04 || t == 0x06 || t == 0x14 || t == 0x16 || t == 0x24 || t == 0x26;
  }
  /// IPv4 / IPv6 endpoint, multicast or SD-endpoint option with the expected length.
  constexpr std::optional<sd_endpoint> endpoint() const noexcept {
    const u8 t = type();
    const bool v4 = t == 0x04 || t == 0x14 || t == 0x24, v6 = t == 0x06 || t == 0x16 || t == 0x26;
    if (v4 && length() == 9 && b_.size() == 12) {
      const std::byte* p = b_.data();
      return sd_endpoint{t, false, detail::load_array<4>(p + 4), {}, field<wire::sd_ipv4_option, "l4_proto">(p),
                         field<wire::sd_ipv4_option, "port">(p)};
    }
    if (v6 && length() == 21 && b_.size() == 24) {
      const std::byte* p = b_.data();
      return sd_endpoint{t, true, {}, detail::load_array<16>(p + 4), field<wire::sd_ipv6_option, "l4_proto">(p),
                         field<wire::sd_ipv6_option, "port">(p)};
    }
    return std::nullopt;
  }
  constexpr std::optional<sd_load_balancing> load_balancing() const noexcept {
    if (type() != sd_option_type::load_balancing || length() != 5 || b_.size() != 8) return std::nullopt;
    return sd_load_balancing{field<wire::sd_load_balancing_option, "priority">(b_.data()),
                             field<wire::sd_load_balancing_option, "weight">(b_.data())};
  }
  /// Configuration option items (empty range for other option types).
  constexpr sd_config_items configuration() const noexcept {
    return sd_config_items(type() == sd_option_type::configuration ? body() : bytes{});
  }

 private:
  bytes b_;
};

/// Fixed-stride range over the entries array.
class sd_entries {
 public:
  constexpr explicit sd_entries(bytes b) noexcept : b_(b) {}
  class iterator {
   public:
    using value_type = sd_entry_view;
    using difference_type = std::ptrdiff_t;
    constexpr iterator() = default;
    constexpr iterator(const std::byte* p, const std::byte* e) noexcept : p_(p), e_(e) {}
    constexpr sd_entry_view operator*() const noexcept { return sd_entry_view(p_); }
    constexpr iterator& operator++() noexcept { p_ += 16; return *this; }
    constexpr iterator operator++(int) noexcept { auto t = *this; ++*this; return t; }
    constexpr bool operator==(std::default_sentinel_t) const noexcept { return e_ - p_ < 16; }

   private:
    const std::byte* p_ = nullptr;
    const std::byte* e_ = nullptr;
  };
  constexpr iterator begin() const noexcept { return iterator(b_.data(), b_.data() + b_.size()); }
  constexpr std::default_sentinel_t end() const noexcept { return {}; }
  constexpr std::size_t size() const noexcept { return b_.size() / 16; }
  constexpr sd_entry_view operator[](std::size_t i) const noexcept { return sd_entry_view(b_.data() + 16 * i); }

 private:
  bytes b_;
};

/// Variable-length range over the options array. Stops at an option that does not fit
/// (well_formed() then reports false).
class sd_options {
 public:
  constexpr explicit sd_options(bytes b) noexcept : b_(b) {}
  class iterator {
   public:
    using value_type = sd_option_view;
    using difference_type = std::ptrdiff_t;
    constexpr iterator() = default;
    constexpr explicit iterator(bytes rest) noexcept : rest_(rest) { step_ = next_size(rest_); }
    constexpr sd_option_view operator*() const noexcept { return sd_option_view(rest_.first(step_)); }
    constexpr iterator& operator++() noexcept { rest_ = rest_.subspan(step_); step_ = next_size(rest_); return *this; }
    constexpr iterator operator++(int) noexcept { auto t = *this; ++*this; return t; }
    constexpr bool operator==(std::default_sentinel_t) const noexcept { return step_ == 0; }

   private:
    bytes rest_{};
    std::size_t step_ = 0;
  };
  constexpr iterator begin() const noexcept { return iterator(b_); }
  constexpr std::default_sentinel_t end() const noexcept { return {}; }
  constexpr std::size_t count() const noexcept {
    std::size_t c = 0;
    for (bytes r = b_; std::size_t n = next_size(r); r = r.subspan(n)) ++c;
    return c;
  }
  constexpr bool well_formed() const noexcept {
    bytes r = b_;
    while (std::size_t n = next_size(r)) r = r.subspan(n);
    return r.empty();
  }
  /// The i-th option (linear walk).
  constexpr std::optional<sd_option_view> operator[](std::size_t i) const noexcept {
    for (auto o : *this)
      if (i-- == 0) return o;
    return std::nullopt;
  }
  static constexpr std::size_t next_size(bytes r) noexcept {
    if (r.size() < 3) return 0;
    const std::size_t n = 3 + std::size_t(detail::be16(r.data()));
    return n <= r.size() ? n : 0;
  }

 private:
  bytes b_;
};

/// The SD payload of one SOME/IP-SD message.
class sd_view {
 public:
  /// `payload` = the SOME/IP payload (after the 16-byte header). Validates once: the 8-byte SD
  /// header, the whole entries array and the options-length field are present. The options
  /// region is clamped to the available bytes (options_truncated() tells).
  static constexpr std::optional<sd_view> parse(bytes payload) noexcept {
    if (payload.size() < 12) return std::nullopt;
    const std::size_t el = detail::be32(payload.data() + 4);
    if (el > payload.size() - 12) return std::nullopt;
    return sd_view(payload, el);
  }
  /// From a whole SOME/IP message; nullopt unless it is an SD message (0xFFFF / 0x8100).
  static constexpr std::optional<sd_view> parse(const someip_view& m) noexcept {
    if (!m.is_sd() || m.is_tp()) return std::nullopt;
    return parse(m.payload());
  }

  constexpr u8 flags() const noexcept { return u8(b_[0]); }
  constexpr bool reboot() const noexcept { return (flags() & sd_flag::reboot) != 0; }
  constexpr bool unicast() const noexcept { return (flags() & sd_flag::unicast) != 0; }
  constexpr bool explicit_initial_data_control() const noexcept {
    return (flags() & sd_flag::explicit_initial_data_control) != 0;
  }
  constexpr u32 entries_length() const noexcept { return u32(el_); }
  constexpr u32 options_length() const noexcept { return detail::be32(b_.data() + 8 + el_); }
  constexpr sd_entries entries() const noexcept { return sd_entries(b_.subspan(8, el_)); }
  constexpr sd_options options() const noexcept {
    const bytes rest = b_.subspan(12 + el_);
    const std::size_t ol = options_length();
    return sd_options(rest.first(ol < rest.size() ? ol : rest.size()));
  }
  constexpr bool options_truncated() const noexcept { return options_length() > b_.size() - 12 - el_; }
  /// Entries array length is a multiple of 16, options fit and parse exactly.
  constexpr bool well_formed() const noexcept {
    return el_ % 16 == 0 && !options_truncated() && options().well_formed();
  }

  /// Call f(sd_option_view, int run) for every option entry `e` references (run 1 or 2), in
  /// option-array order; one walk over the options array.
  template <class F>
  constexpr void for_each_option(const sd_entry_view& e, F&& f) const {
    const std::size_t a1 = e.index_1(), n1 = e.num_options_1(), a2 = e.index_2(), n2 = e.num_options_2();
    std::size_t i = 0;
    for (auto o : options()) {
      if (i >= a1 && i < a1 + n1) f(o, 1);
      if (i >= a2 && i < a2 + n2) f(o, 2);
      ++i;
    }
  }

 private:
  constexpr sd_view(bytes b, std::size_t el) noexcept : b_(b), el_(el) {}
  bytes b_;
  std::size_t el_;
};

// ---------------------------------------------------------------------------------------------
// builders
// ---------------------------------------------------------------------------------------------

/// The 8-byte SD header [flags:8][reserved:24][entries_length:32]. entries_length is derived: the
/// bytes of the entry layers (sd_service_entry / sd_eventgroup_entry / sd_entry) right after it in
/// the frame; set `entries_length` to override (entries carried as raw bytes, malformed lengths).
struct sd_header {
  u8 flags = sd_flag::reboot | sd_flag::unicast;
  std::optional<u32> entries_length{};
  std::array<u8, 3> reserved{};

  static constexpr std::size_t size() noexcept { return 8; }
  constexpr bool write(std::byte* p, const build_ctx& c = {}) const noexcept {
    const std::size_t el = entries_length ? *entries_length : c.sd_entries_after;
    if (el > 0xFFFFFFFFu) return false;
    return emit_wire(wire::sd_header{flags, reserved, u32(el)}, p) == 8;
  }
};

/// A service entry (FindService 0x00, OfferService / StopOffer 0x01), wire::sd_service_entry.
struct sd_service_entry {
  u8 type = sd_entry_type::offer_service;
  u8 index_1 = 0, index_2 = 0, num_options_1 = 0, num_options_2 = 0;
  u16 service_id = 0;
  u16 instance_id = 0xFFFF;
  u8 major_version = 0xFF;
  u32 ttl = 0xFFFFFF;  // 24 bits; 0 = StopOffer
  u32 minor_version = 0xFFFFFFFF;

  static constexpr bool sd_entry_layer = true;
  static constexpr sd_service_entry find_service(u16 svc, u16 inst = 0xFFFF, u8 major = 0xFF,
                                                 u32 minor = 0xFFFFFFFF, u32 ttl = 0xFFFFFF) noexcept {
    return {sd_entry_type::find_service, 0, 0, 0, 0, svc, inst, major, ttl, minor};
  }
  static constexpr sd_service_entry offer_service(u16 svc, u16 inst, u8 major, u32 minor, u32 ttl = 0xFFFFFF) noexcept {
    return {sd_entry_type::offer_service, 0, 0, 0, 0, svc, inst, major, ttl, minor};
  }
  static constexpr sd_service_entry stop_offer_service(u16 svc, u16 inst, u8 major, u32 minor) noexcept {
    return offer_service(svc, inst, major, minor, 0);
  }
  /// Reference options [first, first+count) as run 1 (and optionally a second run).
  constexpr sd_service_entry& with_options(u8 first, u8 count, u8 first2 = 0, u8 count2 = 0) noexcept {
    index_1 = first, num_options_1 = count, index_2 = first2, num_options_2 = count2;
    return *this;
  }
  static constexpr std::size_t size() noexcept { return 16; }
  constexpr bool write(std::byte* p, const build_ctx& = {}) const noexcept {
    if (num_options_1 > 15 || num_options_2 > 15 || ttl > 0xFFFFFF) return false;
    return emit_wire(wire::sd_service_entry{type, index_1, index_2, {num_options_1}, {num_options_2}, service_id,
                                            instance_id, major_version, {ttl}, minor_version},
                     p) == 16;
  }
};

/// An eventgroup entry (SubscribeEventgroup 0x06, SubscribeEventgroupAck 0x07; TTL 0 = Stop /
/// Nack), wire::sd_eventgroup_entry.
struct sd_eventgroup_entry {
  u8 type = sd_entry_type::subscribe_eventgroup;
  u8 index_1 = 0, index_2 = 0, num_options_1 = 0, num_options_2 = 0;
  u16 service_id = 0;
  u16 instance_id = 0xFFFF;
  u8 major_version = 0xFF;
  u32 ttl = 0xFFFFFF;  // 24 bits
  u8 counter = 0;      // 4 bits
  u16 eventgroup_id = 0;
  bool initial_data_requested = false;  // legacy flag: bit 7 of byte 13 (reserved bit 0x008)
  u16 reserved = 0;                     // the 12 reserved bits as on the wire (OR-ed with the flag)

  static constexpr bool sd_entry_layer = true;
  static constexpr sd_eventgroup_entry subscribe(u16 svc, u16 inst, u8 major, u16 eventgroup, u32 ttl = 0xFFFFFF,
                                                 u8 counter = 0) noexcept {
    return {sd_entry_type::subscribe_eventgroup, 0, 0, 0, 0, svc, inst, major, ttl, counter, eventgroup, false, 0};
  }
  static constexpr sd_eventgroup_entry stop_subscribe(u16 svc, u16 inst, u8 major, u16 eventgroup,
                                                      u8 counter = 0) noexcept {
    return subscribe(svc, inst, major, eventgroup, 0, counter);
  }
  static constexpr sd_eventgroup_entry subscribe_ack(u16 svc, u16 inst, u8 major, u16 eventgroup,
                                                     u32 ttl = 0xFFFFFF, u8 counter = 0) noexcept {
    return {sd_entry_type::subscribe_eventgroup_ack, 0, 0, 0, 0, svc, inst, major, ttl, counter, eventgroup, false, 0};
  }
  static constexpr sd_eventgroup_entry subscribe_nack(u16 svc, u16 inst, u8 major, u16 eventgroup,
                                                      u8 counter = 0) noexcept {
    return subscribe_ack(svc, inst, major, eventgroup, 0, counter);
  }
  constexpr sd_eventgroup_entry& with_options(u8 first, u8 count, u8 first2 = 0, u8 count2 = 0) noexcept {
    index_1 = first, num_options_1 = count, index_2 = first2, num_options_2 = count2;
    return *this;
  }
  static constexpr std::size_t size() noexcept { return 16; }
  constexpr bool write(std::byte* p, const build_ctx& = {}) const noexcept {
    if (num_options_1 > 15 || num_options_2 > 15 || ttl > 0xFFFFFF || counter > 15 || reserved > 0xFFF) return false;
    const u16 res = u16(reserved | (initial_data_requested ? 0x008 : 0));
    return emit_wire(wire::sd_eventgroup_entry{type, index_1, index_2, {num_options_1}, {num_options_2}, service_id,
                                               instance_id, major_version, {ttl}, {res}, {counter}, eventgroup_id},
                     p) == 16;
  }
};

/// One SD entry whose kind is chosen at run time by `type`: eventgroup types (6, 7) are written as
/// an sd_eventgroup_entry, every other type as an sd_service_entry. A convenience for entry
/// arrays (someip_sd{.entries = ...}); for frame templates use the two typed builders.
struct sd_entry {
  u8 type = sd_entry_type::offer_service;
  u8 index_1 = 0, index_2 = 0, num_options_1 = 0, num_options_2 = 0;
  u16 service_id = 0;
  u16 instance_id = 0xFFFF;
  u8 major_version = 0xFF;
  u32 ttl = 0xFFFFFF;
  u32 minor_version = 0xFFFFFFFF;
  u8 counter = 0;
  u16 eventgroup_id = 0;

  static constexpr bool sd_entry_layer = true;
  static constexpr sd_entry find_service(u16 svc, u16 inst = 0xFFFF, u8 major = 0xFF, u32 minor = 0xFFFFFFFF,
                                         u32 ttl = 0xFFFFFF) noexcept {
    return {sd_entry_type::find_service, 0, 0, 0, 0, svc, inst, major, ttl, minor, 0, 0};
  }
  static constexpr sd_entry offer_service(u16 svc, u16 inst, u8 major, u32 minor, u32 ttl = 0xFFFFFF) noexcept {
    return {sd_entry_type::offer_service, 0, 0, 0, 0, svc, inst, major, ttl, minor, 0, 0};
  }
  static constexpr sd_entry subscribe(u16 svc, u16 inst, u8 major, u16 eventgroup, u32 ttl = 0xFFFFFF,
                                      u8 counter = 0) noexcept {
    return {sd_entry_type::subscribe_eventgroup, 0, 0, 0, 0, svc, inst, major, ttl, 0, counter, eventgroup};
  }
  static constexpr sd_entry subscribe_ack(u16 svc, u16 inst, u8 major, u16 eventgroup, u32 ttl = 0xFFFFFF,
                                          u8 counter = 0) noexcept {
    return {sd_entry_type::subscribe_eventgroup_ack, 0, 0, 0, 0, svc, inst, major, ttl, 0, counter, eventgroup};
  }
  /// Reference options [first, first+count) as run 1 (and optionally a second run).
  constexpr sd_entry& with_options(u8 first, u8 count, u8 first2 = 0, u8 count2 = 0) noexcept {
    index_1 = first, num_options_1 = count, index_2 = first2, num_options_2 = count2;
    return *this;
  }

  constexpr bool is_eventgroup() const noexcept {
    return type == sd_entry_type::subscribe_eventgroup || type == sd_entry_type::subscribe_eventgroup_ack;
  }
  /// The typed builders this entry is written as.
  constexpr sd_service_entry as_service() const noexcept {
    return {type, index_1, index_2, num_options_1, num_options_2, service_id, instance_id, major_version, ttl,
            minor_version};
  }
  constexpr sd_eventgroup_entry as_eventgroup() const noexcept {
    return {type, index_1, index_2, num_options_1, num_options_2, service_id, instance_id, major_version, ttl,
            counter, eventgroup_id, false, 0};
  }

  static constexpr std::size_t size() noexcept { return 16; }
  constexpr bool write(std::byte* p, const build_ctx& c = {}) const noexcept {
    if (counter > 15) return false;
    return is_eventgroup() ? as_eventgroup().write(p, c) : as_service().write(p, c);
  }
};

/// The options-array length word; `length` defaults to every byte after it in the frame (the
/// option layers that follow).
struct sd_options_length {
  std::optional<u32> length{};
  static constexpr std::size_t size() noexcept { return 4; }
  constexpr bool write(std::byte* p, const build_ctx& c = {}) const noexcept {
    if (!length && c.after > 0xFFFFFFFFu) return false;
    return emit_wire(wire::sd_options_length{length ? *length : u32(c.after)}, p) == 4;
  }
};

/// An IPv4 endpoint (0x04), multicast (0x14) or SD-endpoint (0x24) option, wire::sd_ipv4_option
/// (length 9).
struct sd_ipv4_option {
  u8 type = sd_option_type::ipv4_endpoint;
  bool discardable = false;
  ipv4_addr address{};
  u8 l4_proto = ip_proto::udp;
  u16 port = 0;

  static constexpr sd_ipv4_option endpoint(ipv4_addr a, u8 proto, u16 port) noexcept {
    return {sd_option_type::ipv4_endpoint, false, a, proto, port};
  }
  static constexpr sd_ipv4_option multicast(ipv4_addr a, u16 port) noexcept {
    return {sd_option_type::ipv4_multicast, false, a, ip_proto::udp, port};
  }
  static constexpr sd_ipv4_option sd_endpoint(ipv4_addr a, u16 port = nanowire::port::someip_sd) noexcept {
    return {sd_option_type::ipv4_sd_endpoint, false, a, ip_proto::udp, port};
  }
  static constexpr std::size_t size() noexcept { return 12; }
  constexpr bool write(std::byte* p, const build_ctx& = {}) const noexcept {
    return emit_wire(wire::sd_ipv4_option{9, type, u8(discardable ? 0x80 : 0), address, 0, l4_proto, port}, p) == 12;
  }
};

/// An IPv6 endpoint (0x06), multicast (0x16) or SD-endpoint (0x26) option, wire::sd_ipv6_option
/// (length 21).
struct sd_ipv6_option {
  u8 type = sd_option_type::ipv6_endpoint;
  bool discardable = false;
  ipv6_addr address{};
  u8 l4_proto = ip_proto::udp;
  u16 port = 0;

  static constexpr sd_ipv6_option endpoint(ipv6_addr a, u8 proto, u16 port) noexcept {
    return {sd_option_type::ipv6_endpoint, false, a, proto, port};
  }
  static constexpr sd_ipv6_option multicast(ipv6_addr a, u16 port) noexcept {
    return {sd_option_type::ipv6_multicast, false, a, ip_proto::udp, port};
  }
  static constexpr sd_ipv6_option sd_endpoint(ipv6_addr a, u16 port = nanowire::port::someip_sd) noexcept {
    return {sd_option_type::ipv6_sd_endpoint, false, a, ip_proto::udp, port};
  }
  static constexpr std::size_t size() noexcept { return 24; }
  constexpr bool write(std::byte* p, const build_ctx& = {}) const noexcept {
    return emit_wire(wire::sd_ipv6_option{21, type, u8(discardable ? 0x80 : 0), address, 0, l4_proto, port}, p) == 24;
  }
};

/// A load-balancing option (0x02), wire::sd_load_balancing_option (length 5).
struct sd_load_balancing_option {
  u16 priority = 0;
  u16 weight = 0;
  bool discardable = false;
  static constexpr std::size_t size() noexcept { return 8; }
  constexpr bool write(std::byte* p, const build_ctx& = {}) const noexcept {
    return emit_wire(wire::sd_load_balancing_option{5, sd_option_type::load_balancing, u8(discardable ? 0x80 : 0),
                                                    priority, weight},
                     p) == 8;
  }
};

/// One SD option whose kind is chosen at run time by `type` (IPv4 / IPv6 endpoint-like options
/// are written as sd_ipv4_option / sd_ipv6_option, load balancing as sd_load_balancing_option,
/// configuration and unknown types as [length][type][reserved][config bytes]). Use the factories;
/// `config` is the raw configuration string (items as [len][chars]..., terminated by a 0 byte —
/// see sd_encode_config). A convenience for option arrays; for frame templates use the typed
/// builders.
struct sd_option {
  u8 type = sd_option_type::ipv4_endpoint;
  bool discardable = false;
  ipv4_addr v4{};
  ipv6_addr v6{};
  u8 l4_proto = ip_proto::udp;
  u16 port = 0;
  u16 priority = 0, weight = 0;
  bytes config{};

  static constexpr sd_option ipv4_endpoint(ipv4_addr a, u8 proto, u16 port) noexcept {
    return {sd_option_type::ipv4_endpoint, false, a, {}, proto, port, 0, 0, {}};
  }
  static constexpr sd_option ipv6_endpoint(ipv6_addr a, u8 proto, u16 port) noexcept {
    return {sd_option_type::ipv6_endpoint, false, {}, a, proto, port, 0, 0, {}};
  }
  static constexpr sd_option ipv4_multicast(ipv4_addr a, u16 port) noexcept {
    return {sd_option_type::ipv4_multicast, false, a, {}, ip_proto::udp, port, 0, 0, {}};
  }
  static constexpr sd_option ipv6_multicast(ipv6_addr a, u16 port) noexcept {
    return {sd_option_type::ipv6_multicast, false, {}, a, ip_proto::udp, port, 0, 0, {}};
  }
  static constexpr sd_option ipv4_sd_endpoint(ipv4_addr a, u16 port = nanowire::port::someip_sd) noexcept {
    return {sd_option_type::ipv4_sd_endpoint, false, a, {}, ip_proto::udp, port, 0, 0, {}};
  }
  static constexpr sd_option ipv6_sd_endpoint(ipv6_addr a, u16 port = nanowire::port::someip_sd) noexcept {
    return {sd_option_type::ipv6_sd_endpoint, false, {}, a, ip_proto::udp, port, 0, 0, {}};
  }
  static constexpr sd_option load_balancing(u16 priority, u16 weight) noexcept {
    return {sd_option_type::load_balancing, false, {}, {}, 0, 0, priority, weight, {}};
  }
  static constexpr sd_option configuration(bytes raw) noexcept {
    return {sd_option_type::configuration, false, {}, {}, 0, 0, 0, 0, raw};
  }

  constexpr bool is_v4() const noexcept { return type == 0x04 || type == 0x14 || type == 0x24; }
  constexpr bool is_v6() const noexcept { return type == 0x06 || type == 0x16 || type == 0x26; }
  /// The typed builders this option is written as (when is_v4() / is_v6() / load balancing).
  constexpr sd_ipv4_option as_ipv4() const noexcept { return {type, discardable, v4, l4_proto, port}; }
  constexpr sd_ipv6_option as_ipv6() const noexcept { return {type, discardable, v6, l4_proto, port}; }
  constexpr sd_load_balancing_option as_load_balancing() const noexcept { return {priority, weight, discardable}; }

  constexpr std::size_t size() const noexcept {
    if (is_v4()) return 12;
    if (is_v6()) return 24;
    if (type == sd_option_type::load_balancing) return 8;
    return 4 + config.size();  // configuration / unknown: raw body
  }
  constexpr bool write(std::byte* p, const build_ctx& c = {}) const noexcept {
    if (is_v4()) return as_ipv4().write(p, c);
    if (is_v6()) return as_ipv6().write(p, c);
    if (type == sd_option_type::load_balancing) return as_load_balancing().write(p, c);
    if (config.size() + 1 > 0xffff) return false;
    if (emit_wire(wire::sd_option_hdr{u16(1 + config.size()), type, u8(discardable ? 0x80 : 0x00)}, p) != 4)
      return false;
    detail::copy_bytes(p + 4, config);
    return true;
  }
};

/// Encode configuration items ("key=value" strings) as [len][chars]... 0 into `out`; returns the
/// size written, or 0 when an item is empty or longer than 255 bytes or `out` is too small.
inline std::size_t sd_encode_config(std::span<const std::string_view> items, mut_bytes out) noexcept {
  std::size_t n = 0;
  for (auto it : items) {
    if (it.empty() || it.size() > 255 || out.size() - n < it.size() + 2) return 0;
    out[n++] = std::byte(it.size());
    for (char ch : it) out[n++] = std::byte(ch);
  }
  if (n + 1 > out.size()) return 0;
  out[n++] = std::byte{0};
  return n;
}

/// The SD payload (follows a someip{} header layer; use someip_sd_header() for that header).
struct someip_sd {
  u8 flags = sd_flag::reboot | sd_flag::unicast;
  std::span<const sd_entry> entries{};
  std::span<const sd_option> options{};

  constexpr std::size_t options_size() const noexcept {
    std::size_t n = 0;
    for (const auto& o : options) n += o.size();
    return n;
  }
  constexpr std::size_t size() const noexcept { return 12 + 16 * entries.size() + options_size(); }
  constexpr bool write(std::byte* p, const build_ctx&) const noexcept {
    if (entries.size() > 0xffffffffu / 16) return false;
    const std::size_t el = 16 * entries.size();
    const std::size_t ol = options_size();
    if (ol > 0xffffffffu) return false;
    if (emit_wire(wire::sd_header{flags, {0, 0, 0}, u32(el)}, p) != 8) return false;
    std::byte* q = p + 8;
    for (const auto& e : entries) {
      if (!e.write(q)) return false;
      q += 16;
    }
    if (emit_wire(wire::sd_options_length{u32(ol)}, q) != 4) return false;
    q += 4;
    for (const auto& o : options) {
      if (!o.write(q)) return false;
      q += o.size();
    }
    return true;
  }
};

/// The SOME/IP header of an SD message (Message ID 0xFFFF8100, client 0, notification).
constexpr someip someip_sd_header(u16 session_id = 1) noexcept {
  someip h{};
  h.service_id = sd_service_id;
  h.method_id = sd_method_id;
  h.client_id = 0;
  h.session_id = session_id;
  h.message_type = someip_type::notification;
  return h;
}

}  // namespace nanowire

#endif  // NANOWIRE_SOMEIP_SD_HPP_INCLUDED
