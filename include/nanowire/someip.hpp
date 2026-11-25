// SPDX-License-Identifier: Apache-2.0
// nanowire/someip.hpp — SOME/IP message header (AUTOSAR PRS_SOMEIP) and the SOME/IP-TP header.
//
//   wire::someip_hdr / wire::someip_tp_hdr   layouts (SOME/IP length is a nanom computed field)
//   someip_view                              zero-copy reader of one message
//   someip_tp_view                           the TP header (offset in 16-byte units, More flag)
//   someip_messages                          zero-copy range over messages packed back to back in
//                                            one UDP / TCP payload
//   someip / someip_tp                       builders
//
// SOME/IP has no magic number: whether a UDP payload IS SOME/IP is port configuration (see
// dispatch.hpp). Service Discovery (service 0xFFFF, method 0x8100) is in someip_sd.hpp;
// TP reassembly is in reassembly.hpp.
#ifndef NANOWIRE_SOMEIP_HPP_INCLUDED
#define NANOWIRE_SOMEIP_HPP_INCLUDED

#include <nanowire/core.hpp>

namespace nanowire::wire {
struct someip_hdr {
  nm::be<u16> service_id, method_id;
  nm::be<u32> length;  // bytes from client_id to the end of the message (= 8 + payload)
  nm::be<u16> client_id, session_id;
  u8 protocol_version, interface_version, message_type, return_code;
};
struct someip_tp_hdr {
  nm::ubits<28> offset;  // in 16-byte units
  nm::ubits<3> reserved;
  nm::ubits<1> more;  // More Segments flag
};
}  // namespace nanowire::wire

NANOM_DESCRIBE(nanowire::wire::someip_hdr, service_id, method_id, length, client_id, session_id, protocol_version,
               interface_version, message_type, return_code);
NANOM_DESCRIBE(nanowire::wire::someip_tp_hdr, offset, reserved, more);

template <>
struct nanom::computed<nanowire::wire::someip_hdr> {
  static constexpr auto fields = std::tuple{nanom::calc<"length">(
      [](const nanowire::wire::someip_hdr&, const nanom::emit_ctx& c) { return 8 + c.payload.size(); })};
};

namespace nanowire {

static_assert(nm::wire_size_v<wire::someip_hdr> == 16 && nm::wire_size_v<wire::someip_tp_hdr> == 4);

/// Message Type values (byte 14). `tp_flag` (0x20) marks a SOME/IP-TP segment.
namespace someip_type {
inline constexpr u8 request = 0x00, request_no_return = 0x01, notification = 0x02, request_ack = 0x40,
                    request_no_return_ack = 0x41, notification_ack = 0x42, response = 0x80, error = 0x81,
                    response_ack = 0xC0, error_ack = 0xC1, tp_flag = 0x20;
}
/// Return Code values (byte 15), PRS_SOMEIP.
namespace someip_rc {
inline constexpr u8 ok = 0x00, not_ok = 0x01, unknown_service = 0x02, unknown_method = 0x03, not_ready = 0x04,
                    not_reachable = 0x05, timeout = 0x06, wrong_protocol_version = 0x07,
                    wrong_interface_version = 0x08, malformed_message = 0x09, wrong_message_type = 0x0A,
                    e2e_repeated = 0x0B, e2e_wrong_sequence = 0x0C, e2e = 0x0D, e2e_not_available = 0x0E,
                    e2e_no_new_data = 0x0F;
}
inline constexpr u16 sd_service_id = 0xFFFF, sd_method_id = 0x8100;

class someip_tp_view {
 public:
  static constexpr std::size_t size = 4;
  constexpr someip_tp_view(const std::byte* p, std::size_t avail) noexcept : p_(p), n_(avail) {}  // unchecked
  /// Offset in 16-byte units, as on the wire.
  constexpr u32 offset_units() const noexcept { return field<wire::someip_tp_hdr, "offset">(p_); }
  /// Offset in bytes (the upper 28 bits ARE units of 16, so this is the word with the low nibble cleared).
  constexpr u32 offset_bytes() const noexcept { return detail::be32(p_) & 0xFFFFFFF0u; }
  constexpr bool more() const noexcept { return (u8(p_[3]) & 1) != 0; }
  constexpr u8 reserved() const noexcept { return field<wire::someip_tp_hdr, "reserved">(p_); }
  /// This segment's slice of the original payload (after the TP header).
  constexpr bytes segment() const noexcept { return {p_ + 4, n_ - 4}; }

 private:
  const std::byte* p_;
  std::size_t n_;
};

class someip_view {
 public:
  static constexpr std::size_t header_size = 16;
  /// Validates once: >= 16 bytes and length >= 8. The message may be truncated (see truncated()).
  static constexpr std::optional<someip_view> parse(bytes b) noexcept {
    if (b.size() < header_size || detail::be32(b.data() + 4) < 8) return std::nullopt;
    return someip_view(b.data(), b.size());
  }
  constexpr someip_view(const std::byte* p, std::size_t n) noexcept : p_(p), n_(n) {}  // unchecked

  constexpr u16 service_id() const noexcept { return field<wire::someip_hdr, "service_id">(p_); }
  constexpr u16 method_id() const noexcept { return field<wire::someip_hdr, "method_id">(p_); }
  /// Message ID = service_id << 16 | method_id.
  constexpr u32 message_id() const noexcept { return detail::be32(p_); }
  constexpr u32 length() const noexcept { return field<wire::someip_hdr, "length">(p_); }
  constexpr u16 client_id() const noexcept { return field<wire::someip_hdr, "client_id">(p_); }
  constexpr u16 session_id() const noexcept { return field<wire::someip_hdr, "session_id">(p_); }
  /// Request ID = client_id << 16 | session_id.
  constexpr u32 request_id() const noexcept { return detail::be32(p_ + 8); }
  constexpr u8 protocol_version() const noexcept { return u8(p_[12]); }
  constexpr u8 interface_version() const noexcept { return u8(p_[13]); }
  constexpr u8 message_type() const noexcept { return u8(p_[14]); }
  /// Message type without the TP flag.
  constexpr u8 message_type_base() const noexcept { return u8(p_[14]) & u8(~someip_type::tp_flag); }
  constexpr u8 return_code() const noexcept { return u8(p_[15]); }

  constexpr bool is_tp() const noexcept { return (message_type() & someip_type::tp_flag) != 0; }
  constexpr bool is_sd() const noexcept { return message_id() == (u32(sd_service_id) << 16 | sd_method_id); }

  /// Declared size of the whole message (16 + payload) = 8 + length.
  constexpr std::size_t message_size() const noexcept { return 8 + std::size_t(length()); }
  constexpr bool truncated() const noexcept { return message_size() > n_; }
  constexpr bytes header() const noexcept { return {p_, header_size}; }
  /// The message (header + payload) clamped to the available bytes.
  constexpr bytes message() const noexcept {
    const std::size_t m = message_size();
    return {p_, m < n_ ? m : n_};
  }
  /// The payload after the 16-byte header (for a TP segment this starts with the TP header).
  constexpr bytes payload() const noexcept { return message().subspan(header_size); }
  /// The TP header, when is_tp() and at least 4 payload bytes are present.
  constexpr std::optional<someip_tp_view> tp() const noexcept {
    const bytes pl = payload();
    if (!is_tp() || pl.size() < someip_tp_view::size) return std::nullopt;
    return someip_tp_view(pl.data(), pl.size());
  }

 private:
  const std::byte* p_;
  std::size_t n_;
};

/// Zero-copy range over SOME/IP messages packed back to back (one UDP datagram may carry
/// several). Each element is a someip_view over exactly that message. Iteration stops at the end
/// or at a message that is malformed (length < 8) or does not fit (well_formed() then reports
/// false; rest() is the unconsumed tail).
class someip_messages {
 public:
  constexpr explicit someip_messages(bytes b) noexcept : b_(b) {}
  class iterator {
   public:
    using value_type = someip_view;
    using difference_type = std::ptrdiff_t;
    constexpr iterator() = default;
    constexpr explicit iterator(bytes rest) noexcept : rest_(rest) { load(); }
    constexpr someip_view operator*() const noexcept { return someip_view(rest_.data(), step_); }
    constexpr iterator& operator++() noexcept { rest_ = rest_.subspan(step_); load(); return *this; }
    constexpr iterator operator++(int) noexcept { auto t = *this; ++*this; return t; }
    constexpr bool operator==(std::default_sentinel_t) const noexcept { return step_ == 0; }

   private:
    constexpr void load() noexcept { step_ = next_size(rest_); }
    bytes rest_{};
    std::size_t step_ = 0;
  };
  constexpr iterator begin() const noexcept { return iterator(b_); }
  constexpr std::default_sentinel_t end() const noexcept { return {}; }
  /// Bytes left after the last complete message (empty when the payload was fully consumed).
  constexpr bytes rest() const noexcept {
    bytes r = b_;
    while (std::size_t n = next_size(r)) r = r.subspan(n);
    return r;
  }
  constexpr bool well_formed() const noexcept { return rest().empty(); }
  constexpr std::size_t count() const noexcept {
    std::size_t c = 0;
    for (bytes r = b_; std::size_t n = next_size(r); r = r.subspan(n)) ++c;
    return c;
  }

  /// Size of the complete message at the start of `r`, or 0.
  static constexpr std::size_t next_size(bytes r) noexcept {
    if (r.size() < 16) return 0;
    const u32 l = detail::be32(r.data() + 4);
    if (l < 8 || std::size_t(l) + 8 > r.size()) return 0;
    return std::size_t(l) + 8;
  }

 private:
  bytes b_;
};

// ---------------------------------------------------------------------------------------------
// builders
// ---------------------------------------------------------------------------------------------

/// The SOME/IP-TP header values for one segment (offset in BYTES; must be a multiple of 16).
struct someip_tp {
  u32 offset = 0;
  bool more = false;
};

/// SOME/IP header. `length` is derived (8 + everything after the header, TP header included)
/// unless overridden. With `tp` set, the TP flag is OR-ed into message_type and the 4-byte TP
/// header follows the 16-byte header.
struct someip {
  u16 service_id = 0;
  u16 method_id = 0;
  u16 client_id = 0;
  u16 session_id = 1;
  u8 protocol_version = 1;
  u8 interface_version = 1;
  u8 message_type = someip_type::notification;
  u8 return_code = someip_rc::ok;
  std::optional<someip_tp> tp{};
  std::optional<u32> length{};

  constexpr std::size_t size() const noexcept { return tp ? 20 : 16; }
  constexpr bool write(std::byte* p, const build_ctx& c) const noexcept {
    wire::someip_hdr h{service_id,
                       method_id,
                       0,
                       client_id,
                       session_id,
                       protocol_version,
                       interface_version,
                       u8(tp ? (message_type | someip_type::tp_flag) : message_type),
                       return_code};
    if (tp) {
      if (tp->offset % 16 != 0) return false;
      wire::someip_tp_hdr t{{tp->offset / 16}, {0}, {u8(tp->more)}};
      if (emit_wire(t, p + 16) != 4) return false;
    }
    if (emit_wire(h, p, bytes(p + 16, (tp ? 4 : 0) + c.after)) != 16) return false;
    if (length) detail::put_be32(p + 4, *length);
    return true;
  }
};

}  // namespace nanowire

#endif  // NANOWIRE_SOMEIP_HPP_INCLUDED
