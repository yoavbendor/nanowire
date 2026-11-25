// SPDX-License-Identifier: Apache-2.0
// nanowire/dispatch.hpp — runtime dispatch from a parsed packet to user handlers, plus a
// compile-time fast path.
//
// Run time (configurable while running; registration allocates, dispatch does not):
//
//   nanowire::registry reg;
//   reg.port(30490, nanowire::app_protocol::someip)              // UDP port -> protocol
//      .port(30501, nanowire::app_protocol::someip)
//      .port(42000, nanowire::app_protocol::pdu_over_ip)
//      .on_someip(0x1234, 0x8001, [](const nanowire::someip_message& m) { ... })
//      .on_someip_payload<std::uint32_t>(0x1234, 0x8002, nanom::be_u32,   // nanom::dyn<T> decoder
//                                        [](const nanowire::someip_message&, std::uint32_t v) { ... })
//      .on_sd([](const nanowire::someip_message&, const nanowire::sd_view& sd) { ... })
//      .on_pdu(0x100, [](const nanowire::pdu_message& p) { ... })
//      .container(0x200, {.header = nanowire::ipdum_header::short_header})  // IpduM container
//      .attach(tp_reassembler);                                   // SOME/IP-TP: reassemble, then dispatch
//   reg.dispatch(pkt, now);
//
// Lookups: a 64 Ki-entry port table (one byte load), sorted flat maps for (service, method) and
// PDU IDs (binary search). Payload decoders are nanom::dyn<T> parsers (nanom's runtime-composed
// parsers), run over the contiguous payload, or over a preallocated scratch copy for a
// reassembled TP message.
//
// Compile time: dispatch_static<message_id(0x1234, 0x8001), ...>(id, f) unrolls to a compare chain
// calling f(std::integral_constant<u32, Id>{}) — no table, no indirect call.
#ifndef NANOWIRE_DISPATCH_HPP_INCLUDED
#define NANOWIRE_DISPATCH_HPP_INCLUDED

#include <nanowire/autosar_pdu.hpp>
#include <nanowire/packet.hpp>
#include <nanowire/reassembly.hpp>
#include <nanowire/someip_sd.hpp>

#include <nanom/dyn.hpp>

#include <algorithm>
#include <memory>
#include <type_traits>
#include <utility>
#include <vector>

namespace nanowire {

/// Message ID = service << 16 | method.
constexpr u32 message_id(u16 service, u16 method) noexcept { return (u32(service) << 16) | method; }

/// Compile-time fast path: call f(std::integral_constant<u32, Id>{}) for the matching Id.
template <u32... Ids, class F>
constexpr bool dispatch_static(u32 id, F&& f) {
  return ((id == Ids ? (f(std::integral_constant<u32, Ids>{}), true) : false) || ...);
}
/// Compile-time port set membership.
template <u16... Ports>
constexpr bool port_in(u16 p) noexcept {
  return ((p == Ports) || ...);
}

enum class app_protocol : u8 { none = 0, someip = 1, pdu_over_ip = 2 };

/// A SOME/IP message handed to a handler (valid during the call only).
struct someip_message {
  const packet* pkt = nullptr;
  someip_view header{nullptr, 0};  ///< the message header (rebuilt header for reassembled TP)
  bytes payload{};                 ///< contiguous payload; empty when `segmented`
  nanom::segments segments{};      ///< the payload as segments (always valid)
  bool segmented = false;          ///< a reassembled SOME/IP-TP message
  nanom::seg_input input() const noexcept { return nanom::from(segments); }
  std::size_t payload_size() const noexcept { return segments.size(); }
};
/// A PDU handed to a handler (top-level PDU-over-IP or contained in an IpduM container).
struct pdu_message {
  const packet* pkt = nullptr;
  u32 id = 0;
  bytes data{};
  u32 container_id = 0;  ///< the container's PDU ID, 0 for a top-level PDU
  bool contained = false;
};

/// Move-only type-erased callable (allocates once, at registration).
template <class Sig>
class handler;
template <class R, class... A>
class handler<R(A...)> {
 public:
  handler() = default;
  template <class F>
    requires(!std::is_same_v<std::remove_cvref_t<F>, handler> && std::is_invocable_r_v<R, F&, A...>)
  handler(F f)  // NOLINT(google-explicit-constructor)
      : obj_(new F(std::move(f)), [](void* o) { delete static_cast<F*>(o); }),
        call_([](void* o, A... a) -> R { return (*static_cast<F*>(o))(std::forward<A>(a)...); }) {}
  R operator()(A... a) const { return call_(obj_.get(), std::forward<A>(a)...); }
  explicit operator bool() const noexcept { return call_ != nullptr; }

 private:
  std::unique_ptr<void, void (*)(void*)> obj_{nullptr, [](void*) {}};
  R (*call_)(void*, A...) = nullptr;
};

namespace detail {
/// Sorted-vector map: allocation at insert, binary search at lookup.
template <class K, class V>
class flat_map {
 public:
  void set(K k, V v) {
    auto it = std::lower_bound(keys_.begin(), keys_.end(), k);
    const auto i = std::size_t(it - keys_.begin());
    if (it != keys_.end() && *it == k) {
      vals_[i] = std::move(v);
    } else {
      keys_.insert(it, k);
      vals_.insert(vals_.begin() + std::ptrdiff_t(i), std::move(v));
    }
  }
  bool erase(K k) {
    auto it = std::lower_bound(keys_.begin(), keys_.end(), k);
    if (it == keys_.end() || *it != k) return false;
    const auto i = it - keys_.begin();
    keys_.erase(it);
    vals_.erase(vals_.begin() + i);
    return true;
  }
  const V* find(K k) const noexcept {
    auto it = std::lower_bound(keys_.begin(), keys_.end(), k);
    return (it != keys_.end() && *it == k) ? &vals_[std::size_t(it - keys_.begin())] : nullptr;
  }
  std::size_t size() const noexcept { return keys_.size(); }

 private:
  std::vector<K> keys_;
  std::vector<V> vals_;
};
}  // namespace detail

struct dispatch_stats {
  u32 messages = 0;  ///< SOME/IP messages + PDUs seen
  u32 handled = 0;   ///< delivered to a handler
  u32 tp_segments = 0;
  u32 tp_completed = 0;
};

class registry {
 public:
  using someip_handler = handler<void(const someip_message&)>;
  using sd_handler = handler<void(const someip_message&, const sd_view&)>;
  using pdu_handler = handler<void(const pdu_message&)>;

  explicit registry(std::size_t scratch_bytes = 64 * 1024)
      : udp_(std::make_unique<std::array<app_protocol, 65536>>()),
        tcp_(std::make_unique<std::array<app_protocol, 65536>>()),
        scratch_(scratch_bytes) {
    udp_->fill(app_protocol::none);
    tcp_->fill(app_protocol::none);
    (*udp_)[port::someip_sd] = app_protocol::someip;
  }

  // ---- configuration ----
  registry& port(u16 p, app_protocol a, l4_kind l4 = l4_kind::udp) {
    (l4 == l4_kind::tcp ? *tcp_ : *udp_)[p] = a;
    return *this;
  }
  registry& on_someip(u16 service, u16 method, someip_handler h) {
    methods_.set(message_id(service, method), std::move(h));
    return *this;
  }
  /// Every method of a service without a more specific handler.
  registry& on_service(u16 service, someip_handler h) {
    services_.set(service, std::move(h));
    return *this;
  }
  /// Fallback for SOME/IP messages nothing else handles.
  registry& on_someip_other(someip_handler h) {
    other_someip_ = std::move(h);
    return *this;
  }
  registry& on_sd(sd_handler h) {
    sd_ = std::move(h);
    return *this;
  }
  /// Decode the payload with a nanom parser, then call on_value(msg, value). Decode failures are
  /// counted as unhandled.
  template <class T, class D, class F>
  registry& on_someip_payload(u16 service, u16 method, D decoder, F on_value) {
    nanom::dyn<T> dec = decoder;
    std::vector<std::byte>* scratch = &scratch_;
    return on_someip(service, method, [dec, on_value, scratch](const someip_message& m) mutable {
      bytes in = m.payload;
      if (m.segmented) {
        const std::size_t n = copy_to(m.segments, mut_bytes(*scratch));
        if (n != m.segments.size()) return;
        in = bytes(scratch->data(), n);
      }
      auto r = dec(nanom::from(in));
      if (r) on_value(m, r->value);
    });
  }
  registry& on_pdu(u32 id, pdu_handler h) {
    pdus_.set(id, std::move(h));
    return *this;
  }
  registry& on_pdu_other(pdu_handler h) {
    other_pdu_ = std::move(h);
    return *this;
  }
  /// PDUs with this ID are IpduM containers: their contained PDUs are dispatched by their own IDs.
  registry& container(u32 id, ipdum_config cfg) {
    containers_.set(id, cfg);
    return *this;
  }
  /// Feed SOME/IP-TP segments to `r`; completed messages are dispatched like any other message.
  registry& attach(someip_tp_reassembler& r) {
    tp_ = &r;
    return *this;
  }

  // ---- lookup ----
  constexpr app_protocol classify(const packet& pkt) const noexcept {
    const auto& t = pkt.l4() == l4_kind::tcp ? *tcp_ : *udp_;
    if (pkt.l4() != l4_kind::udp && pkt.l4() != l4_kind::tcp) return app_protocol::none;
    const app_protocol d = t[pkt.dst_port()];
    return d != app_protocol::none ? d : t[pkt.src_port()];
  }

  // ---- dispatch ----
  dispatch_stats dispatch(const packet& pkt, u64 now = 0, u64 token = 0) const {
    dispatch_stats st;
    switch (classify(pkt)) {
      case app_protocol::someip:
        for (auto m : pkt.someip_all()) dispatch_someip(pkt, m, now, token, st);
        break;
      case app_protocol::pdu_over_ip:
        for (auto p : soad_pdus(pkt.payload())) dispatch_pdu(pkt, p, 0, false, st);
        break;
      case app_protocol::none:
        break;
    }
    return st;
  }

 private:
  void dispatch_someip(const packet& pkt, const someip_view& m, u64 now, u64 token, dispatch_stats& st) const {
    if (m.is_tp() && tp_) {
      ++st.tp_segments;
      auto r = feed(*tp_, pkt, m, now, token);
      if (!r.complete()) return;
      ++st.tp_completed;
      const auto hdr = r.parts.part(0);
      someip_message msg;
      msg.pkt = &pkt;
      msg.header = someip_view(hdr.data(), hdr.size());
      msg.segments = nanom::segments(r.part_list.subspan(1));  // part 0 is the rebuilt header
      msg.segmented = true;
      deliver(msg, st);
      return;
    }
    someip_message msg;
    msg.pkt = &pkt;
    msg.header = m;
    msg.payload = m.payload();
    const std::span<const std::byte> one = msg.payload;
    msg.segments = nanom::segments(std::span<const std::span<const std::byte>>(&one, 1));
    deliver(msg, st);
  }

  void deliver(const someip_message& msg, dispatch_stats& st) const {
    ++st.messages;
    if (msg.header.is_sd()) {
      if (sd_) {
        std::optional<sd_view> sd;
        if (!msg.segmented) sd = sd_view::parse(msg.payload);
        if (sd) {
          sd_(msg, *sd);
          ++st.handled;
        }
      }
      return;
    }
    if (auto* h = methods_.find(msg.header.message_id())) {
      (*h)(msg);
      ++st.handled;
    } else if (auto* s = services_.find(msg.header.service_id())) {
      (*s)(msg);
      ++st.handled;
    } else if (other_someip_) {
      other_someip_(msg);
      ++st.handled;
    }
  }
  void dispatch_pdu(const packet& pkt, const pdu_view& p, u32 container, bool contained, dispatch_stats& st) const {
    ++st.messages;
    if (!contained) {
      if (auto* cfg = containers_.find(p.id)) {
        for (auto c : ipdum_pdus(p.data, *cfg)) dispatch_pdu(pkt, c, p.id, true, st);
        return;
      }
    }
    const pdu_message msg{&pkt, p.id, p.data, container, contained};
    if (auto* h = pdus_.find(p.id)) {
      (*h)(msg);
      ++st.handled;
    } else if (other_pdu_) {
      other_pdu_(msg);
      ++st.handled;
    }
  }

  std::unique_ptr<std::array<app_protocol, 65536>> udp_, tcp_;
  detail::flat_map<u32, someip_handler> methods_;
  detail::flat_map<u16, someip_handler> services_;
  detail::flat_map<u32, pdu_handler> pdus_;
  detail::flat_map<u32, ipdum_config> containers_;
  someip_handler other_someip_;
  sd_handler sd_;
  pdu_handler other_pdu_;
  someip_tp_reassembler* tp_ = nullptr;
  std::vector<std::byte> scratch_;
};

}  // namespace nanowire

#endif  // NANOWIRE_DISPATCH_HPP_INCLUDED
