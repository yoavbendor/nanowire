// SPDX-License-Identifier: Apache-2.0
// nanowire/build.hpp — frame composition: write a stack of builder values into a buffer.
//
//   std::array<std::byte, 1514> buf;
//   auto f = nanowire::build_frame(buf,
//       nanowire::eth{.dst = ..., .src = ...},
//       nanowire::vlan{.vid = 100, .pcp = 3},
//       nanowire::ipv4{.src = ip4("10.0.0.1"), .dst = ip4("10.0.0.2")},
//       nanowire::udp{.src_port = 30501, .dst_port = 30501},
//       nanowire::someip{.service_id = 0x1234, .method_id = 0x8001},
//       nanowire::raw{payload});
//   // f->size, f->layers[i].offset / .size  (where each layer landed: a crafting template's map)
//
// Derived fields: every type / protocol field left unset takes the next layer's (eth.type from
// vlan.tpid / 0x0800 / 0x86DD, ipv4.protocol from udp / tcp / ...), every length field covers
// the layers after it, and checksums (IPv4 header, UDP / TCP pseudo header) are computed after
// the whole frame is written (inner layers first). Any explicit value overrides the derivation,
// so malformed frames can be crafted on purpose.
//
// A layer is any value with `size()` and `bool write(std::byte*, const build_ctx&)`; optional
// `ethertype()` / `ip_protocol()` announce it to the layer before, optional
// `finalize(std::byte*, const build_ctx&)` runs in the checksum pass. User layers plug in the same
// way. Nothing allocates (make_frame is the vector-returning convenience).
#ifndef NANOWIRE_BUILD_HPP_INCLUDED
#define NANOWIRE_BUILD_HPP_INCLUDED

#include <nanowire/core.hpp>

#include <tuple>
#include <utility>
#include <vector>

namespace nanowire {

template <class L>
concept layer = requires(const L& l, std::byte* p, const build_ctx& c) {
  { l.size() } -> std::convertible_to<std::size_t>;
  { l.write(p, c) } -> std::same_as<bool>;
};

/// Opaque payload bytes.
struct raw {
  bytes data{};
  constexpr std::size_t size() const noexcept { return data.size(); }
  constexpr bool write(std::byte* p, const build_ctx&) const noexcept {
    for (std::size_t i = 0; i < data.size(); ++i) p[i] = data[i];
    return true;
  }
};
/// `count` copies of `value` (padding, filler payloads).
struct fill {
  std::size_t count = 0;
  std::byte value{0};
  constexpr std::size_t size() const noexcept { return count; }
  constexpr bool write(std::byte* p, const build_ctx&) const noexcept {
    for (std::size_t i = 0; i < count; ++i) p[i] = value;
    return true;
  }
};

struct layer_span {
  std::size_t offset = 0;
  std::size_t size = 0;
};
/// Where each layer landed in the frame (a crafting template's field map).
template <std::size_t N>
struct frame_layout {
  std::size_t size = 0;
  std::array<layer_span, N> layers{};
};

enum class build_errc : u8 { buffer_too_small, invalid_field };
struct build_error {
  build_errc code;
  std::size_t layer;  // index of the failing layer (N for buffer_too_small)
};

/// Total bytes the layers occupy.
template <layer... L>
constexpr std::size_t frame_size(const L&... ls) noexcept {
  return (std::size_t{0} + ... + std::size_t(ls.size()));
}

namespace detail {
template <class L>
constexpr void announce(const L& l, build_ctx& c) noexcept {
  if constexpr (requires { l.ethertype(); }) c.next_ethertype = u16(l.ethertype());
  if constexpr (requires { l.ip_protocol(); }) {
    c.next_ip_proto = u8(l.ip_protocol());
    c.has_next_ip_proto = true;
  }
}
template <class L>
constexpr u8 l3_version_of(const L& l) noexcept {
  if constexpr (requires { l.ethertype(); }) {
    const u16 et = u16(l.ethertype());
    return et == ethertype::ipv4 ? 4 : et == ethertype::ipv6 ? 6 : 0;
  } else {
    return 0;
  }
}
}  // namespace detail

/// Write the layers back to back into `out`. Returns the layout, or which layer failed.
template <layer... L>
constexpr nanom::expected<frame_layout<sizeof...(L)>, build_error> build_frame(mut_bytes out, const L&... ls) noexcept {
  constexpr std::size_t N = sizeof...(L);
  frame_layout<N> lay{};
  const std::array<std::size_t, N> sz{std::size_t(ls.size())...};
  std::size_t total = 0;
  for (std::size_t i = 0; i < N; ++i) {
    lay.layers[i] = {total, sz[i]};
    total += sz[i];
  }
  lay.size = total;
  if (total > out.size()) return nanom::unexpected<build_error>(build_error{build_errc::buffer_too_small, N});

  std::array<build_ctx, N> ctx{};
  const auto tup = std::forward_as_tuple(ls...);
  std::byte* frame = out.data();
  // contexts: what follows each layer, and the enclosing L3 header
  [&]<std::size_t... I>(std::index_sequence<I...>) {
    std::size_t l3_off = 0;
    u8 l3v = 0;
    (
        [&] {
          build_ctx& c = ctx[I];
          c.after = total - lay.layers[I].offset - lay.layers[I].size;
          c.frame = frame;
          c.l3_off = l3_off;
          c.l3_version = l3v;
          if constexpr (I + 1 < N) detail::announce(std::get<I + 1 < N ? I + 1 : 0>(tup), c);
          if (const u8 v = detail::l3_version_of(std::get<I>(tup))) {
            l3_off = lay.layers[I].offset;
            l3v = v;
          }
        }(),
        ...);
  }(std::make_index_sequence<N>{});

  std::size_t bad = N;
  [&]<std::size_t... I>(std::index_sequence<I...>) {
    ((bad == N && !std::get<I>(tup).write(frame + lay.layers[I].offset, ctx[I]) ? (bad = I, 0) : 0), ...);
  }(std::make_index_sequence<N>{});
  if (bad != N) return nanom::unexpected<build_error>(build_error{build_errc::invalid_field, bad});

  // checksum pass, innermost layer first
  [&]<std::size_t... I>(std::index_sequence<I...>) {
    (
        [&] {
          constexpr std::size_t J = N - 1 - I;
          const auto& l = std::get<J>(tup);
          if constexpr (requires { l.finalize(frame, ctx[J]); }) l.finalize(frame + lay.layers[J].offset, ctx[J]);
        }(),
        ...);
  }(std::make_index_sequence<N>{});
  return lay;
}

/// Convenience: build into a new vector (allocates).
template <layer... L>
nanom::expected<std::vector<std::byte>, build_error> make_frame(const L&... ls) {
  std::vector<std::byte> v(frame_size(ls...));
  auto r = build_frame(mut_bytes(v), ls...);
  if (!r) return nanom::unexpected<build_error>(r.error());
  return v;
}

}  // namespace nanowire

#endif  // NANOWIRE_BUILD_HPP_INCLUDED
