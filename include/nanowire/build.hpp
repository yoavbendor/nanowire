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
// `ethertype()` / `ip_protocol()` / `someip_type_flags()` announce it to the layer before, optional
// `finalize(std::byte*, const build_ctx&)` runs in the checksum pass. User layers plug in the same
// way. Nothing allocates (make_frame is the vector-returning convenience).
#ifndef NANOWIRE_BUILD_HPP_INCLUDED
#define NANOWIRE_BUILD_HPP_INCLUDED

#include <nanowire/core.hpp>

#include <tuple>
#include <utility>
#include <vector>

// Lambdas inside build_frame are always inlined (they are its loop bodies).
#if defined(__GNUC__) || defined(__clang__)
#define NANOWIRE_INLINE_LAMBDA __attribute__((always_inline))
#else
#define NANOWIRE_INLINE_LAMBDA
#endif

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
    detail::copy_bytes(p, data);
    return true;
  }
};
/// `count` copies of `value` (padding, filler payloads).
struct fill {
  std::size_t count = 0;
  std::byte value{0};
  constexpr std::size_t size() const noexcept { return count; }
  constexpr bool write(std::byte* p, const build_ctx&) const noexcept {
    if consteval {
      for (std::size_t i = 0; i < count; ++i) p[i] = value;
    } else {
      if (count) std::memset(p, std::to_integer<int>(value), count);
    }
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

namespace detail {
template <layer... L>
constexpr std::optional<std::size_t> checked_frame_size(const L&... ls) noexcept {
  std::size_t total = 0;
  bool ok = true;
  (
      [&](std::size_t s) {
        if (s > std::size_t(-1) - total) ok = false;
        else total += s;
      }(std::size_t(ls.size())),
      ...);
  if (!ok) return std::nullopt;
  return total;
}
template <class L>
constexpr void announce(const L& l, build_ctx& c) noexcept {
  if constexpr (requires { l.ethertype(); }) c.next_ethertype = u16(l.ethertype());
  if constexpr (requires { l.ip_protocol(); }) {
    c.next_ip_proto = u8(l.ip_protocol());
    c.has_next_ip_proto = true;
  }
  if constexpr (requires { l.someip_type_flags(); }) c.next_someip_type_flags = u8(l.someip_type_flags());
}
template <class L>
concept sd_entry_layer = requires { requires bool(L::sd_entry_layer); };
/// One past the last index of the run of SD entry layers that starts right after layer I.
template <std::size_t I, class... L>
consteval std::size_t sd_entry_run_end() {
  constexpr std::array<bool, sizeof...(L)> is_entry{sd_entry_layer<L>...};
  std::size_t j = I + 1;
  while (j < sizeof...(L) && is_entry[j]) ++j;
  return j;
}
template <class L>
concept has_finalize = requires(const L& l, std::byte* p, const build_ctx& c) { l.finalize(p, c); };
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

/// Total bytes the layers occupy (saturates at SIZE_MAX on overflow).
template <layer... L>
constexpr std::size_t frame_size(const L&... ls) noexcept {
  return detail::checked_frame_size(ls...).value_or(std::size_t(-1));
}

/// Write the layers back to back into `out`. Returns the layout, or which layer failed.
///
/// One pass computes every offset (each size() is called once), one pass writes the layers in
/// order (each layer's build_ctx is assembled on the fly from local offsets: no context array),
/// and the checksum pass runs only over layers that have finalize(), innermost first. The layout
/// is written once, into the returned value. Every derivation (lengths, types, entries_length)
/// comes from the layers' sizes and types; nothing depends on the bytes a layer wrote.
/// Always inlined (with its loop-body lambdas), so builder values the caller knows at compile
/// time fold into the stores.
template <layer... L>
[[gnu::always_inline]] constexpr nanom::expected<frame_layout<sizeof...(L)>, build_error> build_frame(
    mut_bytes out, const L&... ls) noexcept {
  constexpr std::size_t N = sizeof...(L);
  // Every return is `res` (named return value: the layout is written once, into the caller's slot).
  nanom::expected<frame_layout<N>, build_error> res{frame_layout<N>{}};
  // Offsets live in locals until the frame is written: the layers store through std::byte
  // pointers, which may alias any escaping object, so state kept in the result would be reloaded
  // after every store.
  std::array<std::size_t, N + 1> off{};  // off[i] = start of layer i, off[N] = frame size
  {
    bool fits = true;  // no size_t wraparound: each size is checked against the room left
    std::size_t i = 0;
    (
        [&](std::size_t s) NANOWIRE_INLINE_LAMBDA {
          fits &= s <= out.size() - off[i];  // sticky: once false, the offsets no longer matter
          off[i + 1] = off[i] + s;
          ++i;
        }(std::size_t(ls.size())),
        ...);
    if (!fits) {
      res = nanom::unexpected<build_error>(build_error{build_errc::buffer_too_small, N});
      return res;
    }
  }
  const std::size_t total = off[N];

  const auto tup = std::forward_as_tuple(ls...);
  std::byte* const frame = out.data();
  auto ctx_of = [&]<std::size_t I>(std::integral_constant<std::size_t, I>, std::size_t off3, u8 v3) NANOWIRE_INLINE_LAMBDA {
    build_ctx c{};
    c.after = total - off[I + 1];
    c.frame = frame;
    c.l3_off = off3;
    c.l3_version = v3;
    if constexpr (I + 1 < N) detail::announce(std::get<I + 1 < N ? I + 1 : 0>(tup), c);
    if constexpr (constexpr std::size_t e = detail::sd_entry_run_end<I, L...>(); e > I + 1)
      c.sd_entries_after = off[e] - off[I + 1];
    return c;
  };
  // The enclosing L3 header (offset, version) of each layer that has a finalize() pass.
  std::array<std::size_t, N> l3_off{};
  std::array<u8, N> l3_ver{};

  std::size_t bad = N;
  const bool ok = [&]<std::size_t... I>(std::index_sequence<I...>) NANOWIRE_INLINE_LAMBDA {
    std::size_t off3 = 0;
    u8 v3 = 0;
    return (
        [&]() NANOWIRE_INLINE_LAMBDA {
          const auto& l = std::get<I>(tup);
          if constexpr (detail::has_finalize<std::remove_cvref_t<decltype(l)>>) l3_off[I] = off3, l3_ver[I] = v3;
          if (!l.write(frame + off[I], ctx_of(std::integral_constant<std::size_t, I>{}, off3, v3))) {
            bad = I;
            return false;
          }
          if (const u8 v = detail::l3_version_of(l)) off3 = off[I], v3 = v;
          return true;
        }() &&
        ...);
  }(std::make_index_sequence<N>{});
  if (!ok) {
    res = nanom::unexpected<build_error>(build_error{build_errc::invalid_field, bad});
    return res;
  }

  // checksum pass, innermost layer first
  [&]<std::size_t... I>(std::index_sequence<I...>) NANOWIRE_INLINE_LAMBDA {
    (
        [&]() NANOWIRE_INLINE_LAMBDA {
          constexpr std::size_t J = N - 1 - I;
          const auto& l = std::get<J>(tup);
          if constexpr (detail::has_finalize<std::remove_cvref_t<decltype(l)>>)
            l.finalize(frame + off[J], ctx_of(std::integral_constant<std::size_t, J>{}, l3_off[J], l3_ver[J]));
        }(),
        ...);
  }(std::make_index_sequence<N>{});

  frame_layout<N>& lay = *res;
  lay.size = total;
  [&]<std::size_t... I>(std::index_sequence<I...>) NANOWIRE_INLINE_LAMBDA {
    ((lay.layers[I] = {off[I], off[I + 1] - off[I]}), ...);
  }(std::make_index_sequence<N>{});
  return res;
}

/// Convenience: build into a new vector (allocates).
template <layer... L>
nanom::expected<std::vector<std::byte>, build_error> make_frame(const L&... ls) {
  const auto total = detail::checked_frame_size(ls...);
  if (!total) return nanom::unexpected<build_error>(build_error{build_errc::buffer_too_small, sizeof...(L)});
  std::vector<std::byte> v(*total);
  auto r = build_frame(mut_bytes(v), ls...);
  if (!r) return nanom::unexpected<build_error>(r.error());
  return v;
}

}  // namespace nanowire

#endif  // NANOWIRE_BUILD_HPP_INCLUDED
