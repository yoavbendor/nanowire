// SPDX-License-Identifier: Apache-2.0
// build_frame_bench — the cost of writing one frame with nanowire's builders.
//
//   build_frame_bench [mode=all|build_frame|emit|memcpy] [frames=2000000] [reps=7]
//
// Every mode writes Eth / VLAN / IPv4 / UDP / SOME/IP + a 32-byte payload (94 bytes) per frame,
// with the IPv4 identification and the SOME/IP session changing per frame, IPv4 total length +
// header checksum derived, UDP length derived, UDP checksum 0 (none):
//   build_frame  nanowire::build_frame(buf, eth, vlan, ipv4, udp, someip, raw)
//   emit         the same bytes by hand: nanom::emit called once per wire struct, the lengths
//                derived through each struct's emit_ctx payload (the reference: what the builders
//                would cost as plain per-layer nanom::emit calls)
//   memcpy       copy a prebuilt frame and patch the two fields + checksum (the template floor)
// All modes are checked to produce byte-identical frames. Reports the best ns/frame over the reps.
// For instructions per frame run one mode under callgrind; frame_once() is the per-frame entry:
//   valgrind --tool=callgrind --toggle-collect='*frame_once*' ./build_frame_bench build_frame 100000 1
#include <nanowire/nanowire.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

namespace {
using namespace nanowire;
using clk = std::chrono::steady_clock;

constexpr std::size_t kPay = 32;
const eth kEth{.dst = {1, 0x80, 0xc2, 0, 0, 1}, .src = {2, 0, 0, 0, 0xaa, 1}};
const vlan kVlan{.vid = 100, .pcp = 3};
const ipv4 kIp{.src = {10, 0, 0, 1}, .dst = {10, 0, 0, 2}};
const udp kUdp{.src_port = 30501, .dst_port = 30501, .checksum = 0};
const someip kSomeip{.service_id = 0x1234, .method_id = 0x8001, .client_id = 1, .session_id = 0};

volatile std::uint64_t g_sink;

// The header values come from memory in every mode (the compiler may not fold them into
// immediates), as they would from a real application's configuration.
template <class T>
[[gnu::always_inline]] inline const T& opaque(const T& x) {
  const T* p = &x;
  asm volatile("" : "+r"(p));
  return *p;
}

// The application keeps its builder values and updates the per-frame fields in place.
ipv4 g_ip = kIp;
someip g_someip = kSomeip;

[[gnu::noinline]] std::size_t frame_once_build_frame(std::array<std::byte, 256>& buf, const std::byte* pay, u16 i) {
  ipv4& ip = const_cast<ipv4&>(opaque(g_ip));
  someip& s = const_cast<someip&>(opaque(g_someip));
  ip.id = i;
  s.session_id = i;
  const auto f = build_frame(buf, opaque(kEth), opaque(kVlan), ip, opaque(kUdp), s, raw{{pay, kPay}});
  return f ? f->size : 0;
}

template <class W>
void nm_emit(const W& w, std::byte* p, bytes after = {}) {
  (void)nanom::emit(w, std::span<std::byte>(p, nanom::wire_size_v<W>), nanom::emit_ctx{after}, std::endian::big);
}

// The same frame written by hand: one nanom::emit per wire struct, every value taken from the same
// builder objects, lengths through each struct's computed fields, IPv4 header checksum computed.
[[gnu::noinline]] std::size_t frame_once_emit(std::array<std::byte, 256>& buf, const std::byte* pay, u16 i) {
  const eth& e = opaque(kEth);
  const vlan& v = opaque(kVlan);
  const ipv4& ip = opaque(kIp);
  const udp& u = opaque(kUdp);
  const someip& s = opaque(kSomeip);
  std::byte* p = buf.data();
  constexpr std::size_t n = 14 + 4 + 20 + 8 + 16 + kPay;
  std::memcpy(p + 62, pay, kPay);
  nm_emit(wire::eth_hdr{e.dst, e.src, ethertype::vlan}, p);
  nm_emit(wire::vlan_tag{v.pcp, u8(v.dei), v.vid, ethertype::ipv4}, p + 14);
  nm_emit(wire::someip_hdr{s.service_id, s.method_id, 0, s.client_id, i, s.protocol_version, s.interface_version,
                           s.message_type, s.return_code},
          p + 46, bytes(p + 62, kPay));
  nm_emit(wire::udp_hdr{u.src_port, u.dst_port, 0, *u.checksum}, p + 38, bytes(p + 46, 16 + kPay));
  wire::ipv4_hdr h{};
  h.version = 4;
  h.ihl = 5;
  h.dscp = ip.dscp;
  h.ecn = ip.ecn;
  h.identification = i;
  h.df = u8(ip.df);
  h.ttl = ip.ttl;
  h.protocol = ip_proto::udp;
  h.src = ip.src;
  h.dst = ip.dst;
  nm_emit(h, p + 18, bytes(p + 38, 8 + 16 + kPay));
  return n;
}

std::array<std::byte, 256> g_proto{};
[[gnu::noinline]] std::size_t frame_once_memcpy(std::array<std::byte, 256>& buf, const std::byte* pay, u16 i) {
  constexpr std::size_t n = 14 + 4 + 20 + 8 + 16 + kPay;
  std::memcpy(buf.data(), g_proto.data(), 62);
  std::memcpy(buf.data() + 62, pay, kPay);
  detail::put_be16(buf.data() + 18 + 4, i);
  detail::put_be16(buf.data() + 46 + 10, i);
  detail::put_be16(buf.data() + 18 + 10, 0);
  detail::put_be16(buf.data() + 18 + 10, detail::internet_checksum(bytes(buf.data() + 18, 20)));
  return n;
}

std::uint64_t fnv(const std::byte* p, std::size_t n, std::uint64_t h) {
  for (std::size_t i = 0; i < n; ++i) h = (h ^ std::uint8_t(p[i])) * 1099511628211ull;
  return h;
}

template <class F>
std::pair<double, std::uint64_t> run(long n, int reps, F&& once) {
  std::array<std::byte, 256> buf{};
  std::byte pay[kPay];
  double best = 1e30;
  std::uint64_t hash = 0;
  for (int r = 0; r < reps; ++r) {
    std::uint64_t h = 1469598103934665603ull;
    const auto t0 = clk::now();
    for (long i = 0; i < n; ++i) {
      std::memset(pay, int(i & 0xff), kPay);
      const std::size_t len = once(buf, pay, u16(i));
      if (r == 0 && i < 4096) h = fnv(buf.data(), len, h);
      g_sink = g_sink + std::uint8_t(buf[30]);
    }
    best = std::min(best, std::chrono::duration<double, std::nano>(clk::now() - t0).count());
    if (r == 0) hash = h;
  }
  return {best / double(n), hash};
}
}  // namespace

int main(int argc, char** argv) {
  const std::string mode = argc > 1 ? argv[1] : "all";
  const long n = argc > 2 ? std::atol(argv[2]) : 2000000;
  const int reps = argc > 3 ? std::max(1, std::atoi(argv[3])) : 7;
  {
    std::byte pay[kPay]{};
    frame_once_build_frame(g_proto, pay, 0);
  }
  const bool all = mode == "all";
  std::uint64_t ha = 0, hb = 0, hc = 0;
  if (all || mode == "build_frame") {
    auto [ns, h] = run(n, reps, frame_once_build_frame);
    ha = h;
    std::printf("build_frame  nanowire::build_frame        %7.2f ns/frame\n", ns);
  }
  if (all || mode == "emit") {
    auto [ns, h] = run(n, reps, frame_once_emit);
    hb = h;
    std::printf("emit         nanom::emit per wire struct  %7.2f ns/frame\n", ns);
  }
  if (all || mode == "memcpy") {
    auto [ns, h] = run(n, reps, frame_once_memcpy);
    hc = h;
    std::printf("memcpy       prebuilt frame + 2 patches   %7.2f ns/frame\n", ns);
  }
  if (all) {
    const bool same = ha == hb && hb == hc;
    std::printf("frames byte-identical across modes: %s\n", same ? "yes" : "NO");
    return same ? 0 : 1;
  }
  return 0;
}
