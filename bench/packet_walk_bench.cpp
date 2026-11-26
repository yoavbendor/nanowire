// SPDX-License-Identifier: Apache-2.0
// packet_walk_bench — nanowire's packet view vs the raw read floor on a classic pcap capture.
//
//   packet_walk_bench capture.pcap [reps=7] [mode=all|floor|nanowire|nanowire_full|nanom_shark]
//
// Every mode walks the pcap records sequentially straight out of the in-memory file (no index),
// locates the SOME/IP header and sums service / method / session (so nothing is optimized away):
//   floor          fixed offsets for Eth+VLAN+IPv4+UDP (no parsing, no validation): the memory floor
//   nanowire       nanowire::packet::parse + pkt.someip()
//   nanowire_full  same, plus every SOME/IP message in the datagram and the IP / UDP views
//   nanom_shark    nanom_shark's walk_packet_ext (the predecessor) + the SOME/IP header at its offset
// Reports best and median ns/pkt over the reps. Use a single mode under callgrind for instr/pkt:
//   valgrind --tool=callgrind --callgrind-out-file=cg.out ./packet_walk_bench small.pcap 1 nanowire
#include <nanowire/packet.hpp>

#if NANOWIRE_BENCH_HAVE_SHARK
#include <nanom_shark/protocols.hpp>
#endif

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

namespace {
using clk = std::chrono::steady_clock;

struct capture {
  std::vector<std::byte> file;
  bool swapped = false;
};

std::uint32_t rd32(const std::byte* p, bool swapped) {
  std::uint32_t v;
  std::memcpy(&v, p, 4);
  return swapped ? __builtin_bswap32(v) : v;
}

template <class F>
inline std::size_t for_each_record(const capture& c, F&& f) {
  const std::byte* p = c.file.data() + 24;
  const std::byte* e = c.file.data() + c.file.size();
  std::size_t n = 0;
  while (e - p >= 16) {
    const std::uint32_t cap = rd32(p + 8, c.swapped);
    if (std::size_t(e - p - 16) < cap) break;
    f(nanowire::bytes(p + 16, cap));
    p += 16 + cap;
    ++n;
  }
  return n;
}

struct result {
  double best = 1e30, median = 0;
  std::uint64_t sink = 0;
  std::size_t pkts = 0;
};

template <class F>
result run(const capture& c, int reps, F&& per_packet) {
  std::vector<double> t;
  result r;
  for (int i = 0; i < reps; ++i) {
    std::uint64_t acc = 0;
    const auto t0 = clk::now();
    const std::size_t n = for_each_record(c, [&](nanowire::bytes pkt) { acc += per_packet(pkt); });
    const double ns = std::chrono::duration<double, std::nano>(clk::now() - t0).count() / double(n);
    t.push_back(ns);
    r.sink += acc;
    r.pkts = n;
  }
  std::sort(t.begin(), t.end());
  r.best = t.front();
  r.median = t[t.size() / 2];
  return r;
}

void report(const char* name, const result& r) {
  std::printf("%-14s best %6.1f ns/pkt  median %6.1f ns/pkt  (%zu pkts, checksum %llu)\n", name, r.best, r.median,
              r.pkts, static_cast<unsigned long long>(r.sink));
}

inline std::uint64_t floor_one(nanowire::bytes b) {
  // Ethernet(14) + VLAN(4) + IPv4(20) + UDP(8) = 46: the generator's dominant layout.
  if (b.size() < 46 + 16) return 0;
  const std::byte* s = b.data() + 46;
  return std::uint64_t(nanowire::detail::be16(s)) + nanowire::detail::be16(s + 2) + nanowire::detail::be16(s + 10);
}

inline std::uint64_t nanowire_one(nanowire::bytes b) {
  const auto pkt = nanowire::packet::parse(b);
  if (auto m = pkt.someip()) return std::uint64_t(m->service_id()) + m->method_id() + m->session_id();
  return 0;
}

inline std::uint64_t nanowire_full(nanowire::bytes b) {
  const auto pkt = nanowire::packet::parse(b);
  std::uint64_t acc = 0;
  if (auto ip = pkt.ipv4()) acc += ip->ttl() + ip->total_length();
  if (auto u = pkt.udp()) acc += u->dst_port();
  if (pkt.l4() == nanowire::l4_kind::udp)
    for (auto m : pkt.someip_all()) acc += std::uint64_t(m.service_id()) + m.method_id() + m.session_id();
  return acc;
}

#if NANOWIRE_BENCH_HAVE_SHARK
struct shark_visitor {};
inline std::uint64_t shark_one(nanowire::bytes b) {
  const auto r = nmproto::walk_packet_ext(nmproto::kLinkTypeEthernet, nanom::bytes(b.data(), b.size()), shark_visitor{});
  if (!r.reached_l4 || r.l4_payload_offset + 16 > b.size()) return 0;
  const std::byte* s = b.data() + r.l4_payload_offset;
  return std::uint64_t(nanowire::detail::be16(s)) + nanowire::detail::be16(s + 2) + nanowire::detail::be16(s + 10);
}
#endif
}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    std::fprintf(stderr, "usage: %s capture.pcap [reps] [mode]\n", argv[0]);
    return 2;
  }
  capture c;
  {
    std::ifstream f(argv[1], std::ios::binary);
    if (!f) {
      std::fprintf(stderr, "cannot open %s\n", argv[1]);
      return 1;
    }
    f.seekg(0, std::ios::end);
    c.file.resize(std::size_t(f.tellg()));
    f.seekg(0);
    f.read(reinterpret_cast<char*>(c.file.data()), std::streamsize(c.file.size()));
  }
  if (c.file.size() < 24) return 1;
  const std::uint32_t magic = rd32(c.file.data(), false);
  if (magic == 0xd4c3b2a1u || magic == 0x4d3cb2a1u) c.swapped = true;
  else if (magic != 0xa1b2c3d4u && magic != 0xa1b23c4du) {
    std::fprintf(stderr, "not a classic pcap file\n");
    return 1;
  }
  const int reps = argc > 2 ? std::max(1, std::atoi(argv[2])) : 7;
  const std::string mode = argc > 3 ? argv[3] : "all";
  const bool all = mode == "all";
  std::printf("%s: %.1f MB, %d reps\n", argv[1], double(c.file.size()) / 1e6, reps);
  if (all || mode == "floor") report("floor", run(c, reps, floor_one));
  if (all || mode == "nanowire") report("nanowire", run(c, reps, nanowire_one));
  if (all || mode == "nanowire_full") report("nanowire_full", run(c, reps, nanowire_full));
#if NANOWIRE_BENCH_HAVE_SHARK
  if (all || mode == "nanom_shark") report("nanom_shark", run(c, reps, shark_one));
#endif
  return 0;
}
