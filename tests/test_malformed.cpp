// SPDX-License-Identifier: Apache-2.0
// Malformed / truncated input never reads out of bounds.
//
// Every frame of a corpus (built with nanowire's own builders, covering every protocol) is fed
// to every reader at every truncation length and under random byte mutations, each time from an
// EXACTLY sized heap allocation, so an over-read of even one byte trips ASan in the sanitizer
// build. Independently of ASan, every span a reader hands out is checked to lie inside the input.
#include "check.hpp"

#include <nanowire/nanowire.hpp>

#include <memory>
#include <vector>

using namespace nanowire;

namespace {
struct bounds {
  const std::byte* lo;
  const std::byte* hi;
  bool ok = true;
  void in(bytes b) {
    if (b.empty()) return;
    if (b.data() < lo || b.data() + b.size() > hi) ok = false;
  }
};

std::uint64_t g_sink = 0;

void exercise_someip(const someip_view& m, bounds& bd) {
  g_sink += m.service_id() + m.method_id() + m.length() + m.session_id() + m.message_type();
  bd.in(m.message());
  bd.in(m.payload());
  if (auto tp = m.tp()) {
    g_sink += tp->offset_bytes() + tp->more();
    bd.in(tp->segment());
  }
  if (auto sd = sd_view::parse(m.payload())) {
    g_sink += sd->flags() + sd->entries_length() + sd->well_formed();
    for (auto e : sd->entries()) {
      bd.in(e.raw());
      g_sink += e.service_id() + e.ttl() + e.eventgroup_id() + e.minor_version();
      sd->for_each_option(e, [&](const sd_option_view& o, int run) { g_sink += o.type() + unsigned(run); });
    }
    for (auto o : sd->options()) {
      bd.in(o.raw());
      bd.in(o.body());
      if (auto ep = o.endpoint()) g_sink += ep->port;
      if (auto lb = o.load_balancing()) g_sink += lb->weight;
      for (auto item : o.configuration()) {
        bd.in(bytes(reinterpret_cast<const std::byte*>(item.data()), item.size()));
        g_sink += item.size();
      }
    }
  }
}

void exercise_bytes(bytes b, bounds& bd) {
  for (auto lt : {link_type::ethernet, link_type::raw}) {
    const auto pkt = packet::parse(b, lt);
    bd.in(pkt.data());
    bd.in(pkt.l3_bytes());
    bd.in(pkt.payload());
    bd.in(pkt.fragment_data());
    if (auto e = pkt.eth()) bd.in(e->header()), g_sink += e->ethertype();
    for (std::size_t i = 0; i < pkt.vlan_count(); ++i) bd.in(pkt.vlan(i).header()), g_sink += pkt.vlan(i).vid();
    if (auto ip = pkt.ipv4()) {
      bd.in(ip->header());
      bd.in(ip->payload());
      g_sink += ip->checksum_ok() + ip->total_length();
      for (auto o : ip->options()) bd.in(o.value), g_sink += o.type;
      g_sink += ip->options().well_formed();
    }
    if (auto ip = pkt.ipv6()) {
      bd.in(ip->payload());
      bd.in(ip->upper_payload());
      for (auto x : ip->extensions()) {
        bd.in(x.header());
        for (auto o : x.options()) bd.in(o.value), g_sink += o.type;
        if (auto r = x.routing()) {
          for (std::size_t i = 0; i < r->segment_count(); ++i) g_sink += r->segment(i)[15];
          bd.in(r->tlvs());
        }
        if (auto f = x.fragment()) g_sink += f->offset();
      }
    }
    if (auto f = pkt.ipv6_fragment()) g_sink += f->identification();
    if (auto u = pkt.udp()) bd.in(u->header()), bd.in(u->payload()), g_sink += u->length();
    if (auto t = pkt.tcp()) bd.in(t->header()), bd.in(t->options()), bd.in(t->payload()), g_sink += t->flags();
    if (auto m = pkt.someip()) exercise_someip(*m, bd);
    for (auto m : pkt.someip_all()) exercise_someip(m, bd);
    g_sink += pkt.someip_all().count();
    for (auto p : soad_pdus(pkt.payload())) {
      bd.in(p.data);
      for (auto h : {ipdum_header::short_header, ipdum_header::long_header})
        for (auto o : {std::endian::big, std::endian::little})
          for (auto c : ipdum_pdus(p.data, {h, o, false})) bd.in(c.data), g_sink += c.id;
    }
  }
  // the standalone readers on the raw bytes too
  if (auto m = someip_view::parse(b)) exercise_someip(*m, bd);
  for (auto m : someip_messages(b)) exercise_someip(m, bd);
  if (auto sd = sd_view::parse(b)) {
    for (auto e : sd->entries()) bd.in(e.raw());
    for (auto o : sd->options()) bd.in(o.raw());
  }
  for (auto p : soad_pdus(b)) bd.in(p.data);
  for (auto p : ipdum_pdus(b)) bd.in(p.data);
  for (auto p : ipdum_pdus(b, {ipdum_header::long_header, std::endian::little, true})) bd.in(p.data);
  for (auto o : ipv4_options(b)) bd.in(o.value);
  for (auto o : ipv6_options(b)) bd.in(o.value);
  if (!b.empty())
    for (auto x : ipv6_ext_range(u8(b[0]), b.subspan(1))) bd.in(x.header());
  for (auto it : sd_config_items(b)) g_sink += it.size();
  if (auto t = tcp_view::parse(b)) bd.in(t->options()), bd.in(t->payload());
  if (auto u = udp_view::parse(b)) bd.in(u->payload());
  if (auto v = ipv4_view::parse(b)) bd.in(v->payload()), bd.in(v->options_bytes());
  if (auto v = ipv6_view::parse(b)) bd.in(v->payload());
}

/// Run the readers over an exactly-sized heap copy of `b`.
bool exercise_exact(bytes b) {
  std::unique_ptr<std::byte[]> copy(new std::byte[b.size() ? b.size() : 1]);
  if (!b.empty()) std::memcpy(copy.get(), b.data(), b.size());
  const bytes exact(copy.get(), b.size());
  bounds bd{exact.data(), exact.data() + exact.size()};
  exercise_bytes(exact, bd);
  return bd.ok;
}

std::vector<std::vector<std::byte>> corpus() {
  std::vector<std::vector<std::byte>> c;
  static const std::array<std::byte, 40> pl{std::byte{1}};
  static std::array<std::byte, 32> cfg{};
  static const std::array<std::string_view, 2> items{"a=b", "c"};
  const std::size_t cn = sd_encode_config(items, cfg);
  static const std::array<ipv6_addr, 2> segs{ip6("fc00::1"), ip6("fc00::2")};
  static const std::array<std::byte, 6> opts{std::byte{0x94}, std::byte{4}, std::byte{0}, std::byte{0}, std::byte{1},
                                             std::byte{0}};
  const std::array<sd_entry, 2> entries{sd_entry::offer_service(1, 2, 3, 4).with_options(0, 3),
                                        sd_entry::subscribe(1, 2, 3, 4).with_options(1, 1, 2, 1)};
  const std::array<sd_option, 5> options{sd_option::ipv4_endpoint(ip4("1.2.3.4"), 17, 5),
                                         sd_option::ipv6_multicast(ip6("ff02::1"), 6), sd_option::load_balancing(1, 2),
                                         sd_option::configuration(bytes(cfg.data(), cn)),
                                         sd_option::ipv6_sd_endpoint(ip6("fd00::9"))};
  const std::array<pdu, 2> pdus{pdu{7, bytes(pl).first(3)}, pdu{8, bytes(pl).first(1)}};
  auto add = [&](auto&&... l) {
    auto f = make_frame(l...);
    if (f) c.push_back(*f);
  };
  add(eth{}, vlan{.tpid = ethertype::qinq}, vlan{}, ipv4{.options = opts}, udp{}, someip{}, raw{pl});
  add(eth{}, ipv4{}, udp{}, someip_sd_header(), someip_sd{.entries = entries, .options = options});
  add(eth{}, ipv6{}, ipv6_hbh{.options = opts}, ipv6_srh{.segments = segs}, ipv6_dstopts{}, udp{}, someip{}, raw{pl});
  add(eth{}, ipv6{}, ipv6_frag{.more = true}, udp{}, raw{pl});
  add(eth{}, ipv4{.mf = true}, udp{}, someip{.tp = someip_tp{.offset = 32, .more = true}}, raw{pl});
  add(eth{}, ipv4{}, tcp{.options = opts}, raw{pl});
  add(eth{}, ipv4{}, udp{}, soad_pdu{.id = 1, .data = pl}, soad_pdu_header{.id = 2}, ipdum_container{.pdus = pdus});
  add(eth{}, ipv4{}, udp{}, someip{}, raw{bytes(pl).first(4)}, someip{}, raw{pl});
  return c;
}

struct xorshift {
  std::uint64_t s = 0x9e3779b97f4a7c15ull;
  std::uint64_t operator()() {
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    return s;
  }
};
}  // namespace

TEST(every_truncation_of_every_frame) {
  int bad = 0;
  CHECK_EQ(corpus().size(), 8u);  // every corpus frame built
  for (const auto& f : corpus())
    for (std::size_t n = 0; n <= f.size(); ++n)
      if (!exercise_exact(bytes(f).first(n))) ++bad;
  CHECK_EQ(bad, 0);
}

TEST(random_mutations) {
  xorshift rng;
  auto c = corpus();
  int bad = 0;
  for (int it = 0; it < 60000; ++it) {
    auto f = c[rng() % c.size()];
    const int flips = 1 + int(rng() % 6);
    for (int k = 0; k < flips; ++k) f[rng() % f.size()] = std::byte(rng());
    const std::size_t n = (rng() % 4 == 0) ? std::size_t(rng() % (f.size() + 1)) : f.size();
    if (!exercise_exact(bytes(f).first(n))) ++bad;
  }
  CHECK_EQ(bad, 0);
}

TEST(random_garbage) {
  xorshift rng;
  int bad = 0;
  std::vector<std::byte> g;
  for (int it = 0; it < 20000; ++it) {
    g.resize(rng() % 200);
    for (auto& b : g) b = std::byte(rng() % 4 == 0 ? 0 : rng());
    if (!exercise_exact(g)) ++bad;
  }
  CHECK_EQ(bad, 0);
}

TEST(reassemblers_on_mutated_fragments) {
  xorshift rng;
  ipv4_reassembler r4(ip_reassembly_defaults());
  ipv6_reassembler r6(ip_reassembly_defaults());
  someip_tp_reassembler tp(tp_reassembly_defaults());
  auto c = corpus();
  std::vector<std::vector<std::byte>> keep;  // reassemblers hold views: keep buffers alive
  keep.reserve(30000);
  for (int it = 0; it < 30000; ++it) {
    auto f = c[3 + rng() % 2];  // the fragment / TP frames
    for (int k = 0; k < 3; ++k) f[14 + rng() % (f.size() - 14)] = std::byte(rng());
    keep.push_back(std::move(f));
    const auto pkt = packet::parse(keep.back());
    for (auto r : {feed(r4, pkt, u64(it)).status, feed(r6, pkt, u64(it)).status}) g_sink += u8(r);
    for (auto m : pkt.someip_all()) {
      auto r = feed(tp, pkt, m, u64(it));
      if (r.complete()) g_sink += r.parts.size();
    }
    if (it % 1000 == 0) r4.expire(u64(it)), r6.expire(u64(it)), tp.expire(u64(it));
  }
  CHECK(r4.in_flight() <= r4.config().max_in_flight);
  CHECK(tp.in_flight() <= tp.config().max_in_flight);
}

TEST(regression_vlan_cap_ipv6_guard_and_large_frag6_off) {
  // 64 VLAN tags + IPv4 parses cleanly; 65 VLAN tags stops at 64 with malformed flag
  {
    std::vector<std::byte> f(14 + 65 * 4 + 20, std::byte{0});
    detail::put_be16(f.data() + 12, ethertype::vlan);
    for (std::size_t i = 0; i < 65; ++i) {
      detail::put_be16(f.data() + 14 + 4 * i, u16(i + 1));
      detail::put_be16(f.data() + 14 + 4 * i + 2, i < 64 ? ethertype::vlan : ethertype::ipv4);
    }
    const auto p65 = packet::parse(f);
    CHECK(p65.is_malformed());
    CHECK_EQ(p65.vlan_count(), 64u);
    CHECK(p65.l3() == l3_kind::none);

    // Change 64th tag's inner ethertype to IPv4 and put minimal IPv4 header after 64 tags
    detail::put_be16(f.data() + 14 + 4 * 63 + 2, ethertype::ipv4);
    f[14 + 4 * 64] = std::byte{0x45};
    detail::put_be16(f.data() + 14 + 4 * 64 + 2, 20);
    const auto p64 = packet::parse(f);
    CHECK(!p64.is_malformed());
    CHECK_EQ(p64.vlan_count(), 64u);
    CHECK(p64.l3() == l3_kind::ipv4);
  }

  // 65 chained IPv6 extension headers -> hits 64-header guard and sets malformed
  {
    std::vector<std::byte> f(40 + 65 * 8, std::byte{0});
    f[0] = std::byte{0x60};
    detail::put_be16(f.data() + 4, u16(65 * 8));
    f[6] = std::byte(ip_proto::ipv6_opts);
    for (std::size_t i = 0; i < 65; ++i) {
      f[40 + i * 8] = std::byte(i < 64 ? ip_proto::ipv6_opts : ip_proto::no_next);
      f[40 + i * 8 + 1] = std::byte{0};  // 8 bytes each
    }
    const auto pkt = packet::parse(f, link_type::raw);
    CHECK(pkt.l3() == l3_kind::ipv6);
    CHECK(pkt.is_malformed());
    CHECK(pkt.l4() == l4_kind::none);
  }

  // frag6_off_ >= 65536 (33 Destination Options headers of 2048 bytes each = 67584 bytes, then Fragment Header)
  {
    constexpr std::size_t nhdrs = 33;
    constexpr std::size_t ext_len = 2048;  // hdr_ext_len = 255 -> (255 + 1) * 8 = 2048
    constexpr std::size_t frag_off = 40 + nhdrs * ext_len;  // 67624 > 65535
    std::vector<std::byte> f(frag_off + 8 + 16, std::byte{0});
    f[0] = std::byte{0x60};
    detail::put_be16(f.data() + 4, 0);  // payload_length == 0 -> jumbogram (to end of buffer)
    f[6] = std::byte(ip_proto::ipv6_opts);
    for (std::size_t i = 0; i < nhdrs; ++i) {
      f[40 + i * ext_len] = std::byte(i + 1 < nhdrs ? ip_proto::ipv6_opts : ip_proto::ipv6_frag);
      f[40 + i * ext_len + 1] = std::byte{255};
    }
    // Fragment Header at frag_off: next=17 (UDP), offset=2 (16 bytes), more=1, id=0x12345678
    f[frag_off] = std::byte(ip_proto::udp);
    detail::put_be16(f.data() + frag_off + 2, u16((2u << 3) | 1u));
    detail::put_be32(f.data() + frag_off + 4, 0x12345678u);
    const auto pkt = packet::parse(f, link_type::raw);
    CHECK(!pkt.is_malformed());
    CHECK(pkt.is_fragment());
    auto fh = pkt.ipv6_fragment();
    CHECK(fh.has_value());
    CHECK_EQ(fh->identification(), 0x12345678u);
    CHECK_EQ(fh->offset_bytes(), 16u);
    CHECK(fh->more());
    CHECK_EQ(pkt.fragment_data().size(), 16u);
  }
}

TEST_MAIN()
