// SPDX-License-Identifier: Apache-2.0
// Zero-copy reassembly: IPv4, IPv6 and SOME/IP-TP; in-order, out-of-order, overlap, duplicate,
// conflict policies, timeout, capacity, limits, token release, aliasing (zero copy) and
// no allocation in steady state.
#include "check.hpp"

#include <nanowire/nanowire.hpp>

#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <new>
#include <random>
#include <vector>

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wmismatched-new-delete"
#endif
// ---- allocation counter (for the steady-state no-allocation check) ----
static std::atomic<long> g_allocs{0};
void* operator new(std::size_t n) {
  ++g_allocs;
  if (void* p = std::malloc(n ? n : 1)) return p;
  throw std::bad_alloc();
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }

using namespace nanowire;

namespace {
using frames = std::vector<std::vector<std::byte>>;

std::vector<std::byte> pattern(std::size_t n, unsigned seed = 1) {
  std::vector<std::byte> v(n);
  for (std::size_t i = 0; i < n; ++i) v[i] = std::byte((i * 131 + seed * 7) & 0xff);
  return v;
}

/// The L4 datagram (UDP header + SOME/IP + payload) that gets fragmented.
std::vector<std::byte> udp_datagram(std::size_t payload) {
  auto pl = pattern(payload);
  return *make_frame(udp{.src_port = 30501, .dst_port = 30501}, someip{.service_id = 0x1234, .method_id = 0x8004},
                     raw{pl});
}

/// IPv4 fragments of `dgram` (chunk = multiple of 8), each a complete Ethernet frame.
frames ipv4_fragments(const std::vector<std::byte>& dgram, std::size_t chunk, u16 id) {
  frames f;
  for (std::size_t off = 0; off < dgram.size(); off += chunk) {
    const std::size_t n = std::min(chunk, dgram.size() - off);
    f.push_back(*make_frame(eth{}, ipv4{.src = ip4("10.0.0.1"), .dst = ip4("10.0.0.2"), .id = id,
                                        .mf = off + n < dgram.size(), .frag_offset = u16(off / 8),
                                        .protocol = ip_proto::udp},
                            raw{bytes(dgram).subspan(off, n)}));
  }
  return f;
}
frames ipv6_fragments(const std::vector<std::byte>& dgram, std::size_t chunk, u32 id) {
  frames f;
  for (std::size_t off = 0; off < dgram.size(); off += chunk) {
    const std::size_t n = std::min(chunk, dgram.size() - off);
    f.push_back(*make_frame(eth{}, ipv6{.src = ip6("fd00::1"), .dst = ip6("fd00::2")},
                            ipv6_frag{.offset = u16(off / 8), .more = off + n < dgram.size(), .id = id,
                                      .next_header = ip_proto::udp},
                            raw{bytes(dgram).subspan(off, n)}));
  }
  return f;
}

std::vector<std::byte> materialize(const nanom::segments& s) {
  std::vector<std::byte> v(s.size());
  CHECK_EQ(copy_to(s, v), s.size());
  return v;
}

bool aliases(const nanom::segments& s, const frames& src) {
  for (std::size_t i = 0; i < s.parts(); ++i) {
    const auto p = s.part(i);
    bool in = false;
    for (const auto& f : src)
      if (p.data() >= f.data() && p.data() + p.size() <= f.data() + f.size()) in = true;
    if (!in) return false;
  }
  return true;
}

struct token_log {
  std::vector<u64> released;
  std::vector<drop_reason> drops;
  static void rel(void* c, u64 t) { static_cast<token_log*>(c)->released.push_back(t); }
  static void drop(void* c, const ipv4_frag_key&, drop_reason r, u32, u32) {
    static_cast<token_log*>(c)->drops.push_back(r);
  }
  ipv4_reassembler::hooks hooks() { return {rel, drop, this}; }
};

/// Raw add() of byte ranges of `whole` (offset, size, more) with a fixed key.
ipv4_reassembler::result put(ipv4_reassembler& r, const std::vector<std::byte>& whole, u32 off, u32 n, bool more,
                             u64 now = 0, u64 tok = 0, u16 id = 1) {
  return r.add(ipv4_frag_key{{1, 1, 1, 1}, {2, 2, 2, 2}, 17, id}, now, off, more, bytes(whole).subspan(off, n), tok);
}
}  // namespace

TEST(ipv4_in_order_zero_copy) {
  const auto dgram = udp_datagram(3000);
  const auto fr = ipv4_fragments(dgram, 1480, 7);
  CHECK_EQ(fr.size(), 3u);
  ipv4_reassembler r(ip_reassembly_defaults());
  for (std::size_t i = 0; i < fr.size(); ++i) {
    const auto pkt = packet::parse(fr[i]);
    CHECK(pkt.is_fragment());
    auto res = feed(r, pkt, i);
    if (i + 1 < fr.size()) {
      CHECK(res.status == frag_status::buffered);
      CHECK(res.retained);
    } else {
      CHECK(res.complete());
      CHECK_EQ(res.meta, 17u);
      CHECK_EQ(res.size(), dgram.size());
      CHECK(materialize(res.parts) == dgram);
      CHECK(aliases(res.parts, fr));  // every part points into a source frame: no copy happened
      // parse straight over the segments (UDP header, then SOME/IP header across a seam-free part)
      auto u = nanom::strct_seg<wire::udp_hdr>(std::endian::big)(res.input());
      CHECK(u.has_value());
      CHECK_EQ(u16(u->value.dst_port), 30501);
      auto s = nanom::strct_seg<wire::someip_hdr>(std::endian::big)(u->rest);
      CHECK(s && u16(s->value.service_id) == 0x1234 && u32(s->value.length) == 8 + 3000);
    }
  }
  CHECK_EQ(r.stats().completed, 1u);
}

TEST(ipv4_out_of_order_permutations) {
  const auto dgram = udp_datagram(5000);
  auto fr = ipv4_fragments(dgram, 512, 9);
  std::mt19937 rng(3);
  ipv4_reassembler r(ip_reassembly_defaults());
  for (int round = 0; round < 50; ++round) {
    std::shuffle(fr.begin(), fr.end(), rng);
    int completes = 0;
    for (std::size_t i = 0; i < fr.size(); ++i) {
      auto res = feed(r, packet::parse(fr[i]), u64(round));
      if (res.complete()) {
        ++completes;
        CHECK_EQ(i + 1, fr.size());
        CHECK(materialize(res.parts) == dgram);
      }
    }
    CHECK_EQ(completes, 1);
  }
  CHECK_EQ(r.in_flight(), 1u);  // the last completed datagram awaits auto release
}

TEST(duplicates_and_benign_overlap) {
  const auto d = pattern(64);
  ipv4_reassembler r(ip_reassembly_defaults());
  CHECK(put(r, d, 0, 24, true).status == frag_status::buffered);
  auto dup = put(r, d, 0, 24, true);
  CHECK(dup.status == frag_status::duplicate);
  CHECK(!dup.retained);
  CHECK(put(r, d, 16, 24, true).status == frag_status::buffered);  // overlaps [16,24) with equal bytes
  CHECK(put(r, d, 8, 8, true).status == frag_status::duplicate);   // fully covered
  auto last = put(r, d, 32, 32, false);
  CHECK(last.complete());
  CHECK(materialize(last.parts) == d);
  CHECK_EQ(r.stats().duplicates, 2u);
}

TEST(overlap_policies) {
  const auto a = pattern(48, 1), b = pattern(48, 2);  // disagree everywhere
  for (auto pol : {overlap_policy::reject_conflict, overlap_policy::first_wins, overlap_policy::last_wins}) {
    auto cfg = ip_reassembly_defaults();
    cfg.overlap = pol;
    token_log log;
    ipv4_reassembler r(cfg, log.hooks());
    put(r, a, 0, 24, true, 0, 1);
    put(r, a, 32, 16, false, 0, 2);
    auto res = put(r, b, 16, 24, true, 0, 3);  // [16,40) overlaps both neighbours
    if (pol == overlap_policy::reject_conflict) {
      CHECK(res.status == frag_status::dropped && res.reason == drop_reason::conflict);
      CHECK(log.drops.size() == 1 && log.drops[0] == drop_reason::conflict);
      CHECK((log.released == std::vector<u64>{1, 2}));  // both stored fragments given back
      CHECK_EQ(r.in_flight(), 0u);
    } else {
      CHECK(res.complete());
      const auto m = materialize(res.parts);
      std::vector<std::byte> want(48);
      for (std::size_t i = 0; i < 48; ++i) {
        const bool new_bytes = i >= 16 && i < 40;
        const bool b_wins = pol == overlap_policy::last_wins ? new_bytes : (i >= 24 && i < 32);
        want[i] = b_wins ? b[i] : a[i];
      }
      CHECK(m == want);
    }
  }
}

TEST(timeout_capacity_limits) {
  auto cfg = ip_reassembly_defaults();
  cfg.timeout = 100;
  cfg.max_in_flight = 2;
  cfg.max_fragments = 3;
  cfg.max_datagram = 4096;
  token_log log;
  ipv4_reassembler r(cfg, log.hooks());
  const auto d = pattern(8192);
  put(r, d, 0, 16, true, 0, 10, 1);
  put(r, d, 0, 16, true, 50, 20, 2);
  CHECK_EQ(r.expire(100), 0u);
  CHECK_EQ(r.expire(101), 1u);  // id 1 idle > 100
  CHECK(log.drops.back() == drop_reason::timeout);
  CHECK(log.released.back() == 10);
  CHECK_EQ(r.stats().timeouts, 1u);
  // capacity: 2 slots; a third datagram evicts the least recently fed
  put(r, d, 0, 16, true, 120, 30, 3);
  put(r, d, 0, 16, true, 130, 40, 4);  // evicts id 2 (last fed at 50)
  CHECK_EQ(r.stats().evictions, 1u);
  CHECK(log.drops.back() == drop_reason::capacity);
  CHECK(log.released.back() == 20);
  // too many fragments for one datagram
  put(r, d, 16, 16, true, 131, 0, 3);
  put(r, d, 32, 16, true, 132, 0, 3);
  auto tm = put(r, d, 48, 16, true, 133, 0, 3);
  CHECK(tm.status == frag_status::dropped && tm.reason == drop_reason::too_many_fragments);
  // too large
  auto tl = put(r, d, 4096, 16, false, 134, 0, 9);
  CHECK(tl.reason == drop_reason::too_large);
  // misaligned non-last fragment
  auto ma = put(r, d, 0, 12, true, 135, 0, 10);
  CHECK(ma.reason == drop_reason::misaligned);
  // inconsistent ends: two different last fragments
  CHECK(put(r, d, 16, 16, false, 136, 0, 11).status == frag_status::buffered);  // end = 32
  auto ie = put(r, d, 24, 16, false, 137, 0, 11);                                 // end = 40
  CHECK(ie.status == frag_status::dropped && ie.reason == drop_reason::inconsistent);
  // no eviction mode: a full table refuses new datagrams
  cfg.evict_oldest_when_full = false;
  ipv4_reassembler r2(cfg);
  put(r2, d, 0, 16, true, 0, 0, 1);
  put(r2, d, 0, 16, true, 0, 0, 2);
  CHECK(put(r2, d, 0, 16, true, 0, 0, 3).reason == drop_reason::capacity);
}

TEST(tokens_released_after_completion) {
  token_log log;
  auto cfg = ip_reassembly_defaults();
  cfg.auto_release = false;
  ipv4_reassembler r(cfg, log.hooks());
  const auto d = pattern(32);
  put(r, d, 16, 16, false, 0, 2);
  auto res = put(r, d, 0, 16, true, 0, 1);
  CHECK(res.complete());
  CHECK(log.released.empty());  // still pinned while the caller reads the parts
  r.release(res.id);
  std::sort(log.released.begin(), log.released.end());
  CHECK((log.released == std::vector<u64>{1, 2}));
  r.release(res.id);  // stale handle: no-op
  CHECK_EQ(log.released.size(), 2u);
  // auto release: tokens come back on the next call
  token_log log2;
  ipv4_reassembler r2(ip_reassembly_defaults(), log2.hooks());
  put(r2, d, 16, 16, false, 0, 5);
  CHECK(put(r2, d, 0, 16, true, 0, 6).complete());
  CHECK(log2.released.empty());
  r2.expire(1);
  CHECK_EQ(log2.released.size(), 2u);
}

TEST(ipv6_reassembly_from_packets) {
  const auto dgram = udp_datagram(3000);
  auto fr = ipv6_fragments(dgram, 1232, 0xabcdef);
  std::reverse(fr.begin(), fr.end());
  ipv6_reassembler r(ip_reassembly_defaults());
  ipv6_reassembler::result last;
  for (auto& f : fr) last = feed(r, packet::parse(f), 0);
  CHECK(last.complete());
  CHECK_EQ(last.meta, 17u);  // next header from the offset-0 fragment
  CHECK(materialize(last.parts) == dgram);
  CHECK(aliases(last.parts, fr));
  // a non-fragment is ignored
  auto plain = *make_frame(eth{}, ipv6{}, udp{}, raw{});
  CHECK(feed(r, packet::parse(plain), 0).status == frag_status::not_fragment);
}

namespace {
frames tp_segments(const std::vector<std::byte>& payload, std::size_t seg, u16 session, u16 sport = 30501) {
  frames f;
  for (std::size_t off = 0; off < payload.size(); off += seg) {
    const std::size_t n = std::min(seg, payload.size() - off);
    f.push_back(*make_frame(eth{}, ipv4{.src = ip4("10.0.0.1"), .dst = ip4("10.0.0.2")},
                            udp{.src_port = sport, .dst_port = 30501},
                            someip{.service_id = 0x1234, .method_id = 0x8003, .client_id = 1, .session_id = session,
                                   .message_type = someip_type::notification,
                                   .tp = someip_tp{.offset = u32(off), .more = off + n < payload.size()}},
                            raw{bytes(payload).subspan(off, n)}));
  }
  return f;
}
}  // namespace

TEST(someip_tp_reassembly) {
  const auto payload = pattern(5000, 9);
  auto segs = tp_segments(payload, 1392, 77);
  CHECK_EQ(segs.size(), 4u);
  std::swap(segs[0], segs[2]);
  someip_tp_reassembler r(tp_reassembly_defaults());
  someip_tp_reassembler::result res;
  for (auto& s : segs) {
    const auto pkt = packet::parse(s);
    res = feed(r, pkt, *pkt.someip(), 0);
  }
  CHECK(res.complete());
  CHECK_EQ(res.size(), 16u + 5000);
  const auto msg = materialize(res.parts);
  auto m = someip_view::parse(msg);
  CHECK(m.has_value());
  CHECK_EQ(m->length(), 8u + 5000);
  CHECK_EQ(m->message_type(), someip_type::notification);  // TP flag cleared
  CHECK(!m->is_tp());
  CHECK_EQ(m->session_id(), 77);
  CHECK(std::equal(payload.begin(), payload.end(), m->payload().begin()));
  // the payload parts alias the captured frames (only the 16-byte header was rebuilt)
  CHECK(aliases(nanom::segments(res.part_list.subspan(1)), segs));
}

TEST(someip_tp_new_session_supersedes) {
  const auto p1 = pattern(3000, 1), p2 = pattern(3000, 2);
  auto s1 = tp_segments(p1, 1392, 1), s2 = tp_segments(p2, 1392, 2);
  std::vector<drop_reason> drops;
  someip_tp_reassembler r(tp_reassembly_defaults(),
                          {nullptr,
                           [](void* c, const someip_tp_key&, drop_reason why, u32, u32) {
                             static_cast<std::vector<drop_reason>*>(c)->push_back(why);
                           },
                           &drops});
  auto f = [&](const std::vector<std::byte>& fr) {
    const auto pkt = packet::parse(fr);
    return feed(r, pkt, *pkt.someip(), 0);
  };
  f(s1[0]);
  f(s1[1]);
  someip_tp_reassembler::result last;
  for (auto& s : s2) last = f(s);  // session 2 aborts session 1
  CHECK(drops.size() == 1 && drops[0] == drop_reason::superseded);
  CHECK(last.complete());
  const auto msg = materialize(last.parts);
  CHECK(std::equal(p2.begin(), p2.end(), msg.begin() + 16));
  // a different sender port is a different key: no interference
  auto s3 = tp_segments(p1, 1392, 1, 40000);
  someip_tp_reassembler::result l3;
  for (auto& s : s3) l3 = f(s);
  CHECK(l3.complete());
}

TEST(someip_tp_misaligned_segment) {
  const auto payload = pattern(100);
  auto bad = *make_frame(eth{}, ipv4{}, udp{}, someip{.tp = someip_tp{.offset = 0, .more = true}},
                         raw{bytes(payload).first(40)});  // 40 is not a multiple of 16
  someip_tp_reassembler r(tp_reassembly_defaults());
  const auto pkt = packet::parse(bad);
  auto res = feed(r, pkt, *pkt.someip(), 0);
  CHECK(res.status == frag_status::dropped && res.reason == drop_reason::misaligned);
}

TEST(no_allocation_in_steady_state) {
  const auto dgram = udp_datagram(4000);
  std::vector<frames> sets;
  for (u16 id = 0; id < 64; ++id) sets.push_back(ipv4_fragments(dgram, 1480, id));
  const auto tp = tp_segments(pattern(4000), 1392, 5);
  ipv4_reassembler r(ip_reassembly_defaults());
  someip_tp_reassembler t(tp_reassembly_defaults());
  // warm up once, then count
  std::size_t done = 0;
  auto run = [&] {
    for (auto& s : sets)
      for (std::size_t i = s.size(); i-- > 0;) done += feed(r, packet::parse(s[i]), 1).complete();
    for (auto& s : tp) {
      const auto pkt = packet::parse(s);
      done += feed(t, pkt, *pkt.someip(), 1).complete();
    }
  };
  run();
  const long before = g_allocs.load();
  for (int i = 0; i < 20; ++i) run();
  CHECK_EQ(g_allocs.load() - before, 0);
  CHECK_EQ(done, 21u * 65);
}

TEST(regression_too_many_frags_bounds_empty_and_epoch) {
  // 1. max_datagram clamping & overflow-safe offset + size check
  {
    reassembly_config c;
    c.max_datagram = std::size_t(-1);
    ipv4_reassembler r4(c);
    CHECK_EQ(r4.config().max_datagram, 0xFFFFFFFEu);
    someip_tp_reassembler rtp(c);
    CHECK_EQ(rtp.config().max_datagram, 0xFFFFFFF7u);

    const auto d = pattern(32);
    auto ovf = r4.add(ipv4_frag_key{{1, 1, 1, 1}, {2, 2, 2, 2}, 17, 1}, 0, 0xFFFFFFF0u, false, d);
    CHECK(ovf.status == frag_status::dropped && ovf.reason == drop_reason::too_large);
    CHECK_EQ(r4.in_flight(), 0u);
  }

  // 2. too_many_fragments does not inflate hooks_.dropped bytes, and duplicate at limit still works
  {
    struct drop_info {
      drop_reason why = drop_reason::none;
      u32 bytes = 0;
      u32 frags = 0;
      int count = 0;
    } info;
    auto cfg = ip_reassembly_defaults();
    cfg.max_fragments = 2;
    ipv4_reassembler r(cfg, {nullptr,
                             [](void* c, const ipv4_frag_key&, drop_reason why, u32 b, u32 f) {
                               auto* di = static_cast<drop_info*>(c);
                               di->why = why;
                               di->bytes = b;
                               di->frags = f;
                               ++di->count;
                             },
                             &info});
    const auto d = pattern(64);
    CHECK(put(r, d, 0, 16, true).status == frag_status::buffered);
    CHECK(put(r, d, 16, 16, true).status == frag_status::buffered);
    // Exact duplicate at max_fragments is accepted as duplicate without killing slot
    CHECK(put(r, d, 0, 16, true).status == frag_status::duplicate);
    CHECK_EQ(info.count, 0);
    // 3rd distinct fragment trips too_many_fragments with pre-fragment covered == 32 (not 48)
    auto tm = put(r, d, 32, 16, true);
    CHECK(tm.status == frag_status::dropped && tm.reason == drop_reason::too_many_fragments);
    CHECK_EQ(info.count, 1);
    CHECK(info.why == drop_reason::too_many_fragments);
    CHECK_EQ(info.bytes, 32u);
    CHECK_EQ(info.frags, 2u);
  }

  // 3. Empty non-last fragments rejected without allocating slot; 0-byte terminal fragment works cleanly
  {
    const auto d = pattern(32);
    for (auto pol : {overlap_policy::reject_conflict, overlap_policy::last_wins}) {
      auto cfg = ip_reassembly_defaults();
      cfg.overlap = pol;
      ipv4_reassembler r(cfg);
      // Empty non-last fragment: dropped, no slot allocated
      auto bad = r.add(ipv4_frag_key{{1, 1, 1, 1}, {2, 2, 2, 2}, 17, 1}, 0, 0, true, bytes{});
      CHECK(bad.status == frag_status::dropped);
      CHECK_EQ(r.in_flight(), 0u);

      // Valid 0-byte terminal fragment arriving FIRST, then data -> completes without duplicate count
      auto term = r.add(ipv4_frag_key{{1, 1, 1, 1}, {2, 2, 2, 2}, 17, 2}, 0, 16, false, bytes{});
      CHECK(term.status == frag_status::buffered && !term.retained);
      CHECK_EQ(r.stats().duplicates, 0u);
      // Duplicate 0-byte terminal fragment increments duplicates
      auto term_dup = r.add(ipv4_frag_key{{1, 1, 1, 1}, {2, 2, 2, 2}, 17, 2}, 0, 16, false, bytes{});
      CHECK(term_dup.status == frag_status::duplicate);
      CHECK_EQ(r.stats().duplicates, 1u);
      auto body = r.add(ipv4_frag_key{{1, 1, 1, 1}, {2, 2, 2, 2}, 17, 2}, 0, 0, true, bytes(d).first(16));
      CHECK(body.complete());
      CHECK(materialize(body.parts) == std::vector<std::byte>(d.begin(), d.begin() + 16));

      // Valid 0-byte terminal fragment arriving LAST -> completes without duplicate count
      const u64 dup_before = r.stats().duplicates;
      CHECK(put(r, d, 0, 16, true, 0, 0, 3).status == frag_status::buffered);
      auto fin = r.add(ipv4_frag_key{{1, 1, 1, 1}, {2, 2, 2, 2}, 17, 3}, 0, 16, false, bytes{});
      CHECK(fin.complete());
      CHECK_EQ(r.stats().duplicates, dup_before);
      CHECK(materialize(fin.parts) == std::vector<std::byte>(d.begin(), d.begin() + 16));

      // 0-byte datagram
      auto zero = r.add(ipv4_frag_key{{1, 1, 1, 1}, {2, 2, 2, 2}, 17, 4}, 0, 0, false, bytes{});
      CHECK(zero.complete());
      CHECK_EQ(zero.size(), 0u);
      CHECK_EQ(r.stats().duplicates, dup_before);
    }
  }

  // 4. Misaligned fragment from a different epoch must NOT kill the current epoch's slot
  {
    someip_tp_reassembler r(tp_reassembly_defaults());
    const auto d = pattern(32);
    someip_tp_key k{};
    k.message_id = 0x12348001u;
    std::array<std::byte, 16> hdr{};
    CHECK(r.add(k, 0, 0, true, bytes(d).first(16), 1, /*epoch=*/2, 0, hdr).status == frag_status::buffered);
    // Stray misaligned segment from old epoch 1
    auto ma = r.add(k, 1, 0, true, bytes(d).first(10), 2, /*epoch=*/1, 0, hdr);
    CHECK(ma.status == frag_status::dropped && ma.reason == drop_reason::misaligned);
    CHECK_EQ(r.in_flight(), 1u);  // epoch 2 slot survived!
    auto fin = r.add(k, 2, 16, false, bytes(d).subspan(16, 16), 3, /*epoch=*/2, 0, hdr);
    CHECK(fin.complete());
    CHECK_EQ(fin.size(), 16u + 32u);
  }
}

TEST_MAIN()
