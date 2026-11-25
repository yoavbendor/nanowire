// SPDX-License-Identifier: Apache-2.0
// The C++ side of the scapy oracle (tests/oracle/scapy_oracle.py).
//
//   test_oracle parse IN.pcap IN.kv    nanowire's reading of a scapy-built capture must equal
//                                      scapy's own dissection (IN.kv), key for key
//   test_oracle build OUT.pcap OUT.kv  write frames built with nanowire's builders, plus what they
//                                      are meant to contain; `scapy_oracle.py check` then verifies
//                                      them with scapy (fields + every length / checksum)
//
// describe() must produce exactly the keys scapy_oracle.py's describe() does.
#include <nanowire/nanowire.hpp>

#include <cstdio>
#include <cstring>
#include <fstream>
#include <map>
#include <random>
#include <sstream>
#include <string>
#include <vector>

using namespace nanowire;
using kvmap = std::map<std::string, std::string>;

namespace {
constexpr u16 pdu_port = 42000;
bool someip_port(u16 p) { return p == 30490 || p == 30501; }
std::string hex(bytes b) {
  static constexpr char h[] = "0123456789abcdef";
  std::string s;
  for (auto x : b) s += h[u8(x) >> 4], s += h[u8(x) & 15];
  return s.empty() ? "-" : s;
}

kvmap describe(const packet& pkt) {
  kvmap kv;
  auto set = [&](const std::string& k, auto v) {
    if constexpr (std::is_convertible_v<decltype(v), std::string>) kv[k] = v;
    else kv[k] = std::to_string(v);
  };
  auto e = pkt.eth();
  if (!e) return kv;
  set("eth.dst", to_string(e->dst()));
  set("eth.src", to_string(e->src()));
  set("eth.type", e->ethertype());
  set("vlan.n", pkt.vlan_count());
  for (std::size_t i = 0; i < pkt.vlan_count(); ++i) {
    const auto v = pkt.vlan(i);
    const std::string p = "vlan." + std::to_string(i) + ".";
    set(p + "vid", v.vid()), set(p + "pcp", v.pcp()), set(p + "dei", int(v.dei())), set(p + "type", v.ethertype());
  }
  if (auto ip = pkt.ipv4()) {
    set("ip.ihl", ip->ihl()), set("ip.dscp", ip->dscp()), set("ip.ecn", ip->ecn()), set("ip.len", ip->total_length());
    set("ip.id", ip->identification()), set("ip.df", int(ip->df())), set("ip.mf", int(ip->mf()));
    set("ip.frag", ip->frag_offset()), set("ip.ttl", ip->ttl()), set("ip.proto", ip->protocol());
    set("ip.chksum", ip->checksum()), set("ip.src", to_string(ip->src())), set("ip.dst", to_string(ip->dst()));
  }
  if (auto ip = pkt.ipv6()) {
    set("ip6.tc", ip->traffic_class()), set("ip6.fl", ip->flow_label()), set("ip6.plen", ip->payload_length());
    set("ip6.nh", ip->next_header()), set("ip6.hlim", ip->hop_limit());
    set("ip6.src", to_string(ip->src())), set("ip6.dst", to_string(ip->dst()));
    std::string ext;
    for (auto x : ip->extensions()) {
      ext += (ext.empty() ? "" : ",") + std::to_string(x.type());
      if (auto r = x.routing(); r && r->is_srh()) {
        set("srh.left", r->segments_left()), set("srh.last", r->last_entry());
        std::string segs;
        for (std::size_t i = 0; i < r->segment_count(); ++i) segs += (i ? "," : "") + to_string(r->segment(i));
        set("srh.segs", segs);
      }
      if (auto f = x.fragment()) set("frag6.off", f->offset()), set("frag6.m", int(f->more())), set("frag6.id", f->identification());
    }
    set("ip6.ext", ext.empty() ? std::string("-") : ext);
  }
  if (auto u = pkt.udp()) {
    set("udp.sport", u->src_port()), set("udp.dport", u->dst_port()), set("udp.len", u->length());
    set("udp.chksum", u->checksum());
  }
  if (auto t = pkt.tcp()) {
    set("tcp.sport", t->src_port()), set("tcp.dport", t->dst_port()), set("tcp.seq", t->seq()), set("tcp.ack", t->ack());
    set("tcp.dataofs", t->data_offset()), set("tcp.flags", t->flags()), set("tcp.window", t->window());
    set("tcp.chksum", t->checksum()), set("tcp.urgptr", t->urgent());
  }
  if (pkt.udp() && (someip_port(pkt.src_port()) || someip_port(pkt.dst_port())))
    if (auto m = pkt.someip()) {
      set("someip.srv", m->service_id()), set("someip.meth", m->method_id()), set("someip.len", m->length());
      set("someip.client", m->client_id()), set("someip.session", m->session_id());
      set("someip.proto", m->protocol_version()), set("someip.iface", m->interface_version());
      set("someip.type", m->message_type()), set("someip.rc", m->return_code());
      if (auto tp = m->tp()) set("tp.offset", tp->offset_bytes()), set("tp.more", int(tp->more()));
      if (auto sd = sd_view::parse(*m)) {
        set("sd.flags", sd->flags());
        set("sd.entries", sd->entries().size());
        std::size_t i = 0;
        for (auto en : sd->entries()) {
          const std::string p = "sd.e." + std::to_string(i++) + ".";
          set(p + "type", en.type()), set(p + "idx1", en.index_1()), set(p + "idx2", en.index_2());
          set(p + "n1", en.num_options_1()), set(p + "n2", en.num_options_2()), set(p + "srv", en.service_id());
          set(p + "inst", en.instance_id()), set(p + "major", en.major_version()), set(p + "ttl", en.ttl());
          if (en.is_service()) set(p + "minor", en.minor_version());
          else set(p + "cnt", en.counter()), set(p + "eg", en.eventgroup_id());
        }
        set("sd.options", sd->options().count());
        i = 0;
        for (auto o : sd->options()) {
          const std::string p = "sd.o." + std::to_string(i++) + ".";
          set(p + "type", o.type()), set(p + "len", o.length());
          if (auto ep = o.endpoint()) {
            set(p + "addr", ep->is_v6 ? to_string(ep->v6) : to_string(ep->v4));
            set(p + "proto", ep->l4_proto), set(p + "port", ep->port);
          } else if (auto lb = o.load_balancing()) {
            set(p + "prio", lb->priority), set(p + "weight", lb->weight);
          } else if (o.type() == sd_option_type::configuration) {
            set(p + "cfg", hex(o.body()));
          }
        }
      }
    }
  if (pkt.udp() && pkt.dst_port() == pdu_port) {
    std::size_t n = 0;
    for (auto p : soad_pdus(pkt.payload())) {
      set("pdu." + std::to_string(n) + ".id", p.id), set("pdu." + std::to_string(n) + ".len", p.data.size());
      ++n;
    }
    set("pdu.n", n);
  }
  return kv;
}

std::vector<std::vector<std::byte>> read_pcap(const char* path) {
  std::ifstream f(path, std::ios::binary);
  std::vector<char> d((std::istreambuf_iterator<char>(f)), {});
  std::vector<std::vector<std::byte>> out;
  std::size_t o = 24;
  auto rd = [&](std::size_t at) {
    u32 v;
    std::memcpy(&v, d.data() + at, 4);
    return v;
  };
  while (o + 16 <= d.size()) {
    const u32 cap = rd(o + 8);
    if (o + 16 + cap > d.size()) break;
    out.emplace_back(reinterpret_cast<const std::byte*>(d.data() + o + 16),
                     reinterpret_cast<const std::byte*>(d.data() + o + 16 + cap));
    o += 16 + cap;
  }
  return out;
}
void write_pcap(const char* path, const std::vector<std::vector<std::byte>>& frames) {
  std::ofstream f(path, std::ios::binary);
  const u32 gh[6] = {0xa1b2c3d4u, 0x00040002u, 0, 0, 65535, 1};
  f.write(reinterpret_cast<const char*>(gh), 24);
  u32 i = 0;
  for (const auto& fr : frames) {
    const u32 rh[4] = {i, 0, u32(fr.size()), u32(fr.size())};
    ++i;
    f.write(reinterpret_cast<const char*>(rh), 16);
    f.write(reinterpret_cast<const char*>(fr.data()), std::streamsize(fr.size()));
  }
}
std::vector<kvmap> read_kv(const char* path) {
  std::ifstream f(path);
  std::vector<kvmap> out;
  for (std::string line; std::getline(f, line);) {
    if (line.empty()) continue;
    kvmap m;
    std::istringstream is(line);
    for (std::string tok; is >> tok;) {
      const auto eq = tok.find('=');
      m[tok.substr(0, eq)] = tok.substr(eq + 1);
    }
    out.push_back(std::move(m));
  }
  return out;
}

int parse_mode(const char* pcap, const char* kvpath) {
  const auto frames = read_pcap(pcap);
  const auto want = read_kv(kvpath);
  int bad = 0;
  if (frames.size() != want.size() || frames.empty()) {
    std::printf("packet count %zu vs %zu\n", frames.size(), want.size());
    return 1;
  }
  std::size_t keys = 0;
  for (std::size_t i = 0; i < frames.size(); ++i) {
    const auto got = describe(packet::parse(frames[i]));
    for (const auto& [k, v] : want[i]) {
      ++keys;
      auto it = got.find(k);
      if (it == got.end() || it->second != v) {
        std::printf("pkt %zu: %s: nanowire=%s scapy=%s\n", i, k.c_str(), it == got.end() ? "(missing)" : it->second.c_str(),
                    v.c_str());
        ++bad;
      }
    }
    for (const auto& [k, v] : got)
      if (!want[i].count(k)) {
        std::printf("pkt %zu: %s: nanowire=%s scapy=(missing)\n", i, k.c_str(), v.c_str());
        ++bad;
      }
  }
  std::printf("%zu packets, %zu fields compared, %d mismatches\n", frames.size(), keys, bad);
  return bad ? 1 : 0;
}

int build_mode(const char* pcap, const char* kvpath) {
  std::mt19937 rng(5);
  auto rnd = [&](u32 n) { return u32(rng() % n); };
  std::vector<std::vector<std::byte>> frames;
  std::vector<std::byte> pl(1500);
  for (auto& b : pl) b = std::byte(rnd(256));
  auto add = [&](auto&&... l) {
    auto f = make_frame(l...);
    if (!f) {
      std::printf("build failed at layer %zu\n", f.error().layer);
      std::exit(1);
    }
    frames.push_back(*f);
  };
  auto rsomeip = [&] {
    return someip{.service_id = u16(rnd(65536)), .method_id = u16(rnd(65536)), .client_id = u16(rnd(65536)),
                  .session_id = u16(rnd(65536)), .interface_version = u8(rnd(256)),
                  .message_type = std::array<u8, 5>{0, 1, 2, 0x80, 0x81}[rnd(5)], .return_code = u8(rnd(16))};
  };
  auto src = [&] { return mac_addr{2, 0, 0, 0, 0, u8(rnd(256))}; };
  const mac_addr dst = mac("02:00:00:00:00:02");
  for (int i = 0; i < 12; ++i)
    add(eth{.dst = dst, .src = src()},
        ipv4{.src = {10, 0, 0, u8(1 + rnd(254))}, .dst = {10, 0, 1, u8(1 + rnd(254))}, .ttl = u8(1 + rnd(255)),
             .dscp = u8(rnd(64)), .ecn = u8(rnd(4)), .id = u16(rnd(65536)), .df = true},
        udp{.src_port = rnd(2) ? u16(30501) : u16(40000), .dst_port = 30501}, rsomeip(), raw{bytes(pl).first(1 + rnd(63))});
  static const std::array<std::byte, 4> ra{std::byte{0x94}, std::byte{4}, std::byte{0}, std::byte{0}};
  for (int i = 0; i < 4; ++i)
    add(eth{.dst = dst, .src = src()}, vlan{.vid = u16(rnd(4096)), .pcp = u8(rnd(8)), .dei = rnd(2) == 1},
        ipv4{.src = ip4("10.0.0.1"), .dst = ip4("10.0.0.2"), .options = ra}, udp{.src_port = 30501, .dst_port = 30501},
        rsomeip(), raw{bytes(pl).first(1 + rnd(63))});
  add(eth{.dst = dst, .src = src()}, vlan{.vid = 10, .pcp = 5, .tpid = ethertype::qinq}, vlan{.vid = 100, .pcp = 3},
      ipv4{.src = ip4("10.0.0.1"), .dst = ip4("10.0.0.2")}, udp{.src_port = 1, .dst_port = 30501}, rsomeip(),
      raw{bytes(pl).first(9)});
  static const std::array<ipv6_addr, 3> segs{ip6("fc00::1"), ip6("fc00::2"), ip6("fc00::3")};
  static const std::array<std::byte, 4> ra6{std::byte{5}, std::byte{2}, std::byte{0}, std::byte{0}};
  add(eth{.dst = dst, .src = src()}, ipv6{.src = ip6("fd00::1"), .dst = ip6("fd00::2"), .traffic_class = 0xb8, .flow_label = 0x12345},
      ipv6_hbh{.options = ra6}, ipv6_srh{.segments = segs, .segments_left = 2}, ipv6_dstopts{},
      udp{.src_port = 30501, .dst_port = 30501}, rsomeip(), raw{bytes(pl).first(20)});
  add(eth{.dst = dst, .src = src()}, ipv6{.src = ip6("fd00::1"), .dst = ip6("fd00::2")},
      ipv6_frag{.offset = 0, .more = true, .id = 0xabcdef}, udp{.src_port = 30501, .dst_port = 30501}, rsomeip(),
      raw{bytes(pl).first(32)});
  add(eth{.dst = dst, .src = src()}, ipv6{.src = ip6("fd00::1"), .dst = ip6("fd00::2")},
      ipv6_frag{.offset = 5, .more = false, .id = 0xabcdef, .next_header = 17}, raw{bytes(pl).first(24)});
  static const std::array<std::byte, 8> tcpopt{std::byte{2}, std::byte{4}, std::byte{0x05}, std::byte{0xb4},
                                               std::byte{1}, std::byte{3}, std::byte{3}, std::byte{7}};
  add(eth{.dst = dst, .src = src()}, ipv4{.src = ip4("1.2.3.4"), .dst = ip4("5.6.7.8")},
      tcp{.src_port = 1234, .dst_port = 80, .seq = 1000, .ack = 2000, .flags = tcp_flag::syn | tcp_flag::ack,
          .window = 8192, .options = tcpopt},
      raw{bytes(pl).first(5)});
  for (u32 off : {0u, 1392u, 2784u})
    add(eth{.dst = dst, .src = src()}, ipv4{}, udp{.src_port = 30501, .dst_port = 30501},
        someip{.service_id = 0x1234, .method_id = 0x8003, .tp = someip_tp{.offset = off, .more = off < 2784}},
        raw{bytes(pl).first(off < 2784 ? 1392 : 100)});
  std::array<std::byte, 64> cfg{};
  const std::array<std::string_view, 2> items{"hello=world", "x=y"};
  const std::size_t cn = sd_encode_config(items, cfg);
  const std::array<sd_entry, 4> entries{
      sd_entry::find_service(0x1111, 0xFFFF, 0xFF, 0xFFFFFFFF, 3),
      sd_entry::offer_service(0x1234, 1, 1, 5).with_options(0, 2),
      sd_entry::subscribe(0x1234, 1, 1, 7, 5, 3).with_options(2, 1, 3, 3),
      sd_entry::subscribe_ack(0x1234, 1, 1, 7, 0),
  };
  const std::array<sd_option, 8> options{
      sd_option::ipv4_endpoint(ip4("10.0.0.1"), 17, 30501), sd_option::load_balancing(1, 2),
      sd_option::ipv4_multicast(ip4("239.0.0.1"), 30502),   sd_option::ipv6_endpoint(ip6("fd00::1"), 6, 30503),
      sd_option::ipv6_multicast(ip6("ff02::1"), 30504),     sd_option::configuration(bytes(cfg.data(), cn)),
      sd_option::ipv4_sd_endpoint(ip4("10.0.0.9")),         sd_option::ipv6_sd_endpoint(ip6("fd00::9"))};
  add(eth{.dst = dst, .src = src()}, ipv4{}, udp{.src_port = 30490, .dst_port = 30490}, someip_sd_header(3),
      someip_sd{.entries = entries, .options = options});
  static const std::array<std::byte, 3> abc{std::byte{'a'}, std::byte{'b'}, std::byte{'c'}};
  add(eth{.dst = dst, .src = src()}, ipv4{}, udp{.src_port = 50000, .dst_port = pdu_port}, soad_pdu{.id = 0x100, .data = abc},
      soad_pdu{.id = 0xdeadbeef}, soad_pdu{.id = 7, .data = bytes(pl).first(20)});

  write_pcap(pcap, frames);
  std::ofstream kv(kvpath);
  for (const auto& f : frames) {
    const auto d = describe(packet::parse(f));
    bool first = true;
    for (const auto& [k, v] : d) kv << (first ? "" : " ") << k << '=' << v, first = false;
    kv << '\n';
  }
  std::printf("%zu frames built\n", frames.size());
  return 0;
}
}  // namespace

int main(int argc, char** argv) {
  if (argc == 4 && std::strcmp(argv[1], "parse") == 0) return parse_mode(argv[2], argv[3]);
  if (argc == 4 && std::strcmp(argv[1], "build") == 0) return build_mode(argv[2], argv[3]);
  std::fprintf(stderr, "usage: %s parse|build PCAP KV\n", argv[0]);
  return 2;
}
