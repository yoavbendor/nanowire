// SPDX-License-Identifier: Apache-2.0
// Golden check against nanom_shark (nanowire's predecessor in nanom) on real / fixture captures:
// for every packet, every field both decode must agree — Ethernet, VLAN, IPv4, IPv6 + extension
// chain (fragment, SRv6 segments), TCP, UDP, the L4 payload offset, the SOME/IP header, SD
// entries and endpoint options — and IP datagrams reassembled by nanom_shark's defrag table must
// equal nanowire's reassembly byte for byte.
//
//   test_golden_shark capture.pcap[ng] ...
#include "check.hpp"

#include <nanowire/nanowire.hpp>

#include <nanom_shark/defrag.hpp>
#include <nanom_shark/pcap.hpp>
#include <nanom_shark/protocols.hpp>
#include <nanom_shark/someip.hpp>

#include <cstring>
#include <fstream>
#include <map>
#include <string>
#include <vector>

using namespace nanowire;
namespace ns = nanom_shark;

namespace {
struct shark_view {
  std::vector<std::size_t> offsets;
  bool eth = false;
  nmproto::Ethernet e{};
  std::vector<nmproto::VlanTag> vlans;
  std::optional<nmproto::Ipv4> v4;
  std::optional<nmproto::Ipv6> v6;
  std::optional<nmproto::Ipv6Fragment> frag;
  std::vector<std::array<u8, 16>> segs;
  std::optional<nmproto::Tcp> tcp;
  std::optional<nmproto::Udp> udp;
  std::size_t l2_end = 0;
  u16 inner_et = 0;
};
struct visitor {
  shark_view* s;
  void on_offset(std::size_t o) { s->offsets.push_back(o); }
  void on_l2_done(u16 et, std::size_t end) { s->inner_et = et, s->l2_end = end; }
  void on_eth(const nmproto::Ethernet& e) { s->eth = true, s->e = e; }
  void on_vlan(const nmproto::VlanTag& v) { s->vlans.push_back(v); }
  void on_ipv4(const nmproto::Ipv4& v) { s->v4 = v; }
  void on_ipv6(const nmproto::Ipv6& v) { s->v6 = v; }
  void on_fragment(const nmproto::Ipv6Fragment& f) { s->frag = f; }
  void on_srh_segment(u8, u8, std::array<u8, 16> a) { s->segs.push_back(a); }
  void on_tcp(const nmproto::Tcp& t) { s->tcp = t; }
  void on_udp(const nmproto::Udp& u) { s->udp = u; }
};

struct counts {
  std::size_t packets = 0, ipv4 = 0, ipv6 = 0, udp = 0, tcp = 0, someip = 0, sd_entries = 0, sd_options = 0,
              vlan = 0, srv6 = 0, frag = 0, v4_dgrams = 0, v6_dgrams = 0;
};

void compare_packet(bytes frame, counts& c) {
  shark_view s;
  const auto w = nmproto::walk_packet_ext(nmproto::kLinkTypeEthernet, nanom::bytes(frame.data(), frame.size()), visitor{&s});
  const auto pkt = packet::parse(frame);
  ++c.packets;
  CHECK_EQ(bool(pkt.eth()), s.eth);
  if (!s.eth) return;
  CHECK(pkt.eth()->dst() == s.e.dst);
  CHECK(pkt.eth()->src() == s.e.src);
  CHECK_EQ(pkt.eth()->ethertype(), u16(s.e.ethertype));
  CHECK_EQ(pkt.vlan_count(), s.vlans.size());
  c.vlan += s.vlans.size();
  for (std::size_t i = 0; i < std::min(pkt.vlan_count(), s.vlans.size()); ++i) {
    CHECK_EQ(pkt.vlan(i).vid(), u16(s.vlans[i].vid));
    CHECK_EQ(pkt.vlan(i).pcp(), u8(s.vlans[i].pcp));
    CHECK_EQ(pkt.vlan(i).dei(), bool(u8(s.vlans[i].dei)));
    CHECK_EQ(pkt.vlan(i).ethertype(), u16(s.vlans[i].inner_ethertype));
  }
  if (s.l2_end) {
    CHECK_EQ(pkt.ethertype(), s.inner_et);
    CHECK_EQ(pkt.l3_offset(), s.l2_end);
  }
  CHECK_EQ(bool(pkt.ipv4()), s.v4.has_value());
  if (s.v4 && pkt.ipv4()) {
    ++c.ipv4;
    const auto v = *pkt.ipv4();
    const auto& x = *s.v4;
    CHECK_EQ(v.version(), u8(x.version));
    CHECK_EQ(v.ihl(), u8(x.ihl));
    CHECK_EQ(v.dscp(), u8(x.dscp));
    CHECK_EQ(v.ecn(), u8(x.ecn));
    CHECK_EQ(v.total_length(), u16(x.total_length));
    CHECK_EQ(v.identification(), u16(x.identification));
    CHECK_EQ((u8(v.df()) << 1) | u8(v.mf()), u8(x.flags) & 3);
    CHECK_EQ(v.frag_offset(), u16(x.frag_offset));
    CHECK_EQ(v.ttl(), x.ttl);
    CHECK_EQ(v.protocol(), x.protocol);
    CHECK_EQ(v.checksum(), u16(x.checksum));
    CHECK(v.src() == x.src && v.dst() == x.dst);
    if (v.is_fragment()) ++c.frag;
  }
  CHECK_EQ(bool(pkt.ipv6()), s.v6.has_value());
  if (s.v6 && pkt.ipv6()) {
    ++c.ipv6;
    const auto v = *pkt.ipv6();
    const auto& x = *s.v6;
    CHECK_EQ(v.traffic_class(), u8(x.traffic_class));
    CHECK_EQ(v.flow_label(), u32(x.flow_label));
    CHECK_EQ(v.payload_length(), u16(x.payload_length));
    CHECK_EQ(v.next_header(), x.next_header);
    CHECK_EQ(v.hop_limit(), x.hop_limit);
    CHECK(v.src() == x.src && v.dst() == x.dst);
    std::vector<std::array<u8, 16>> segs;
    for (auto e : v.extensions())
      if (auto r = e.routing())
        for (std::size_t i = 0; i < r->segment_count(); ++i) segs.push_back(r->segment(i));
    CHECK(segs == s.segs);
    c.srv6 += segs.size();
    CHECK_EQ(bool(pkt.ipv6_fragment()), s.frag.has_value());
    if (s.frag && pkt.ipv6_fragment()) {
      ++c.frag;
      CHECK_EQ(pkt.ipv6_fragment()->identification(), u32(s.frag->identification));
      CHECK_EQ(pkt.ipv6_fragment()->offset(), u16(u16(s.frag->offset_flags) >> 3));
      CHECK_EQ(pkt.ipv6_fragment()->more(), bool(u16(s.frag->offset_flags) & 1));
    }
  }
  CHECK_EQ(bool(pkt.udp()), s.udp.has_value());
  CHECK_EQ(bool(pkt.tcp()), s.tcp.has_value());
  if (s.udp && pkt.udp()) {
    ++c.udp;
    CHECK_EQ(pkt.udp()->src_port(), u16(s.udp->src_port));
    CHECK_EQ(pkt.udp()->dst_port(), u16(s.udp->dst_port));
    CHECK_EQ(pkt.udp()->length(), u16(s.udp->length));
    CHECK_EQ(pkt.udp()->checksum(), u16(s.udp->checksum));
  }
  if (s.tcp && pkt.tcp()) {
    ++c.tcp;
    const auto t = *pkt.tcp();
    CHECK_EQ(t.seq(), u32(s.tcp->seq));
    CHECK_EQ(t.ack(), u32(s.tcp->ack));
    CHECK_EQ(t.data_offset(), u8(s.tcp->data_offset));
    CHECK_EQ(t.flags(), u16(s.tcp->flags));
    CHECK_EQ(t.window(), u16(s.tcp->window));
  }
  if (w.reached_l4) {
    CHECK_EQ(pkt.payload_offset(), w.l4_payload_offset);
    CHECK_EQ(u32((pkt.src_port() << 16) | pkt.dst_port()), u32(w.l4_ports));
  }
  // SOME/IP + SD over UDP payloads
  if (!w.reached_l4 || !s.udp || w.l4_payload_offset + 16 > frame.size()) return;
  const bytes pl = frame.subspan(w.l4_payload_offset);
  auto hdr = nanom::strct<ns::SomeipHeader>(std::endian::big)(nanom::from(nanom::bytes(pl.data(), pl.size())));
  auto m = pkt.someip();
  if (!hdr || !m) return;  // nanowire additionally requires length >= 8
  ++c.someip;
  CHECK_EQ(m->service_id(), u16(hdr->value.service_id));
  CHECK_EQ(m->method_id(), u16(hdr->value.method_id));
  CHECK_EQ(m->length(), u32(hdr->value.length));
  CHECK_EQ(m->client_id(), u16(hdr->value.client_id));
  CHECK_EQ(m->session_id(), u16(hdr->value.session_id));
  CHECK_EQ(m->protocol_version(), hdr->value.protocol_version);
  CHECK_EQ(m->interface_version(), hdr->value.interface_version);
  CHECK_EQ(m->message_type(), hdr->value.message_type);
  CHECK_EQ(m->return_code(), hdr->value.return_code);
  // SD: nanom_shark's traversal clamps; compare on well-formed messages
  std::vector<ns::SomeipSdEntry> se;
  struct opt {
    u8 type;
    u16 len;
    std::array<u8, 16> addr;
    u8 l4;
    u16 port;
  };
  std::vector<opt> so;
  const bytes after = pl.subspan(16, std::min<std::size_t>(pl.size() - 16, m->payload().size()));
  nanom::single_segment one{std::span<const std::byte>(after.data(), after.size())};
  ns::someip::for_each_sd_child(
      hdr->value, nanom::from(one.view()), [&](u8, const ns::SomeipSdEntry& e) { se.push_back(e); },
      [&](u8, u16 len, u8 type, const std::array<u8, 16>& a, u8 l4, u16 port) { so.push_back({type, len, a, l4, port}); });
  auto sd = sd_view::parse(*m);
  if (!sd) {
    CHECK(se.empty());
    return;
  }
  CHECK_EQ(sd->entries().size(), se.size());
  std::size_t i = 0;
  for (auto e : sd->entries()) {
    if (i >= se.size()) break;
    const auto& x = se[i++];
    ++c.sd_entries;
    CHECK_EQ(e.type(), x.type);
    CHECK_EQ(e.index_1(), x.index_1st_opts);
    CHECK_EQ(e.index_2(), x.index_2nd_opts);
    CHECK_EQ(e.num_options_1(), u8(x.num_opt_1));
    CHECK_EQ(e.num_options_2(), u8(x.num_opt_2));
    CHECK_EQ(e.service_id(), u16(x.service_id));
    CHECK_EQ(e.instance_id(), u16(x.instance_id));
    CHECK_EQ(e.major_version(), x.major_version);
    CHECK_EQ(e.ttl(), u32(x.ttl));
    CHECK_EQ(e.minor_version(), u32(x.minor_version));
  }
  CHECK_EQ(sd->options().count(), so.size());
  i = 0;
  for (auto o : sd->options()) {
    if (i >= so.size()) break;
    const auto& x = so[i++];
    ++c.sd_options;
    CHECK_EQ(o.type(), x.type);
    CHECK_EQ(o.length(), x.len);
    if (auto ep = o.endpoint()) {
      CHECK_EQ(ep->port, x.port);
      CHECK_EQ(ep->l4_proto, x.l4);
      if (ep->is_v6) CHECK(ep->v6 == x.addr);
      else CHECK(std::equal(ep->v4.begin(), ep->v4.end(), x.addr.begin()));
    }
  }
}

std::vector<std::byte> seg_bytes(const nanom::segments& s) {
  std::vector<std::byte> v(s.size());
  copy_to(s, v);
  return v;
}

void run_capture(const std::string& path, counts& c) {
  std::ifstream f(path, std::ios::binary);
  CHECK(bool(f));
  std::vector<char> raw((std::istreambuf_iterator<char>(f)), {});
  std::vector<std::byte> file(raw.size());
  if (!raw.empty()) std::memcpy(file.data(), raw.data(), raw.size());
  if (file.empty()) return;
  const nanom::bytes nb(file.data(), file.size());
  std::vector<nmpcap::BlockRef> refs;
  std::string err;
  CHECK(nmpcap::scan_blocks(nb, refs, err));
  std::vector<u16> links;
  // reassembly cross-check
  ns::defrag::ReassemblyTable<ns::defrag::Ipv4Key> s4;
  ns::defrag::ReassemblyTable<ns::defrag::Ipv6Key> s6;
  ipv4_reassembler r4(ip_reassembly_defaults());
  ipv6_reassembler r6(ip_reassembly_defaults());
  std::uint64_t pid = 0;
  for (const auto& r : refs) {
    if (r.kind == nmpcap::Kind::Idb) {
      nmpcap::IdbView iv{};
      if (nmpcap::parse_idb(nb, r, iv)) links.push_back(iv.link_type);
      continue;
    }
    if (r.kind != nmpcap::Kind::Epb && r.kind != nmpcap::Kind::PcapRecord) continue;
    nmpcap::EpbView ev{};
    if (!nmpcap::parse_epb(nb, r, ev)) continue;
    if (ev.interface_id < links.size() && links[ev.interface_id] != 1) continue;
    const bytes frame(file.data() + ev.payload_file_offset, ev.caplen);
    compare_packet(frame, c);
    ++pid;
    const auto pkt = packet::parse(frame);
    if (!pkt.is_fragment()) continue;
    if (auto ip = pkt.ipv4()) {
      ns::defrag::Ipv4Key k{ip->src(), ip->dst(), ip->protocol(), ip->identification()};
      auto a = s4.add_fragment(k, pid, ip->frag_offset_bytes(), ip->mf(), pkt.fragment_data());
      auto b = feed(r4, pkt, pid);
      CHECK_EQ(a.completed, b.complete());
      if (a.completed && b.complete()) {
        ++c.v4_dgrams;
        CHECK(seg_bytes(a.parts) == seg_bytes(b.parts));
      }
    } else if (auto ip6 = pkt.ipv6()) {
      auto fh = pkt.ipv6_fragment();
      ns::defrag::Ipv6Key k{ip6->src(), ip6->dst(), fh->identification()};
      auto a = s6.add_fragment(k, pid, fh->offset_bytes(), fh->more(), pkt.fragment_data());
      auto b = feed(r6, pkt, pid);
      CHECK_EQ(a.completed, b.complete());
      if (a.completed && b.complete()) {
        ++c.v6_dgrams;
        CHECK(seg_bytes(a.parts) == seg_bytes(b.parts));
      }
    }
  }
}

std::vector<std::string> g_paths;
}  // namespace

TEST(golden_vs_nanom_shark) {
  counts c;
  for (const auto& p : g_paths) {
    counts one;
    run_capture(p, one);
    std::printf("  %-60s pkts %zu ipv4 %zu ipv6 %zu udp %zu tcp %zu someip %zu sd_e %zu sd_o %zu vlan %zu srv6 %zu "
                "frag %zu dgrams %zu/%zu\n",
                p.substr(p.size() > 60 ? p.size() - 60 : 0).c_str(), one.packets, one.ipv4, one.ipv6, one.udp, one.tcp,
                one.someip, one.sd_entries, one.sd_options, one.vlan, one.srv6, one.frag, one.v4_dgrams, one.v6_dgrams);
    c.packets += one.packets;
  }
  CHECK(c.packets > 0);
}

int main(int argc, char** argv) {
  for (int i = 1; i < argc; ++i) g_paths.emplace_back(argv[i]);
  return nwtest::run_all();
}
