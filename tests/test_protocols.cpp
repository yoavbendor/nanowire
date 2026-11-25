// SPDX-License-Identifier: Apache-2.0
// Parse / build round trips for every protocol, field access by name, template patching.
#include "check.hpp"

#include <nanowire/nanowire.hpp>

#include <array>
#include <string_view>
#include <vector>

using namespace nanowire;

namespace {
std::vector<std::byte> hexbytes(std::string_view h) {
  std::vector<std::byte> v;
  for (std::size_t i = 0; i + 1 < h.size();) {
    if (h[i] == ' ') {
      ++i;
      continue;
    }
    v.push_back(std::byte(detail::hexval(h[i]) * 16 + detail::hexval(h[i + 1])));
    i += 2;
  }
  return v;
}
template <class... L>
std::vector<std::byte> frame(const L&... l) {
  auto f = make_frame(l...);
  CHECK(bool(f));
  return f ? *f : std::vector<std::byte>{};
}
}  // namespace

TEST(addresses) {
  static_assert(ip4("10.0.0.1") == ipv4_addr{10, 0, 0, 1});
  static_assert(ip6("fd00::1")[0] == 0xfd && ip6("fd00::1")[15] == 1);
  static_assert(ip6("::")[0] == 0 && ip6("1:2:3:4:5:6:7:8")[15] == 8);
  static_assert(mac("02:00:00:00:00:01")[5] == 1);
  CHECK(!parse_ipv4("10.0.0"));
  CHECK(!parse_ipv4("10.0.0.256"));
  CHECK(!parse_ipv6("1::2::3"));
  CHECK(!parse_ipv6("1:2:3:4:5:6:7:8:9"));
  CHECK(!parse_mac("02:00:00:00:00"));
  CHECK(to_string(ip4("192.168.1.20")) == "192.168.1.20");
  CHECK(to_string(mac("02:ab:00:00:00:01")) == "02:ab:00:00:00:01");
  CHECK(to_string(ip6("fd00::1")) == "fd00:0:0:0:0:0:0:1");
}

TEST(field_offsets_and_patch) {
  static_assert(field_offset_v<wire::ipv4_hdr, "ttl"> == 8);
  static_assert(field_offset_v<wire::ipv4_hdr, "checksum"> == 10);
  static_assert(field_bit_offset_v<wire::ipv4_hdr, "frag_offset"> == 51);
  static_assert(field_bits_v<wire::ipv4_hdr, "frag_offset"> == 13);
  static_assert(field_offset_v<wire::someip_hdr, "session_id"> == 10);
  static_assert(field_offset_v<wire::sd_eventgroup_entry, "eventgroup_id"> == 14);
  std::array<std::byte, 4> v{};
  CHECK(patch<wire::vlan_tag, "vid">(v.data(), 0xabc));
  CHECK(patch<wire::vlan_tag, "pcp">(v.data(), 5));
  CHECK(!patch<wire::vlan_tag, "pcp">(v.data(), 8));  // does not fit 3 bits
  CHECK(patch<wire::vlan_tag, "ethertype">(v.data(), 0x0800));
  const vlan_view vv(v.data());
  CHECK_EQ(vv.vid(), 0xabc);
  CHECK_EQ(vv.pcp(), 5);
  CHECK(!vv.dei());
  CHECK_EQ(vv.ethertype(), 0x0800);
}

TEST(ethernet_vlan_qinq) {
  auto f = frame(eth{.dst = mac("02:00:00:00:00:02"), .src = mac("02:00:00:00:00:01")},
                 vlan{.vid = 10, .pcp = 5, .tpid = ethertype::qinq}, vlan{.vid = 100, .pcp = 3, .dei = true},
                 ipv4{.src = ip4("10.0.0.1"), .dst = ip4("10.0.0.2")}, udp{.src_port = 1, .dst_port = 2}, fill{4});
  const auto pkt = packet::parse(f);
  CHECK(pkt.eth().has_value());
  CHECK(pkt.eth()->dst() == mac("02:00:00:00:00:02"));
  CHECK(pkt.eth()->src() == mac("02:00:00:00:00:01"));
  CHECK_EQ(pkt.eth()->ethertype(), 0x88A8);
  CHECK_EQ(pkt.vlan_count(), 2u);
  CHECK_EQ(pkt.vlan(0).vid(), 10);
  CHECK_EQ(pkt.vlan(0).pcp(), 5);
  CHECK_EQ(pkt.vlan(0).ethertype(), 0x8100);
  CHECK_EQ(pkt.vlan(1).vid(), 100);
  CHECK(pkt.vlan(1).dei());
  CHECK_EQ(pkt.ethertype(), 0x0800);
  CHECK_EQ(pkt.l3_offset(), 22u);
  CHECK(pkt.l3() == l3_kind::ipv4);
}

TEST(ipv4_options_checksum_lengths) {
  const std::array<std::byte, 7> opts{std::byte{0x94}, std::byte{0x04}, std::byte{0}, std::byte{0},  // router alert
                                      std::byte{0x01},                                              // NOP
                                      std::byte{0x01}, std::byte{0x01}};
  const std::array<std::byte, 10> pl{};
  auto f = frame(eth{}, ipv4{.src = ip4("192.168.0.1"), .dst = ip4("192.168.0.2"), .ttl = 17, .dscp = 46, .ecn = 1,
                             .id = 0x4242, .df = true, .options = opts},
                 udp{.src_port = 5000, .dst_port = 6000}, raw{pl});
  const auto pkt = packet::parse(f);
  auto ip = pkt.ipv4();
  CHECK(ip.has_value());
  CHECK_EQ(ip->ihl(), 7);  // 20 + 8 (7 option bytes padded)
  CHECK_EQ(ip->header_size(), 28u);
  CHECK_EQ(ip->total_length(), 28 + 8 + 10);
  CHECK_EQ(ip->ttl(), 17);
  CHECK_EQ(ip->dscp(), 46);
  CHECK_EQ(ip->ecn(), 1);
  CHECK_EQ(ip->identification(), 0x4242);
  CHECK(ip->df());
  CHECK(!ip->mf());
  CHECK_EQ(ip->protocol(), 17);
  CHECK(ip->checksum_ok());
  CHECK(nm::verify_computed<wire::ipv4_hdr>(ip->header().first(20), nm::emit_ctx{bytes(f).subspan(14 + 20)},
                                            std::endian::big));
  int n = 0;
  for (auto o : ip->options()) {
    if (n == 0) {
      CHECK_EQ(o.type, 0x94);
      CHECK_EQ(o.value.size(), 2u);
      CHECK(o.copied());
    } else {
      CHECK_EQ(o.type, 1);
    }
    ++n;
  }
  CHECK_EQ(n, 4);  // router alert + 3 NOPs
  CHECK(ip->options().well_formed());
  CHECK_EQ(pkt.udp()->length(), 18);
  CHECK(l4_checksum_ok(pkt.l3_bytes(), 17, pkt.l3_bytes().subspan(28)));
  CHECK_EQ(pkt.payload().size(), 10u);
  // explicit overrides craft malformed headers on purpose
  auto bad = frame(eth{}, ipv4{.total_length = 9, .checksum = 0xdead}, raw{pl});
  auto bp = ipv4_view::parse(bytes(bad).subspan(14));
  CHECK_EQ(bp->total_length(), 9);
  CHECK_EQ(bp->checksum(), 0xdead);
  CHECK(packet::parse(bad).is_malformed());
}

TEST(ipv4_known_bytes) {
  // a classic example header (Wikipedia "IPv4 header checksum"): checksum b861
  auto h = hexbytes("4500 0073 0000 4000 4011 0000 c0a8 0001 c0a8 00c7");
  std::array<std::byte, 20> out{};
  ipv4 b{.src = ip4("192.168.0.1"), .dst = ip4("192.168.0.199"), .ttl = 64, .df = true, .protocol = 17};
  build_ctx c;
  c.after = 0x73 - 20;
  CHECK(b.write(out.data(), c));
  CHECK_EQ(detail::be16(out.data() + 10), 0xb861);
  h[10] = std::byte{0xb8}, h[11] = std::byte{0x61};
  CHECK(std::equal(out.begin(), out.end(), h.begin()));
}

TEST(ipv6_extension_chain_srv6) {
  const std::array<ipv6_addr, 2> segs{ip6("fc00::1"), ip6("fc00::2")};
  const std::array<std::byte, 4> hbh_opt{std::byte{0x05}, std::byte{0x02}, std::byte{0}, std::byte{0}};  // RA
  const std::array<std::byte, 12> pl{};
  auto f = frame(eth{}, ipv6{.src = ip6("fd00::1"), .dst = ip6("fd00::2"), .traffic_class = 0xb8, .flow_label = 0x12345},
                 ipv6_hbh{.options = hbh_opt}, ipv6_srh{.segments = segs, .segments_left = 1}, ipv6_dstopts{},
                 udp{.src_port = 30501, .dst_port = 30501}, raw{pl});
  const auto pkt = packet::parse(f);
  auto ip = pkt.ipv6();
  CHECK(ip.has_value());
  CHECK_EQ(ip->traffic_class(), 0xb8);
  CHECK_EQ(ip->flow_label(), 0x12345u);
  CHECK_EQ(ip->next_header(), 0);
  CHECK_EQ(ip->payload_length(), 8 + 40 + 8 + 8 + 12);
  CHECK(ip->src() == ip6("fd00::1"));
  CHECK_EQ(pkt.ip_protocol(), 17);
  CHECK(pkt.l4() == l4_kind::udp);
  CHECK_EQ(pkt.l4_offset(), 14u + 40 + 8 + 40 + 8);
  CHECK_EQ(ip->upper_protocol(), 17);
  std::vector<u8> types;
  int opts = 0;
  for (auto e : ip->extensions()) {
    types.push_back(e.type());
    if (auto r = e.routing()) {
      CHECK(r->is_srh());
      CHECK_EQ(r->segment_count(), 2u);
      CHECK(r->segment(0) == ip6("fc00::1"));
      CHECK(r->segment(1) == ip6("fc00::2"));
      CHECK_EQ(r->segments_left(), 1);
      CHECK_EQ(r->last_entry(), 1);
    }
    if (e.type() == 0)
      for (auto o : e.options()) {
        if (opts++ == 0) CHECK_EQ(o.type, 5);
      }
  }
  CHECK((types == std::vector<u8>{0, 43, 60}));
  CHECK(l4_checksum_ok(pkt.l3_bytes(), 17, pkt.l3_bytes().subspan(pkt.l4_offset() - 14)));
  CHECK_EQ(pkt.payload().size(), 12u);
}

TEST(ipv6_fragment_gates_l4) {
  const std::array<std::byte, 24> pl{};
  auto first = frame(eth{}, ipv6{}, ipv6_frag{.offset = 0, .more = true, .id = 77}, udp{}, raw{pl});
  auto p1 = packet::parse(first);
  CHECK(p1.is_fragment());
  CHECK(p1.l4() == l4_kind::udp);
  CHECK_EQ(p1.ipv6_fragment()->identification(), 77u);
  CHECK(p1.ipv6_fragment()->more());
  auto later = frame(eth{}, ipv6{}, ipv6_frag{.offset = 4, .more = false, .id = 77, .next_header = 17}, raw{pl});
  auto p2 = packet::parse(later);
  CHECK(p2.is_fragment());
  CHECK(p2.l4() == l4_kind::none);
  CHECK_EQ(p2.ipv6_fragment()->offset_bytes(), 32u);
  CHECK_EQ(p2.fragment_data().size(), 24u);
  CHECK_EQ(p2.ip_protocol(), 17);
}

TEST(tcp_header) {
  const std::array<std::byte, 4> mss{std::byte{2}, std::byte{4}, std::byte{0x05}, std::byte{0xb4}};
  const std::array<std::byte, 5> pl{std::byte{'h'}, std::byte{'e'}, std::byte{'l'}, std::byte{'l'}, std::byte{'o'}};
  auto f = frame(eth{}, ipv4{.src = ip4("1.2.3.4"), .dst = ip4("5.6.7.8")},
                 tcp{.src_port = 1234, .dst_port = 80, .seq = 1000, .ack = 2000, .flags = tcp_flag::syn | tcp_flag::ack,
                     .window = 1024, .options = mss},
                 raw{pl});
  const auto pkt = packet::parse(f);
  auto t = pkt.tcp();
  CHECK(t.has_value());
  CHECK_EQ(t->src_port(), 1234);
  CHECK_EQ(t->dst_port(), 80);
  CHECK_EQ(t->seq(), 1000u);
  CHECK_EQ(t->ack(), 2000u);
  CHECK_EQ(t->data_offset(), 6);
  CHECK(t->has(tcp_flag::syn) && t->has(tcp_flag::ack) && !t->has(tcp_flag::fin));
  CHECK_EQ(t->window(), 1024);
  CHECK_EQ(t->options().size(), 4u);
  CHECK_EQ(pkt.payload().size(), 5u);
  CHECK(l4_checksum_ok(pkt.l3_bytes(), 6, pkt.l3_bytes().subspan(20)));
  CHECK_EQ(pkt.src_port(), 1234);
}

TEST(someip_and_tp) {
  const std::array<std::byte, 32> pl{std::byte{1}, std::byte{2}};
  auto f = frame(eth{}, ipv4{}, udp{.src_port = 30501, .dst_port = 30501},
                 someip{.service_id = 0x1234, .method_id = 0x8001, .client_id = 0x10, .session_id = 0x55,
                        .interface_version = 3, .message_type = someip_type::request, .return_code = 0},
                 raw{pl});
  const auto pkt = packet::parse(f);
  auto m = pkt.someip();
  CHECK(m.has_value());
  CHECK_EQ(m->service_id(), 0x1234);
  CHECK_EQ(m->method_id(), 0x8001);
  CHECK_EQ(m->message_id(), 0x12348001u);
  CHECK_EQ(m->length(), 8u + 32);
  CHECK_EQ(m->client_id(), 0x10);
  CHECK_EQ(m->session_id(), 0x55);
  CHECK_EQ(m->request_id(), 0x00100055u);
  CHECK_EQ(m->protocol_version(), 1);
  CHECK_EQ(m->interface_version(), 3);
  CHECK_EQ(m->message_type(), 0);
  CHECK(!m->is_tp());
  CHECK(!m->truncated());
  CHECK_EQ(m->payload().size(), 32u);
  CHECK(nm::verify_computed<wire::someip_hdr>(m->header(), nm::emit_ctx{m->payload()}, std::endian::big));

  auto t = frame(eth{}, ipv4{}, udp{},
                 someip{.service_id = 0x1234, .method_id = 0x8003, .tp = someip_tp{.offset = 1392, .more = true}},
                 raw{pl});
  auto tm = packet::parse(t).someip();
  CHECK(tm->is_tp());
  CHECK_EQ(tm->message_type(), 0x22);
  CHECK_EQ(tm->message_type_base(), 0x02);
  CHECK_EQ(tm->length(), 8u + 4 + 32);
  auto tp = tm->tp();
  CHECK(tp.has_value());
  CHECK_EQ(tp->offset_bytes(), 1392u);
  CHECK_EQ(tp->offset_units(), 87u);
  CHECK(tp->more());
  CHECK_EQ(tp->segment().size(), 32u);
  // misaligned TP offsets are refused by the builder
  CHECK(!make_frame(someip{.tp = someip_tp{.offset = 17}}));
}

TEST(someip_several_messages_per_datagram) {
  const std::array<std::byte, 3> a{};
  const std::array<std::byte, 9> b{};
  auto f = frame(eth{}, ipv4{}, udp{}, someip{.service_id = 1, .method_id = 1}, raw{a},
                 someip{.service_id = 2, .method_id = 2, .session_id = 9}, raw{b});
  // the first someip's length must cover only its own payload: build it per message instead
  std::vector<std::byte> m1 = *make_frame(someip{.service_id = 1, .method_id = 1}, raw{a});
  std::vector<std::byte> m2 = *make_frame(someip{.service_id = 2, .method_id = 2, .session_id = 9}, raw{b});
  std::vector<std::byte> cat = m1;
  cat.insert(cat.end(), m2.begin(), m2.end());
  cat.push_back(std::byte{0xee});  // trailing junk
  auto g = frame(eth{}, ipv4{}, udp{}, raw{cat});
  const auto pkt = packet::parse(g);
  std::vector<u16> svcs;
  for (auto m : pkt.someip_all()) svcs.push_back(m.service_id());
  CHECK((svcs == std::vector<u16>{1, 2}));
  CHECK_EQ(pkt.someip_all().count(), 2u);
  CHECK(!pkt.someip_all().well_formed());
  CHECK_EQ(pkt.someip_all().rest().size(), 1u);
  (void)f;
}

TEST(someip_sd_entries_and_options) {
  std::array<std::byte, 64> cfgbuf{};
  const std::array<std::string_view, 2> items{"hello=world", "flag"};
  const std::size_t cn = sd_encode_config(items, cfgbuf);
  CHECK_EQ(cn, 1u + 11 + 1 + 4 + 1);
  const std::array<sd_entry, 4> entries{
      sd_entry::find_service(0x1111),
      sd_entry::offer_service(0x1234, 1, 2, 3).with_options(0, 2),
      sd_entry::subscribe(0x1234, 1, 2, 0x4455, 3, 7).with_options(2, 1, 3, 2),
      sd_entry::subscribe_ack(0x1234, 1, 2, 0x4455, 0),
  };
  const std::array<sd_option, 6> options{
      sd_option::ipv4_endpoint(ip4("10.0.0.1"), ip_proto::udp, 30501),
      sd_option::load_balancing(1, 2),
      sd_option::ipv4_multicast(ip4("239.0.0.1"), 30502),
      sd_option::ipv6_endpoint(ip6("fd00::1"), ip_proto::tcp, 30503),
      sd_option::configuration(bytes(cfgbuf.data(), cn)),
      sd_option::ipv4_sd_endpoint(ip4("10.0.0.9")),
  };
  auto f = frame(eth{}, ipv4{}, udp{.src_port = 30490, .dst_port = 30490}, someip_sd_header(7),
                 someip_sd{.entries = entries, .options = options});
  const auto pkt = packet::parse(f);
  auto m = pkt.someip();
  CHECK(m && m->is_sd());
  CHECK_EQ(m->client_id(), 0);
  auto sd = sd_view::parse(*m);
  CHECK(sd.has_value());
  CHECK(sd->reboot() && sd->unicast() && !sd->explicit_initial_data_control());
  CHECK_EQ(sd->entries_length(), 64u);
  CHECK_EQ(sd->entries().size(), 4u);
  CHECK(sd->well_formed());
  auto e = sd->entries();
  CHECK_EQ(e[0].type(), sd_entry_type::find_service);
  CHECK_EQ(e[0].service_id(), 0x1111);
  CHECK_EQ(e[0].instance_id(), 0xFFFF);
  CHECK_EQ(e[0].minor_version(), 0xFFFFFFFFu);
  CHECK_EQ(e[1].type(), sd_entry_type::offer_service);
  CHECK(e[1].is_service());
  CHECK_EQ(e[1].major_version(), 2);
  CHECK_EQ(e[1].minor_version(), 3u);
  CHECK_EQ(e[1].ttl(), 0xFFFFFFu);
  CHECK_EQ(e[1].num_options_1(), 2);
  CHECK(e[2].is_eventgroup());
  CHECK_EQ(e[2].eventgroup_id(), 0x4455);
  CHECK_EQ(e[2].counter(), 7);
  CHECK_EQ(e[2].ttl(), 3u);
  CHECK_EQ(e[2].index_2(), 3);
  CHECK_EQ(e[2].num_options_2(), 2);
  CHECK(e[3].is_stop());
  CHECK_EQ(sd->options().count(), 6u);
  auto o0 = sd->options()[0];
  CHECK(o0 && o0->endpoint());
  CHECK(o0->endpoint()->v4 == ip4("10.0.0.1"));
  CHECK_EQ(o0->endpoint()->port, 30501);
  CHECK_EQ(o0->endpoint()->l4_proto, 17);
  CHECK_EQ(sd->options()[1]->load_balancing()->priority, 1);
  CHECK_EQ(sd->options()[1]->load_balancing()->weight, 2);
  CHECK_EQ(sd->options()[2]->type(), sd_option_type::ipv4_multicast);
  auto o3 = sd->options()[3]->endpoint();
  CHECK(o3 && o3->is_v6 && o3->v6 == ip6("fd00::1") && o3->l4_proto == 6 && o3->port == 30503);
  std::vector<std::string_view> got;
  for (auto it : sd->options()[4]->configuration()) got.push_back(it);
  CHECK(got.size() == 2 && got[0] == "hello=world" && got[1] == "flag");
  CHECK(sd_config_items::split(got[0]).second == "world");
  CHECK_EQ(sd->options()[5]->endpoint()->port, 30490);
  // option resolution for the subscribe entry: run 1 = [2], run 2 = [3, 4]
  std::vector<int> runs;
  std::vector<u8> otypes;
  sd->for_each_option(e[2], [&](const sd_option_view& o, int run) {
    runs.push_back(run);
    otypes.push_back(o.type());
  });
  CHECK((runs == std::vector<int>{1, 2, 2}));
  CHECK((otypes == std::vector<u8>{0x14, 0x06, 0x01}));
}

TEST(pdu_over_ip) {
  const std::array<std::byte, 3> a{std::byte{1}, std::byte{2}, std::byte{3}};
  const std::array<std::byte, 0> none{};
  auto f = frame(eth{}, ipv4{}, udp{.dst_port = 42000}, soad_pdu{.id = 0x100, .data = a}, soad_pdu{.id = 0x200, .data = none},
                 soad_pdu{.id = 0xdeadbeef, .data = a});
  const auto pkt = packet::parse(f);
  std::vector<u32> ids;
  std::vector<std::size_t> lens;
  for (auto p : soad_pdus(pkt.payload())) ids.push_back(p.id), lens.push_back(p.data.size());
  CHECK((ids == std::vector<u32>{0x100, 0x200, 0xdeadbeef}));
  CHECK((lens == std::vector<std::size_t>{3, 0, 3}));
  CHECK(soad_pdus(pkt.payload()).well_formed());
  auto h = hexbytes("00000100 00000003 010203");
  CHECK(std::equal(h.begin(), h.end(), pkt.payload().begin()));
}

TEST(ipdum_containers) {
  const std::array<std::byte, 2> a{std::byte{0xaa}, std::byte{0xbb}};
  const std::array<std::byte, 1> b{std::byte{0xcc}};
  const std::array<pdu, 2> pdus{pdu{0x123456, a}, pdu{0x42, b}};
  for (auto hdr : {ipdum_header::short_header, ipdum_header::long_header})
    for (auto order : {std::endian::big, std::endian::little}) {
      const ipdum_config cfg{.header = hdr, .byte_order = order};
      auto c = make_frame(ipdum_container{.config = cfg, .pdus = pdus, .min_size = 32});
      CHECK(c && c->size() == 32);
      std::vector<u32> ids;
      for (auto p : ipdum_pdus(*c, cfg)) ids.push_back(p.id);
      CHECK((ids == std::vector<u32>{0x123456, 0x42}));
      CHECK(ipdum_pdus(*c, cfg).well_formed());
    }
  auto c = make_frame(ipdum_container{.pdus = pdus});
  auto h = hexbytes("12345602 aabb 00004201 cc");
  CHECK(c && std::equal(h.begin(), h.end(), c->begin()) && c->size() == h.size());
  // container inside a PDU-over-IP record whose length covers it
  auto f = frame(eth{}, ipv4{}, udp{}, soad_pdu_header{.id = 0x300}, ipdum_container{.pdus = pdus});
  auto pkt = packet::parse(f);
  auto rec = *soad_pdus(pkt.payload()).begin();
  CHECK_EQ(rec.id, 0x300u);
  CHECK_EQ(rec.data.size(), 11u);
  // short header refuses IDs over 24 bits
  const std::array<pdu, 1> big{pdu{0x1000000, a}};
  CHECK(!make_frame(ipdum_container{.pdus = big}));
}

TEST(build_layout_and_errors) {
  std::array<std::byte, 64> small{};
  const std::array<std::byte, 100> pl{};
  auto r = build_frame(small, eth{}, ipv4{}, udp{}, raw{pl});
  CHECK(!r && r.error().code == build_errc::buffer_too_small);
  std::array<std::byte, 256> buf{};
  auto ok = build_frame(buf, eth{}, vlan{.vid = 5}, ipv4{}, udp{}, someip{}, raw{pl});
  CHECK(ok.has_value());
  CHECK_EQ(ok->size, 14u + 4 + 20 + 8 + 16 + 100);
  CHECK_EQ(ok->layers[4].offset, 46u);
  CHECK_EQ(ok->layers[4].size, 16u);
  auto bad = build_frame(buf, eth{}, vlan{.vid = 5000}, ipv4{});
  CHECK(!bad && bad.error().code == build_errc::invalid_field && bad.error().layer == 1);
  // template patching + RFC 1624 incremental checksum update keeps the header valid
  std::byte* ip = buf.data() + ok->layers[2].offset;
  const u16 old_ttl_word = detail::be16(ip + 8);
  CHECK(patch<wire::ipv4_hdr, "ttl">(ip, 3));
  detail::put_be16(ip + 10, detail::checksum_update16(detail::be16(ip + 10), old_ttl_word, detail::be16(ip + 8)));
  CHECK(ipv4_view::parse(bytes(ip, 20))->checksum_ok());
  CHECK_EQ(ipv4_view::parse(bytes(ip, 20))->ttl(), 3);
}

TEST(raw_ip_link_types) {
  const std::array<std::byte, 4> pl{};
  auto f = *make_frame(ipv6{}, udp{.dst_port = 9}, raw{pl});
  auto pkt = packet::parse(f, link_type::raw);
  CHECK(!pkt.eth());
  CHECK(pkt.l3() == l3_kind::ipv6);
  CHECK_EQ(pkt.dst_port(), 9);
  auto g = *make_frame(ipv4{}, udp{.dst_port = 7}, raw{pl});
  CHECK_EQ(packet::parse(g, link_type::ipv4).dst_port(), 7);
}

TEST_MAIN()
