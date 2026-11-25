// SPDX-License-Identifier: Apache-2.0
// Runtime registry (ports, SOME/IP methods, nanom::dyn payload decoders, SD, PDUs, IpduM
// containers, SOME/IP-TP) and the compile-time fast path.
#include "check.hpp"

#include <nanowire/nanowire.hpp>

#include <vector>

using namespace nanowire;

TEST(compile_time_fast_path) {
  static_assert(message_id(0x1234, 0x8001) == 0x12348001u);
  static_assert(port_in<30490, 30501>(30501) && !port_in<30490, 30501>(1));
  u32 seen = 0;
  auto f = [&](auto id) {
    if constexpr (decltype(id)::value == message_id(0x1234, 0x8001)) seen = 1;
    else seen = 2;
  };
  CHECK(dispatch_static<message_id(0x1234, 0x8001), message_id(0x1234, 0x8002)>(0x12348001u, f));
  CHECK_EQ(seen, 1u);
  CHECK(dispatch_static<message_id(0x1234, 0x8001), message_id(0x1234, 0x8002)>(0x12348002u, f));
  CHECK_EQ(seen, 2u);
  CHECK(!(dispatch_static<message_id(0x1234, 0x8001)>(0x1u, f)));
}

TEST(someip_routing_and_decoders) {
  registry reg;
  std::vector<std::string> log;
  reg.port(30501, app_protocol::someip)
      .on_someip(0x1234, 0x8001, [&](const someip_message& m) { log.push_back("m1:" + std::to_string(m.header.session_id())); })
      .on_service(0x1234, [&](const someip_message& m) { log.push_back("svc:" + std::to_string(m.header.method_id())); })
      .on_someip_payload<std::uint32_t>(0x2222, 0x0001, nanom::be_u32,
                                        [&](const someip_message&, std::uint32_t v) { log.push_back("u32:" + std::to_string(v)); })
      .on_someip_other([&](const someip_message& m) { log.push_back("other:" + std::to_string(m.header.service_id())); });
  const std::array<std::byte, 4> v{std::byte{0}, std::byte{0}, std::byte{1}, std::byte{2}};
  auto m1 = *make_frame(someip{.service_id = 0x1234, .method_id = 0x8001, .session_id = 5}, raw{});
  auto m2 = *make_frame(someip{.service_id = 0x1234, .method_id = 0x0002}, raw{});
  auto m3 = *make_frame(someip{.service_id = 0x2222, .method_id = 0x0001}, raw{v});
  auto m4 = *make_frame(someip{.service_id = 0x3333, .method_id = 0x0001}, raw{});
  std::vector<std::byte> all;
  for (auto* m : {&m1, &m2, &m3, &m4}) all.insert(all.end(), m->begin(), m->end());
  auto f = *make_frame(eth{}, ipv4{}, udp{.src_port = 40000, .dst_port = 30501}, raw{all});
  const auto pkt = packet::parse(f);
  CHECK(reg.classify(pkt) == app_protocol::someip);
  auto st = reg.dispatch(pkt);
  CHECK_EQ(st.messages, 4u);
  CHECK_EQ(st.handled, 4u);
  CHECK((log == std::vector<std::string>{"m1:5", "svc:2", "u32:258", "other:13107"}));
  // unconfigured port: nothing
  auto g = *make_frame(eth{}, ipv4{}, udp{.src_port = 1, .dst_port = 2}, raw{all});
  CHECK(reg.classify(packet::parse(g)) == app_protocol::none);
  CHECK_EQ(reg.dispatch(packet::parse(g)).messages, 0u);
  // reconfigure at run time
  reg.port(2, app_protocol::someip);
  CHECK_EQ(reg.dispatch(packet::parse(g)).messages, 4u);
}

TEST(sd_dispatch) {
  registry reg;  // 30490 is SOME/IP by default
  int offers = 0;
  u16 port = 0;
  reg.on_sd([&](const someip_message&, const sd_view& sd) {
    for (auto e : sd.entries())
      if (e.type() == sd_entry_type::offer_service) {
        ++offers;
        sd.for_each_option(e, [&](const sd_option_view& o, int) {
          if (auto ep = o.endpoint()) port = ep->port;
        });
      }
  });
  const std::array<sd_entry, 1> entries{sd_entry::offer_service(0x1234, 1, 1, 0).with_options(0, 1)};
  const std::array<sd_option, 1> options{sd_option::ipv4_endpoint(ip4("10.0.0.1"), ip_proto::udp, 30501)};
  auto f = *make_frame(eth{}, ipv4{}, udp{.src_port = 30490, .dst_port = 30490}, someip_sd_header(),
                       someip_sd{.entries = entries, .options = options});
  CHECK_EQ(reg.dispatch(packet::parse(f)).handled, 1u);
  CHECK_EQ(offers, 1);
  CHECK_EQ(port, 30501);
}

TEST(pdu_and_container_dispatch) {
  registry reg;
  std::vector<std::pair<u32, u32>> got;  // (id, container)
  reg.port(42000, app_protocol::pdu_over_ip)
      .container(0x300, {.header = ipdum_header::short_header})
      .on_pdu(0x100, [&](const pdu_message& p) { got.emplace_back(p.id, p.container_id); })
      .on_pdu(0x42, [&](const pdu_message& p) { got.emplace_back(p.id, p.container_id); })
      .on_pdu_other([&](const pdu_message& p) { got.emplace_back(p.id | 0x80000000u, p.container_id); });
  const std::array<std::byte, 2> a{};
  const std::array<pdu, 2> inner{pdu{0x42, a}, pdu{0x43, a}};
  auto f = *make_frame(eth{}, ipv4{}, udp{.dst_port = 42000}, soad_pdu{.id = 0x100, .data = a},
                       soad_pdu_header{.id = 0x300}, ipdum_container{.pdus = inner});
  auto st = reg.dispatch(packet::parse(f));
  CHECK((got == std::vector<std::pair<u32, u32>>{{0x100, 0}, {0x42, 0x300}, {0x80000043u, 0x300}}));
  CHECK_EQ(st.handled, 3u);
}

TEST(tp_dispatch_through_registry) {
  std::vector<std::byte> payload(3000);
  for (std::size_t i = 0; i < payload.size(); ++i) payload[i] = std::byte(i * 7);
  someip_tp_reassembler tp(tp_reassembly_defaults());
  registry reg;
  std::size_t got = 0;
  bool equal = false;
  u32 decoded = 0;
  reg.port(30501, app_protocol::someip)
      .attach(tp)
      .on_someip(0x1234, 0x8003, [&](const someip_message& m) {
        got = m.payload_size();
        std::vector<std::byte> v(got);
        copy_to(m.segments, v);
        equal = m.segmented && v == payload && m.header.length() == 8 + 3000 && !m.header.is_tp();
      })
      .on_someip_payload<std::uint32_t>(0x1234, 0x8005, nanom::be_u32,
                                        [&](const someip_message&, std::uint32_t v) { decoded = v; });
  std::vector<std::vector<std::byte>> frames;  // the reassembler keeps views: frames must outlive it
  frames.reserve(8);
  for (u16 method : {u16(0x8003), u16(0x8005)})
    for (std::size_t off = 0; off < payload.size(); off += 1392) {
      const std::size_t n = std::min<std::size_t>(1392, payload.size() - off);
      frames.push_back(*make_frame(eth{}, ipv4{}, udp{.dst_port = 30501},
                           someip{.service_id = 0x1234, .method_id = method,
                                  .tp = someip_tp{.offset = u32(off), .more = off + n < payload.size()}},
                           raw{bytes(payload).subspan(off, n)}));
      reg.dispatch(packet::parse(frames.back()));
    }
  CHECK_EQ(got, 3000u);
  CHECK(equal);
  CHECK_EQ(decoded, 0x00070e15u);  // first 4 payload bytes, decoded from the scratch copy
}

TEST_MAIN()
