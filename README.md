# nanowire

**One definition per protocol, used for both parsing and crafting.**

nanowire is the header-only C++23 protocol core shared by the two edges of the nano family:

```
              capture ──► nanoshark (read edge: views, tables, sinks)
                              │
                          nanowire   ◄── protocol definitions, views, builders,
                              │          reassembly, dispatch (this repo)
                              │
  templates / pcap / TX ◄── nanocraft (craft edge: compiled frame templates, writers, sinks)
                              │
                            nanom    ◄── parser / emitter / reflection core
```

Each protocol header is declared **once** as a [nanom](https://github.com/yoavbendor/nanom)
described wire struct (`be<>` / `ubits<>` fields). From that single declaration:

- **views** read fields through nanom's own field decode (a `be<u16>` is one load + bswap),
- **builders** write it with `nanom::emit`, deriving lengths and checksums through
  `nanom::computed` fields,
- **templates** patch single fields in place by name (`patch<wire::ipv4_hdr, "ttl">(p, 3)`) at
  offsets known at compile time (`field_offset_v<wire::someip_hdr, "session_id">`).

Its only dependency is nanom (header-only, fetched by CMake). Apache-2.0.

## Protocols (v0.1)

| Layer | Read (zero-copy view) | Build |
|---|---|---|
| Ethernet II, 802.1Q / 802.1ad (QinQ) | `ethernet_view`, `vlan_view` | `eth`, `vlan` |
| IPv4 + options | `ipv4_view`, `ipv4_options` | `ipv4` (ihl / total_length / checksum derived) |
| IPv6 + extension chain (HbH, Routing / SRv6, Fragment, DstOpts, AH) | `ipv6_view`, `ipv6_ext_range`, `ipv6_fragment_view`, `ipv6_routing_view` | `ipv6`, `ipv6_hbh`, `ipv6_srh`, `ipv6_frag`, `ipv6_dstopts` |
| UDP, TCP (header) | `udp_view`, `tcp_view` | `udp`, `tcp` (pseudo-header checksums, SRv6-aware) |
| SOME/IP, SOME/IP-TP | `someip_view`, `someip_tp_view`, `someip_messages` | `someip{.tp = ...}` |
| SOME/IP-SD entries + all option types | `sd_view`, `sd_entries`, `sd_options`, `sd_config_items` | `someip_sd`, `sd_entry`, `sd_option` |
| AUTOSAR PDU-over-IP (SoAd header) | `soad_pdus` | `soad_pdu`, `soad_pdu_header` |
| AUTOSAR IpduM container PDUs (short / long header, BE / LE) | `ipdum_pdus` | `ipdum_container` |

Plus: the one-pass `packet` view, zero-copy `reassembler` (IPv4, IPv6, SOME/IP-TP), and a
runtime `registry` with a compile-time fast path.

## Quick start

```cmake
include(FetchContent)
FetchContent_Declare(nanowire GIT_REPOSITORY https://github.com/yoavbendor/nanowire.git GIT_TAG <commit>)
FetchContent_MakeAvailable(nanowire)
target_link_libraries(app PRIVATE nanowire::nanowire)
```

Developing nanowire and nanom together: `cmake -B build -DFETCHCONTENT_SOURCE_DIR_NANOM=/path/to/nanom`.
Tests and benchmarks build by default when nanowire is the top-level project
(`NANOWIRE_BUILD_TESTS`, `NANOWIRE_BUILD_BENCH`; `NANOWIRE_SANITIZER=address,undefined`).

### Read a packet

```cpp
#include <nanowire/nanowire.hpp>
using namespace nanowire;

auto pkt = packet::parse(frame);                 // std::span<const std::byte>; never allocates
if (auto ip = pkt.ipv4()) use(ip->src(), ip->ttl(), ip->checksum_ok());
if (auto u = pkt.udp())   use(u->dst_port());
if (auto m = pkt.someip())                       // the UDP payload read as SOME/IP
  use(m->service_id(), m->method_id(), m->session_id());
for (auto m : pkt.someip_all()) ...              // several messages in one datagram
```

The walk computes every offset in one pass: L2 end incl. the VLAN stack, L3, the IPv6
extension chain, L4, L4 payload. Lengths are bounded by the IP / UDP length fields (Ethernet
padding excluded) and by the captured bytes. A truncated or malformed layer ends the walk; the
outer layers stay available. Fragments with a non-zero offset carry no L4 header.

### Iterate SOME/IP-SD entries and their options

```cpp
if (auto sd = sd_view::parse(*pkt.someip())) {   // nullopt unless Message ID 0xFFFF8100
  for (auto e : sd->entries()) {
    if (e.type() == sd_entry_type::offer_service && !e.is_stop())
      sd->for_each_option(e, [&](const sd_option_view& o, int run) {
        if (auto ep = o.endpoint()) use(ep->v4, ep->l4_proto, ep->port);
      });
  }
  for (auto o : sd->options())
    for (auto item : o.configuration()) use(sd_config_items::split(item));  // {"key","value"}
}
```

### Iterate AUTOSAR PDUs

```cpp
for (auto p : soad_pdus(pkt.payload()))                       // [id:32][len:32][data] ...
  if (p.id == kContainerId)
    for (auto c : ipdum_pdus(p.data, {.header = ipdum_header::short_header}))  // [id:24][dlc:8][data] ...
      use(c.id, c.data);
```

### Reassemble SOME/IP-TP (and IPv4 / IPv6) without copying

```cpp
someip_tp_reassembler tp(tp_reassembly_defaults());           // all storage allocated here, once
for (auto m : pkt.someip_all()) {
  auto r = feed(tp, pkt, m, now_ns, buffer_token);
  if (r.complete()) {
    // r.parts: part 0 = the rebuilt 16-byte header (length fixed up, TP flag cleared),
    // then the payload segments: views into the captured frames, never copied.
    auto hdr = nanom::strct_seg<wire::someip_hdr>(std::endian::big)(r.input());
  }
}
tp.expire(now_ns);
```

`ipv4_reassembler` / `ipv6_reassembler` work the same way (`feed(r, pkt, now)`). The template
`reassembler<Key, Hash, HeaderBytes>` has limits (max datagram size, datagrams in flight,
fragments per datagram, idle timeout on your clock, fragment unit), overlap policies
(`reject_conflict` — the RFC 5722 stance —, `first_wins`, `last_wins`), an epoch (a new
SOME/IP-TP session aborts the old message), buffer tokens released through a hook when a
datagram is done, and no allocation in steady state (tested with a counting `operator new`).

### Build a frame

```cpp
std::array<std::byte, 1514> buf;
auto f = build_frame(buf,
    eth{.dst = mac("02:00:00:00:00:02"), .src = mac("02:00:00:00:00:01")},
    vlan{.vid = 100, .pcp = 3},
    ipv4{.src = ip4("10.0.0.1"), .dst = ip4("10.0.0.2")},
    udp{.src_port = 30501, .dst_port = 30501},
    someip{.service_id = 0x1234, .method_id = 0x8001, .session_id = 7},
    raw{payload});
// f->size; f->layers[i].offset / .size: where each layer landed (a template's field map)
```

Unset type / protocol fields take the next layer's (`eth.type` from the VLAN TPID, 0x0800, ...);
every length covers the layers after it; IPv4 header and UDP / TCP checksums are computed after
the frame is written. Any explicit value (`.total_length`, `.checksum`, `.length`) overrides the
derivation, so malformed frames can be crafted on purpose. SD:
`someip_sd_header(session)` + `someip_sd{.entries = ..., .options = ...}`.

### Dispatch

```cpp
registry reg;                                             // UDP 30490 is SOME/IP by default
reg.port(30501, app_protocol::someip)
   .port(42000, app_protocol::pdu_over_ip)
   .on_someip(0x1234, 0x8001, [](const someip_message& m) { ... })
   .on_someip_payload<std::uint32_t>(0x1234, 0x8002, nanom::be_u32,   // nanom::dyn<T> decoder
                                     [](const someip_message&, std::uint32_t v) { ... })
   .on_sd([](const someip_message&, const sd_view& sd) { ... })
   .on_pdu(0x100, [](const pdu_message& p) { ... })
   .container(0x300, {.header = ipdum_header::short_header})
   .attach(tp);                                           // TP segments reassembled, then dispatched
reg.dispatch(pkt, now);

// compile-time fast path: a compare chain, no table
dispatch_static<message_id(0x1234, 0x8001), message_id(0x1234, 0x8002)>(m->message_id(),
    [](auto id) { if constexpr (id() == message_id(0x1234, 0x8001)) ...; });
```

## Performance

`bench/packet_walk_bench` walks a classic pcap straight out of memory, locates the SOME/IP
header and reads service / method / session. Capture: `bench/gen_capture.py` (synthetic
automotive mix: VLAN, IPv4 / IPv6, SOME/IP, SD, TP, IP fragments), 1.05 M packets / 331 MB,
GCC 13 -O3, a shared 4-core VM (best of 7 reps; three runs):

| mode | ns/pkt (idle machine) | ns/pkt (loaded machine) | instr/pkt (callgrind) |
|---|---|---|---|
| floor: fixed offsets, no parsing | 40.3 | 54.3 – 56.0 | 34 |
| **nanowire** `packet::parse` + `someip()` | **41.0** (clang 39.9) | 57.2 – 58.0 | 126 |
| nanowire, all views + every SOME/IP message | 42.3 | 57.1 – 58.4 | 147 |
| nanom_shark `walk_packet_ext` | 76.0 (clang 57.4) | 73.8 – 75.3 | 228 |

The walk is memory bound: nanowire sits within 1–3 ns of the raw read floor.

```sh
python3 bench/gen_capture.py auto.pcap 1000000
./build/bench/packet_walk_bench auto.pcap 7
valgrind --tool=callgrind ./build/bench/packet_walk_bench small.pcap 1 nanowire
```

## Tests

`ctest` runs:

- `test_protocols` — parse / build round trips of every protocol, known-answer bytes (IPv4
  checksum, IpduM / PDU layouts), field offsets and in-place patching with RFC 1624 update.
- `test_malformed` — every truncation of every corpus frame and 60 k random mutations, each from
  an exactly-sized heap buffer (ASan trips on a one-byte over-read), plus a check that every span
  a reader returns lies inside its input.
- `test_reassembly` — IPv4 / IPv6 / TP: in order, permutations, duplicates, benign overlap,
  conflicting overlap under each policy, timeout, capacity eviction, limits, tokens, zero-copy
  aliasing proof, no allocation in steady state.
- `test_dispatch` — registry routing, dyn decoders, SD, PDUs, containers, TP through the registry.
- `test_golden_shark` — field-by-field agreement with nanom_shark on nanom's test captures and a
  generated capture (incl. byte-identical reassembled datagrams).
- `oracle_*` — scapy as an independent oracle: nanowire's reading of scapy-built packets equals
  scapy's dissection, and scapy's dissection of nanowire-built frames equals what nanowire meant,
  with every length / checksum re-derived by scapy. Committed vectors always run; live scapy runs
  when a Python with scapy is found.

CI (`.github/workflows/ci.yml`): GCC 13 and Clang 18, Release and ASan+UBSan, `-Werror`.

## Layout

```
include/nanowire/   core, ethernet, ip, transport, someip, someip_sd, autosar_pdu,
                    packet, build, reassembly, dispatch, nanowire (umbrella), detail/checksum
tests/              ctest suites, oracle/scapy_oracle.py, data/ (committed scapy vectors)
bench/              packet_walk_bench, gen_capture.py
```

## License

Apache-2.0. See [LICENSE](LICENSE).
