// SPDX-License-Identifier: Apache-2.0
// nanowire/nanowire.hpp — umbrella header: every nanowire protocol, the packet view, frame
// building, reassembly and dispatch. Include the individual headers to compile less.
//
//   core.hpp         vocabulary: bytes, addresses, BE loads, wire-struct field access / patching
//   ethernet.hpp     Ethernet II, 802.1Q / 802.1ad VLAN
//   ip.hpp           IPv4 (+options), IPv6 (+extension chain, fragment, SRv6)
//   transport.hpp    UDP, TCP
//   someip.hpp       SOME/IP header, SOME/IP-TP header, message iteration
//   someip_sd.hpp    SOME/IP Service Discovery entries and options
//   autosar_pdu.hpp  PDU-over-IP (SoAd) and IpduM container PDUs
//   packet.hpp       one-pass packet view
//   build.hpp        frame composition from builder values
//   reassembly.hpp   zero-copy reassembly (IPv4, IPv6, SOME/IP-TP)
//   dispatch.hpp     runtime registry + compile-time dispatch
#ifndef NANOWIRE_NANOWIRE_HPP_INCLUDED
#define NANOWIRE_NANOWIRE_HPP_INCLUDED

#include <nanowire/autosar_pdu.hpp>
#include <nanowire/build.hpp>
#include <nanowire/core.hpp>
#include <nanowire/dispatch.hpp>
#include <nanowire/ethernet.hpp>
#include <nanowire/ip.hpp>
#include <nanowire/packet.hpp>
#include <nanowire/reassembly.hpp>
#include <nanowire/someip.hpp>
#include <nanowire/someip_sd.hpp>
#include <nanowire/transport.hpp>

#endif  // NANOWIRE_NANOWIRE_HPP_INCLUDED
