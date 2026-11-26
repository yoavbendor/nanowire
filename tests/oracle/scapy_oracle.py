#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""scapy as an independent oracle for nanowire (parse AND build).

  scapy_oracle.py gen   OUT.pcap OUT.kv   build a varied capture with scapy; OUT.kv holds scapy's
                                          own dissection of every packet (one line per packet,
                                          space-separated key=value). test_oracle `parse` checks
                                          nanowire's reading of OUT.pcap against it.
  scapy_oracle.py check IN.pcap IN.kv     IN.pcap was built by nanowire's builders (test_oracle
                                          `build`), IN.kv is what nanowire meant to write. Checks
                                          (1) scapy's dissection equals IN.kv, and (2) every length
                                          and checksum field equals what scapy computes itself
                                          (each auto field is deleted and the packet re-serialized:
                                          the bytes must not change).

Both sides describe a packet with the same keys (see describe() here and in test_oracle.cpp).
SOME/IP is bound to UDP ports 30490 / 30501, PDU-over-IP to 42000. IpduM containers have no scapy
dissector; they are covered by byte-exact vectors in test_protocols instead.
"""
import ipaddress
import random
import struct
import sys

from scapy.contrib.automotive.autosar.pdu import PDU, PDUTransport
from scapy.contrib.automotive.someip import (SD, SOMEIP, SDEntry_EventGroup, SDEntry_Service,
                                             SDOption_Config, SDOption_IP4_EndPoint,
                                             SDOption_IP4_Multicast, SDOption_IP4_SD_EndPoint,
                                             SDOption_IP6_EndPoint, SDOption_IP6_Multicast,
                                             SDOption_IP6_SD_EndPoint, SDOption_LoadBalance)
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import (IPv6, HBHOptUnknown, IPv6ExtHdrDestOpt, IPv6ExtHdrFragment,
                                IPv6ExtHdrHopByHop, IPv6ExtHdrSegmentRouting, RouterAlert)
from scapy.layers.l2 import Dot1AD, Dot1Q, Ether
from scapy.packet import Raw, bind_bottom_up, bind_layers
from scapy.utils import rdpcap, wrpcap

SOMEIP_PORTS = (30490, 30501)
PDU_PORT = 42000
for _p in SOMEIP_PORTS:
    bind_bottom_up(UDP, SOMEIP, sport=_p)
    bind_bottom_up(UDP, SOMEIP, dport=_p)
bind_bottom_up(UDP, PDUTransport, dport=PDU_PORT)
SOMEIP.payload_cls_by_srv_id[0xFFFF] = SD

V6_EXT = {IPv6ExtHdrHopByHop: 0, IPv6ExtHdrSegmentRouting: 43, IPv6ExtHdrFragment: 44, IPv6ExtHdrDestOpt: 60}
OPT_V4 = (SDOption_IP4_EndPoint, SDOption_IP4_Multicast, SDOption_IP4_SD_EndPoint)
OPT_V6 = (SDOption_IP6_EndPoint, SDOption_IP6_Multicast, SDOption_IP6_SD_EndPoint)


def v6(a):
    return ':'.join(format(int(g, 16), 'x') for g in ipaddress.IPv6Address(a).exploded.split(':'))


def layers(p):
    out = []
    while p is not None and p.__class__.__name__ != 'NoPayload':
        out.append(p)
        p = p.payload
    return out


def describe(pkt):
    kv = {}
    ls = layers(pkt)
    e = pkt[Ether]
    kv['eth.dst'], kv['eth.src'], kv['eth.type'] = e.dst.lower(), e.src.lower(), e.type
    vl = [l for l in ls if isinstance(l, (Dot1Q, Dot1AD))]
    kv['vlan.n'] = len(vl)
    for i, l in enumerate(vl):
        kv[f'vlan.{i}.vid'], kv[f'vlan.{i}.pcp'], kv[f'vlan.{i}.dei'], kv[f'vlan.{i}.type'] = l.vlan, l.prio, l.id, l.type
    sport = dport = None
    if IP in pkt:
        ip = pkt[IP]
        kv.update({'ip.ihl': ip.ihl, 'ip.dscp': ip.tos >> 2, 'ip.ecn': ip.tos & 3, 'ip.len': ip.len, 'ip.id': ip.id,
                   'ip.df': int(bool(ip.flags.DF)), 'ip.mf': int(bool(ip.flags.MF)),
                   'ip.rsv': int(bool(ip.flags.evil)), 'ip.frag': ip.frag,
                   'ip.ttl': ip.ttl, 'ip.proto': ip.proto, 'ip.chksum': ip.chksum, 'ip.src': ip.src, 'ip.dst': ip.dst})
    if IPv6 in pkt:
        ip = pkt[IPv6]
        kv.update({'ip6.tc': ip.tc, 'ip6.fl': ip.fl, 'ip6.plen': ip.plen, 'ip6.nh': ip.nh, 'ip6.hlim': ip.hlim,
                   'ip6.src': v6(ip.src), 'ip6.dst': v6(ip.dst)})
        kv['ip6.ext'] = ','.join(str(V6_EXT[type(l)]) for l in ls if type(l) in V6_EXT) or '-'
        if IPv6ExtHdrSegmentRouting in pkt:
            s = pkt[IPv6ExtHdrSegmentRouting]
            kv['srh.left'], kv['srh.last'] = s.segleft, s.lastentry
            kv['srh.segs'] = ','.join(v6(a) for a in s.addresses)
        if IPv6ExtHdrFragment in pkt:
            f = pkt[IPv6ExtHdrFragment]
            kv['frag6.off'], kv['frag6.m'], kv['frag6.id'] = f.offset, f.m, f.id
    if UDP in pkt and not (IPv6ExtHdrFragment in pkt and pkt[IPv6ExtHdrFragment].offset):
        u = pkt[UDP]
        sport, dport = u.sport, u.dport
        kv.update({'udp.sport': u.sport, 'udp.dport': u.dport, 'udp.len': u.len, 'udp.chksum': u.chksum})
    if TCP in pkt:
        t = pkt[TCP]
        kv.update({'tcp.sport': t.sport, 'tcp.dport': t.dport, 'tcp.seq': t.seq, 'tcp.ack': t.ack,
                   'tcp.dataofs': t.dataofs, 'tcp.flags': int(t.flags), 'tcp.window': t.window,
                   'tcp.chksum': t.chksum, 'tcp.urgptr': t.urgptr})
    if SOMEIP in pkt and (sport in SOMEIP_PORTS or dport in SOMEIP_PORTS):
        m = pkt[SOMEIP]
        kv.update({'someip.srv': m.srv_id, 'someip.meth': m.sub_id, 'someip.len': m.len, 'someip.client': m.client_id,
                   'someip.session': m.session_id, 'someip.proto': m.proto_ver, 'someip.iface': m.iface_ver,
                   'someip.type': m.msg_type, 'someip.rc': m.retcode})
        if m.msg_type & 0x20:
            kv['tp.offset'], kv['tp.more'] = m.offset, m.more_seg
    if SD in pkt:
        sd = pkt[SD]
        kv['sd.flags'] = int(sd.flags)
        kv['sd.entries'] = len(sd.entry_array)
        for i, en in enumerate(sd.entry_array):
            p = f'sd.e.{i}.'
            kv.update({p + 'type': en.type, p + 'idx1': en.index_1, p + 'idx2': en.index_2, p + 'n1': en.n_opt_1,
                       p + 'n2': en.n_opt_2, p + 'srv': en.srv_id, p + 'inst': en.inst_id, p + 'major': en.major_ver,
                       p + 'ttl': en.ttl})
            if isinstance(en, SDEntry_Service):
                kv[p + 'minor'] = en.minor_ver
            else:
                kv[p + 'cnt'], kv[p + 'eg'] = en.cnt, en.eventgroup_id
        kv['sd.options'] = len(sd.option_array)
        for i, o in enumerate(sd.option_array):
            p = f'sd.o.{i}.'
            kv[p + 'type'], kv[p + 'len'] = o.type, o.len
            if isinstance(o, OPT_V4):
                kv[p + 'addr'], kv[p + 'proto'], kv[p + 'port'] = o.addr, o.l4_proto, o.port
            elif isinstance(o, OPT_V6):
                kv[p + 'addr'], kv[p + 'proto'], kv[p + 'port'] = v6(o.addr), o.l4_proto, o.port
            elif isinstance(o, SDOption_LoadBalance):
                kv[p + 'prio'], kv[p + 'weight'] = o.priority, o.weight
            elif isinstance(o, SDOption_Config):
                kv[p + 'cfg'] = bytes(o.cfg_str).hex() or '-'
    if PDUTransport in pkt and dport == PDU_PORT:
        pdus = pkt[PDUTransport].pdus
        kv['pdu.n'] = len(pdus)
        for i, x in enumerate(pdus):
            kv[f'pdu.{i}.id'], kv[f'pdu.{i}.len'] = x.pdu_id, x.pdu_payload_len
    return {k: str(v) for k, v in kv.items()}


AUTO = {IP: ('ihl', 'len', 'chksum'), IPv6: ('plen',), UDP: ('len', 'chksum'), TCP: ('dataofs', 'chksum'),
        SD: ('len_entry_array', 'len_option_array'), IPv6ExtHdrHopByHop: ('len',),
        IPv6ExtHdrDestOpt: ('len',), IPv6ExtHdrSegmentRouting: ('len',), SDOption_Config: ('len',),
        PDU: ('pdu_payload_len',)}


def recomputed(pkt):
    """The packet re-serialized with every auto field left for scapy to compute."""
    c = pkt.copy()

    def strip(p):
        for l in layers(p):
            for f in AUTO.get(type(l), ()):
                if f in l.fields:
                    delattr(l, f)
            for fld in getattr(l, 'fields_desc', []):  # packet lists (SD entries / options, PDUs)
                v = l.fields.get(fld.name)
                if isinstance(v, list):
                    for sub in v:
                        if hasattr(sub, 'fields_desc'):
                            strip(sub)
    strip(c)
    return bytes(c)


def gen(out_pcap, out_kv):
    r = random.Random(11)
    pk = []

    def eth(*vl):
        return Ether(dst='02:00:00:00:00:02', src='02:00:00:00:00:%02x' % r.randrange(256))

    def someip(**kw):
        d = dict(srv_id=r.randrange(0x10000), sub_id=r.randrange(0x10000), client_id=r.randrange(0x10000),
                 session_id=r.randrange(0x10000), iface_ver=r.randrange(256), msg_type=r.choice([0, 1, 2, 0x80, 0x81]),
                 retcode=r.randrange(16))
        d.update(kw)
        return SOMEIP(**d)

    def payload(n=None):
        return Raw(bytes(r.randrange(256) for _ in range(n if n is not None else r.randrange(1, 64))))

    for _ in range(12):
        pk.append(eth() / IP(src='10.0.0.%d' % r.randrange(1, 255), dst='10.0.1.%d' % r.randrange(1, 255),
                             ttl=r.randrange(1, 256), tos=r.randrange(256), id=r.randrange(0x10000), flags='DF')
                  / UDP(sport=r.choice([30501, 40000]), dport=30501) / someip() / payload())
    for _ in range(4):
        pk.append(eth() / Dot1Q(vlan=r.randrange(4096), prio=r.randrange(8), id=r.randrange(2))
                  / IP(options=b'\x94\x04\x00\x00') / UDP(sport=30501, dport=30501) / someip() / payload())
    pk.append(eth() / Dot1AD(vlan=10, prio=5) / Dot1Q(vlan=100, prio=3) / IP() / UDP(sport=1, dport=30501)
              / someip() / payload())
    pk.append(eth() / IPv6(src='fd00::1', dst='fd00::2', tc=0xb8, fl=0x12345)
              / IPv6ExtHdrHopByHop(options=[RouterAlert()])
              / IPv6ExtHdrSegmentRouting(addresses=['fc00::1', 'fc00::2', 'fc00::3'], segleft=2)
              / IPv6ExtHdrDestOpt() / UDP(sport=30501, dport=30501) / someip() / payload())
    pk.append(eth() / IPv6(src='fd00::1', dst='fd00::2') / IPv6ExtHdrFragment(offset=0, m=1, id=0xabcdef)
              / UDP(sport=30501, dport=30501) / someip() / payload(32))
    pk.append(eth() / IPv6(src='fd00::1', dst='fd00::2') / IPv6ExtHdrFragment(offset=5, m=0, id=0xabcdef, nh=17)
              / payload(24))
    pk.append(eth() / IP(src='1.2.3.4', dst='5.6.7.8') / TCP(sport=1234, dport=80, seq=1000, ack=2000, flags='SA',
                                                             options=[('MSS', 1460), ('NOP', None), ('WScale', 7)])
              / payload(5))
    for off in (0, 1392, 2784):
        pk.append(eth() / IP() / UDP(sport=30501, dport=30501)
                  / someip(srv_id=0x1234, sub_id=0x8003, msg_type=0x22, offset=off, more_seg=int(off < 2784))
                  / payload(1392 if off < 2784 else 100))
    sd = SD(flags=0xC0)
    sd.set_entryArray([
        SDEntry_Service(type=0, srv_id=0x1111, inst_id=0xFFFF, major_ver=0xFF, ttl=3, minor_ver=0xFFFFFFFF),
        SDEntry_Service(type=1, srv_id=0x1234, inst_id=1, major_ver=1, ttl=0xFFFFFF, minor_ver=5, index_1=0, n_opt_1=2),
        SDEntry_EventGroup(type=6, srv_id=0x1234, inst_id=1, major_ver=1, ttl=5, cnt=3, eventgroup_id=7,
                           index_1=2, n_opt_1=1, index_2=3, n_opt_2=3),
        SDEntry_EventGroup(type=7, srv_id=0x1234, inst_id=1, major_ver=1, ttl=0, eventgroup_id=7)])
    sd.set_optionArray([
        SDOption_IP4_EndPoint(addr='10.0.0.1', l4_proto=17, port=30501),
        SDOption_LoadBalance(priority=1, weight=2),
        SDOption_IP4_Multicast(addr='239.0.0.1', l4_proto=17, port=30502),
        SDOption_IP6_EndPoint(addr='fd00::1', l4_proto=6, port=30503),
        SDOption_IP6_Multicast(addr='ff02::1', l4_proto=17, port=30504),
        SDOption_Config(cfg_str=SDOption_Config.make_string([('hello', 'world'), ('x', 'y')])),
        SDOption_IP4_SD_EndPoint(addr='10.0.0.9', l4_proto=17, port=30490),
        SDOption_IP6_SD_EndPoint(addr='fd00::9', l4_proto=17, port=30490)])
    pk.append(eth() / IP() / UDP(sport=30490, dport=30490)
              / SOMEIP(srv_id=0xFFFF, sub_id=0x8100, msg_type=2, client_id=0, session_id=3) / sd)
    pk.append(eth() / IP(flags='evil+DF', id=r.randrange(0x10000)) / UDP(sport=30501, dport=30501)
              / someip(msg_type=0x22, offset=4176, more_seg=1) / payload(48))
    pk.append(eth() / IP() / UDP(sport=50000, dport=PDU_PORT)
              / PDUTransport(pdus=[PDU(pdu_id=0x100) / Raw(b'abc'), PDU(pdu_id=0xdeadbeef) / Raw(b''),
                                   PDU(pdu_id=7) / Raw(bytes(range(20)))]))
    pkts = [Ether(bytes(p)) for p in pk]  # serialize (scapy computes every auto field), re-dissect
    wrpcap(out_pcap, pkts)
    with open(out_kv, 'w') as f:
        for p in pkts:
            f.write(' '.join(f'{k}={v}' for k, v in describe(p).items()) + '\n')
    print(f'{len(pkts)} packets')


def check(in_pcap, in_kv):
    pkts = rdpcap(in_pcap)
    want = [dict(t.split('=', 1) for t in line.split()) for line in open(in_kv) if line.strip()]
    if len(pkts) != len(want):
        print(f'packet count {len(pkts)} != {len(want)}')
        return 1
    bad = 0
    for i, (p, w) in enumerate(zip(pkts, want)):
        p = Ether(bytes(p))
        got = describe(p)
        for k in sorted(set(got) | set(w)):
            if got.get(k) != w.get(k):
                print(f'pkt {i}: {k}: scapy={got.get(k)} nanowire={w.get(k)}')
                bad += 1
        if SOMEIP in p:  # scapy's SOMEIP.post_build cannot recompute len for a dissected packet
            m = p[SOMEIP]  # (its data lives in a field, not the payload): check the definition
            if m.len != len(bytes(m)) - 8:
                print(f'pkt {i}: someip.len {m.len} != {len(bytes(m)) - 8}')
                bad += 1
        again = recomputed(p)
        if again != bytes(p):
            diff = next(j for j in range(min(len(again), len(bytes(p)))) if again[j] != bytes(p)[j]) \
                if len(again) == len(bytes(p)) else 'len'
            print(f'pkt {i}: scapy recomputes different auto fields (first diff at byte {diff})')
            bad += 1
    print(f'{len(pkts)} packets, {bad} mismatches')
    return 1 if bad else 0


if __name__ == '__main__':
    if len(sys.argv) != 4 or sys.argv[1] not in ('gen', 'check'):
        print(__doc__)
        sys.exit(2)
    if sys.argv[1] == 'gen':
        gen(sys.argv[2], sys.argv[3])
    else:
        sys.exit(check(sys.argv[2], sys.argv[3]))
