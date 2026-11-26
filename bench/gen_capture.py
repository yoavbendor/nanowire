#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Benchmark / golden-test capture generator: python3 gen_capture.py out.pcap N
# Synthetic automotive capture: classic pcap, Ethernet+VLAN, IPv4/IPv6, UDP, SOME/IP, SD, TP, IP fragments.
import struct, random, sys
r = random.Random(7)
def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b)//2), b)); s = (s & 0xffff) + (s >> 16); s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff
def eth(et, vlan=True):
    h = bytes.fromhex('0180c2000001') + bytes.fromhex('02000000aa01')
    return h + (struct.pack('!HHH', 0x8100, (3 << 13) | 100, et) if vlan else struct.pack('!H', et))
def ipv4(proto, payload, ident=0, mf=0, off=0):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, (mf << 13) | off, 64, proto, 0, bytes([10,0,0,1]), bytes([10,0,0,2]))
    return h[:10] + struct.pack('!H', csum(h)) + h[12:] + payload
def ipv6(nh, payload):
    return struct.pack('!IHBB16s16s', 0x60000000, len(payload), nh, 64, b'\xfd' + b'\0'*14 + b'\1', b'\xfd' + b'\0'*14 + b'\2') + payload
def udp(sp, dp, payload):
    return struct.pack('!HHHH', sp, dp, 8 + len(payload), 0) + payload
def someip(svc, meth, mtype, payload, tp=None):
    body = (struct.pack('!I', tp) if tp is not None else b'') + payload
    return struct.pack('!HHIHHBBBB', svc, meth, 8 + len(body), 0x0001, r.randrange(65536), 1, 1, mtype | (0x20 if tp is not None else 0), 0) + body
def sd():
    entries = struct.pack('!BBBBHHII', 1, 0, 0, 0x10, 0x1234, 1, (1 << 24) | 0xffffff, 0) * 2
    opts = struct.pack('!HBB4sBBH', 9, 4, 0, bytes([10,0,0,1]), 0, 17, 30501)
    return struct.pack('!BBBBI', 0xc0, 0, 0, 0, len(entries)) + entries + struct.pack('!I', len(opts)) + opts
pkts = []
n = int(sys.argv[2])
for i in range(n):
    k = r.random()
    if k < 0.70:
        p = eth(0x0800) + ipv4(17, udp(30501, 30501, someip(0x1234, 0x8001, 2, bytes(r.randrange(256) for _ in range(32)))))
    elif k < 0.80:
        p = eth(0x0800) + ipv4(17, udp(30490, 30490, someip(0xffff, 0x8100, 2, sd())))
    elif k < 0.90:
        p = eth(0x86dd) + ipv6(17, udp(30501, 30501, someip(0x1234, 0x8002, 2, bytes(40))))
    elif k < 0.95:
        p = eth(0x0800) + ipv4(17, udp(30501, 30501, someip(0x1234, 0x8003, 2, bytes(1392), tp=((i % 8) * 1392 // 16) << 4 | 1)))
    else:
        dgram = udp(30501, 30501, someip(0x1234, 0x8004, 2, bytes(2900)))
        ident = i & 0xffff
        for off in range(0, len(dgram), 1480):
            chunk = dgram[off:off+1480]
            pkts.append(eth(0x0800) + ipv4(17, chunk, ident, 1 if off + 1480 < len(dgram) else 0, off // 8))
        continue
    pkts.append(p)
with open(sys.argv[1], 'wb') as f:
    f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for i, p in enumerate(pkts):
        f.write(struct.pack('<IIII', i // 1000, i % 1000, len(p), len(p)) + p)
print(len(pkts), 'packets')
