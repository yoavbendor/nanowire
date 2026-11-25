// SPDX-License-Identifier: Apache-2.0
// nanowire/reassembly.hpp — generic ZERO-COPY reassembly, one template for IPv4, IPv6 and
// SOME/IP-TP (generalized from nanom_shark's defrag.hpp).
//
// Fragments are never copied: the table stores spans into the caller's buffers and, when a
// datagram is complete, returns it as an ordered, overlap-trimmed list of views (a
// nanom::segments) that nanom's segmented parsers (strct_seg / seg_input) read directly. Only
// copy_to() materializes, and only when asked.
//
//   nanowire::ipv4_reassembler r({.max_in_flight = 256, .timeout = 2'000'000'000});   // ns clock
//   auto res = nanowire::feed(r, pkt, now_ns, token);
//   if (res.status == nanowire::frag_status::complete) {
//     nanom::seg_input in = res.input();                 // the reassembled IP payload
//     ...                                               // parse UDP / SOME/IP over it
//     r.release(res.id);                                // or leave it to auto_release
//   }
//   r.expire(now_ns);                                   // age out stale datagrams
//
// Buffer lifetime (tokens): each fragment carries a caller-opaque token naming the buffer its
// span points into. When a datagram's slot is freed (released, completed-and-auto-released,
// dropped, timed out, evicted, superseded) the table calls hooks.release(ctx, token) once per
// fragment it retained; result.retained says whether THIS call's span was stored (a duplicate or
// a dropped fragment is not, so its buffer is free when add() returns).
//
// Limits: max datagram size, max datagrams in flight, max fragments per datagram, idle timeout
// on a caller-provided clock (any monotonically increasing u64), fragment size unit (8 for IP,
// 16 for SOME/IP-TP: every fragment but the last must be a multiple). Overlap policy:
// reject_conflict (overlaps must carry identical bytes, else the datagram is dropped — the
// RFC 5722 stance), first_wins, last_wins. An `epoch` per fragment lets a new instance under the
// same key supersede the old one (SOME/IP-TP: a new session ID aborts the previous message).
//
// Steady state allocates nothing: all slots, fragment records, part lists and the key index are
// sized once in the constructor.
#ifndef NANOWIRE_REASSEMBLY_HPP_INCLUDED
#define NANOWIRE_REASSEMBLY_HPP_INCLUDED

#include <nanowire/packet.hpp>
#include <nanowire/someip.hpp>

#include <nanom/segmented.hpp>

#include <algorithm>
#include <cstring>
#include <vector>

namespace nanowire {

enum class overlap_policy : u8 { reject_conflict, first_wins, last_wins };

struct reassembly_config {
  std::size_t max_datagram = 65535;   ///< reassembled size bound (bytes)
  std::size_t max_in_flight = 64;     ///< concurrent datagrams (slots)
  std::size_t max_fragments = 64;     ///< fragments stored per datagram
  u64 timeout = 0;                    ///< idle time (caller's clock units) before expire() drops; 0 = never
  std::size_t unit = 1;               ///< non-last fragments must be a multiple of this (1 = unchecked)
  overlap_policy overlap = overlap_policy::reject_conflict;
  bool evict_oldest_when_full = true; ///< full table: evict the least recently fed datagram (else drop new)
  bool auto_release = true;           ///< a completed datagram is released on the next add()/expire()
};

enum class frag_status : u8 {
  not_fragment,  ///< (feed helpers) the packet is not a fragment of this kind
  buffered,      ///< stored; datagram still incomplete
  duplicate,     ///< contributed no new bytes; not stored
  complete,      ///< this fragment completed the datagram: result.parts is valid
  dropped,       ///< fragment (and, per reason, its datagram) discarded
};
enum class drop_reason : u8 {
  none,
  too_large,           ///< beyond max_datagram
  too_many_fragments,  ///< beyond max_fragments
  capacity,            ///< table full (new datagram refused, or the oldest evicted)
  conflict,            ///< overlapping fragments disagree (reject_conflict)
  misaligned,          ///< a non-last fragment is not a multiple of `unit`
  inconsistent,        ///< data beyond the end announced by the last fragment, or two different ends
  timeout,             ///< idle longer than `timeout`
  superseded,          ///< a fragment with a new epoch under the same key replaced it
};

struct reassembly_stats {
  u64 fragments = 0, completed = 0, duplicates = 0, dropped_datagrams = 0, dropped_fragments = 0, timeouts = 0,
      evictions = 0;
};

template <class Key, class Hash = typename Key::hasher, std::size_t HeaderBytes = 0>
class reassembler {
 public:
  using token = u64;
  using key_type = Key;

  /// Optional callbacks (plain function pointers + context: no allocation, no std::function).
  struct hooks {
    void (*release)(void* ctx, token t) = nullptr;
    void (*dropped)(void* ctx, const Key& key, drop_reason why, u32 bytes, u32 fragments) = nullptr;
    void* ctx = nullptr;
  };

  struct result {
    frag_status status = frag_status::dropped;
    drop_reason reason = drop_reason::none;
    bool retained = false;   ///< this call's span (and token) is now held by the table
    u32 id = 0;              ///< datagram handle (for release / header)
    u32 meta = 0;            ///< caller metadata recorded with the offset-0 fragment
    nanom::segments parts{}; ///< complete: ordered views (part 0 = the header, when HeaderBytes > 0)
    std::span<const std::span<const std::byte>> part_list{};  ///< the same parts, as a span
    constexpr bool complete() const noexcept { return status == frag_status::complete; }
    std::size_t size() const noexcept { return parts.size(); }
    nanom::seg_input input() const noexcept { return nanom::from(parts); }
  };

  explicit reassembler(reassembly_config cfg = {}, hooks h = {}) : cfg_(cfg), hooks_(h) {
    cfg_.max_in_flight = std::clamp<std::size_t>(cfg_.max_in_flight, 1, 65535);
    cfg_.max_fragments = std::clamp<std::size_t>(cfg_.max_fragments, 1, 4096);
    if (cfg_.unit == 0) cfg_.unit = 1;
    pstride_ = 2 * cfg_.max_fragments + 2;  // [header][pieces <= 2*frags-1]
    slots_.resize(cfg_.max_in_flight);
    frags_.resize(cfg_.max_in_flight * cfg_.max_fragments);
    spans_.resize(cfg_.max_in_flight * pstride_);
    poff_.resize(cfg_.max_in_flight * pstride_);
    scratch_spans_.resize(pstride_);
    scratch_off_.resize(pstride_);
    std::size_t cap = 1;
    while (cap < 2 * cfg_.max_in_flight) cap <<= 1;
    index_.assign(cap, 0);
    mask_ = cap - 1;
    free_.reserve(cfg_.max_in_flight);
    for (std::size_t i = cfg_.max_in_flight; i-- > 0;) free_.push_back(u32(i));
  }
  reassembler(const reassembler&) = delete;
  reassembler& operator=(const reassembler&) = delete;

  /// Feed one fragment: [offset, offset + data.size()) of the datagram, `more` = more fragments
  /// follow. `header` (HeaderBytes > 0 only) is copied once per datagram; `meta` is recorded from
  /// the offset-0 fragment.
  result add(const Key& key, u64 now, u32 offset, bool more, bytes data, token tok = 0, u32 epoch = 0, u32 meta = 0,
             bytes header = {}) {
    if (pending_release_) release_pending();
    ++stats_.fragments;
    result r;
    const std::size_t end = std::size_t(offset) + data.size();
    if (end > cfg_.max_datagram) return drop_new(key, r, drop_reason::too_large);
    if (more && cfg_.unit > 1 && data.size() % cfg_.unit != 0) {
      // drop the datagram this would have joined, too: it can never complete correctly
      const std::size_t h = Hash{}(key);
      if (auto s = find(key, h)) kill(*s, drop_reason::misaligned);
      return drop_new(key, r, drop_reason::misaligned);
    }
    const std::size_t h = Hash{}(key);
    std::optional<u32> found = find(key, h);
    if (found && slots_[*found].epoch != epoch) {
      kill(*found, drop_reason::superseded);
      found.reset();
    }
    u32 si;
    if (found) {
      si = *found;
    } else {
      if (free_.empty()) {
        if (!cfg_.evict_oldest_when_full || !evict_oldest()) return drop_new(key, r, drop_reason::capacity);
      }
      si = free_.back();
      free_.pop_back();
      slot& s = slots_[si];
      const u16 g = u16(s.gen + 1);
      s = slot{};
      s.gen = g == 0 ? 1 : g;
      s.key = key;
      s.hash = h;
      s.used = true;
      s.epoch = epoch;
      s.first_seen = now;
      insert_index(si, h);
    }
    slot& s = slots_[si];
    s.last_seen = now;
    r.id = handle(si);
    if constexpr (HeaderBytes > 0) {
      if (!s.have_header && header.size() >= HeaderBytes) {
        std::memcpy(s.header.data(), header.data(), HeaderBytes);
        s.have_header = true;
      }
    }
    // end bookkeeping
    if (!more) {
      if (s.total != unknown && s.total != end) return kill_with(si, r, drop_reason::inconsistent);
      if (s.max_end > end) return kill_with(si, r, drop_reason::inconsistent);
      s.total = u32(end);
    } else if (s.total != unknown && end > s.total) {
      return kill_with(si, r, drop_reason::inconsistent);
    }
    if (offset == 0) s.meta = meta;

    // coverage update
    const auto added = cover(si, offset, data);
    if (added == cover_conflict) return kill_with(si, r, drop_reason::conflict);
    if (added == 0 && cfg_.overlap != overlap_policy::last_wins) {
      ++stats_.duplicates;
      r.status = frag_status::duplicate;
      return finish_check(si, r);
    }
    if (s.nfrags >= cfg_.max_fragments) return kill_with(si, r, drop_reason::too_many_fragments);
    frags_[si * cfg_.max_fragments + s.nfrags++] = frag_rec{tok};
    r.retained = true;
    s.max_end = std::max<u32>(s.max_end, u32(end));
    r.status = frag_status::buffered;
    return finish_check(si, r);
  }

  /// Done with a completed datagram (or abandon an in-flight one): frees its slot, releases tokens.
  void release(u32 id) {
    const u32 si = id & 0xffff;
    if (si >= slots_.size() || !slots_[si].used || handle(si) != id) return;
    free_slot(si);
  }

  /// Drop every datagram idle for more than `timeout` (reason timeout); completed datagrams the
  /// caller never released are released. Returns the number of datagrams removed.
  std::size_t expire(u64 now) {
    if (pending_release_) release_pending();
    if (cfg_.timeout == 0) return 0;
    std::size_t n = 0;
    for (u32 si = 0; si < slots_.size(); ++si) {
      slot& s = slots_[si];
      if (!s.used || now - s.last_seen <= cfg_.timeout || now < s.last_seen) continue;
      if (s.complete) {
        free_slot(si);
      } else {
        ++stats_.timeouts;
        kill(si, drop_reason::timeout);
      }
      ++n;
    }
    return n;
  }

  /// The captured header bytes of a datagram (HeaderBytes > 0).
  std::span<std::byte, HeaderBytes> header(u32 id) noexcept { return slots_[id & 0xffff].header; }

  std::size_t in_flight() const noexcept { return slots_.size() - free_.size(); }
  const reassembly_stats& stats() const noexcept { return stats_; }
  const reassembly_config& config() const noexcept { return cfg_; }

 private:
  static constexpr u32 unknown = 0xffffffffu;
  static constexpr std::size_t cover_conflict = std::size_t(-1);
  struct frag_rec {
    token tok;
  };
  struct slot {
    Key key{};
    std::size_t hash = 0;
    u64 first_seen = 0, last_seen = 0;
    u32 epoch = 0, total = unknown, covered = 0, max_end = 0, meta = 0;
    u32 nfrags = 0, npieces = 0;
    u16 gen = 0;
    bool used = false, complete = false, have_header = false;
    std::array<std::byte, HeaderBytes> header{};
  };

  constexpr u32 handle(u32 si) const noexcept { return (u32(slots_[si].gen) << 16) | si; }

  // ---- index (open addressing, linear probing, backward-shift deletion) ----
  std::optional<u32> find(const Key& k, std::size_t h) const noexcept {
    for (std::size_t i = h & mask_; index_[i]; i = (i + 1) & mask_) {
      const u32 si = index_[i] - 1;
      if (slots_[si].hash == h && slots_[si].key == k) return si;
    }
    return std::nullopt;
  }
  void insert_index(u32 si, std::size_t h) noexcept {
    std::size_t i = h & mask_;
    while (index_[i]) i = (i + 1) & mask_;
    index_[i] = si + 1;
  }
  void erase_index(u32 si) noexcept {
    std::size_t i = slots_[si].hash & mask_;
    while (index_[i] && index_[i] != si + 1) i = (i + 1) & mask_;
    if (!index_[i]) return;
    std::size_t j = i;
    for (;;) {
      j = (j + 1) & mask_;
      if (!index_[j]) break;
      const std::size_t k = slots_[index_[j] - 1].hash & mask_;
      const bool between = i <= j ? (i < k && k <= j) : (i < k || k <= j);
      if (!between) {
        index_[i] = index_[j];
        i = j;
      }
    }
    index_[i] = 0;
  }

  // ---- coverage: pieces sorted by offset, non-overlapping; returns bytes newly covered ----
  std::size_t cover(u32 si, u32 off, bytes data) {
    slot& s = slots_[si];
    std::span<const std::byte>* sp = &spans_[si * pstride_ + 1];
    u32* po = &poff_[si * pstride_ + 1];
    const u32 n = s.npieces;
    const u32 e = off + u32(data.size());
    if (data.empty()) return 0;
    std::size_t m = 0, added = 0;
    auto push = [&](u32 o, std::span<const std::byte> d) {
      scratch_off_[m] = o;
      scratch_spans_[m] = d;
      ++m;
    };
    if (cfg_.overlap == overlap_policy::last_wins) {
      std::size_t removed = 0;
      bool placed = false;
      for (u32 i = 0; i < n; ++i) {
        const u32 a = po[i], b = a + u32(sp[i].size());
        if (b <= off || a >= e) {  // disjoint
          if (!placed && a >= e) push(off, data), placed = true;
          push(a, sp[i]);
          continue;
        }
        if (a < off) push(a, sp[i].first(off - a));
        if (!placed) push(off, data), placed = true;
        if (b > e) push(e, sp[i].subspan(e - a));
        removed += std::min(b, e) - std::max(a, off);
      }
      if (!placed) push(off, data);
      added = data.size() - removed;
    } else {
      u32 cur = off;  // next byte of [off, e) not yet placed
      for (u32 i = 0; i < n; ++i) {
        const u32 a = po[i], b = a + u32(sp[i].size());
        if (b <= cur || a >= e) {
          if (a >= e && cur < e) {
            push(cur, data.subspan(cur - off, e - cur));
            added += e - cur;
            cur = e;
          }
          push(a, sp[i]);
          continue;
        }
        if (a > cur) {  // gap before this piece
          push(cur, data.subspan(cur - off, a - cur));
          added += a - cur;
        }
        if (cfg_.overlap == overlap_policy::reject_conflict) {
          const u32 lo = std::max(a, off), hi = std::min(b, e);
          if (std::memcmp(sp[i].data() + (lo - a), data.data() + (lo - off), hi - lo) != 0) return cover_conflict;
        }
        push(a, sp[i]);
        cur = std::max(cur, b);
      }
      if (cur < e) {
        push(cur, data.subspan(cur - off, e - cur));
        added += e - cur;
      }
    }
    if (m > pstride_ - 1) return cover_conflict;  // cannot happen (pieces <= 2 * fragments)
    for (std::size_t i = 0; i < m; ++i) po[i] = scratch_off_[i], sp[i] = scratch_spans_[i];
    s.npieces = u32(m);
    s.covered += u32(added);
    return added;
  }

  result& finish_check(u32 si, result& r) {
    slot& s = slots_[si];
    if (s.total == unknown || s.covered != s.total) return r;
    // complete: pieces are contiguous [0, total) because they are disjoint, inside [0, total)
    // and sum to total.
    s.complete = true;
    erase_index(si);
    ++stats_.completed;
    std::span<const std::byte>* base = &spans_[si * pstride_];
    std::size_t first = 1;
    if constexpr (HeaderBytes > 0) {
      base[0] = std::span<const std::byte>(s.header.data(), s.have_header ? HeaderBytes : 0);
      first = 0;
    }
    r.status = frag_status::complete;
    r.meta = s.meta;
    r.part_list = std::span<const std::span<const std::byte>>(base + first, s.npieces + 1 - first);
    r.parts = nanom::segments(r.part_list);
    if (cfg_.auto_release) {
      pending_release_ = true;
      pending_ = handle(si);
    }
    if constexpr (HeaderBytes > 0) on_complete_header(s);
    return r;
  }
  void on_complete_header(slot& s) noexcept {
    if constexpr (HeaderBytes >= 16) {  // SOME/IP: length = 8 + payload, clear the TP flag
      detail::put_be32(s.header.data() + 4, 8 + s.total);
      s.header[14] = std::byte(u8(s.header[14]) & u8(~someip_type::tp_flag));
    }
  }

  void release_pending() {
    pending_release_ = false;
    release(pending_);
  }
  result drop_new(const Key&, result& r, drop_reason why) {
    ++stats_.dropped_fragments;
    r.status = frag_status::dropped;
    r.reason = why;
    return r;
  }
  result kill_with(u32 si, result& r, drop_reason why) {
    kill(si, why);
    return drop_new(Key{}, r, why);
  }
  void kill(u32 si, drop_reason why) {
    slot& s = slots_[si];
    ++stats_.dropped_datagrams;
    if (hooks_.dropped) hooks_.dropped(hooks_.ctx, s.key, why, s.covered, s.nfrags);
    free_slot(si);
  }
  bool evict_oldest() {
    u32 best = unknown;
    for (u32 si = 0; si < slots_.size(); ++si)
      if (slots_[si].used && !slots_[si].complete && (best == unknown || slots_[si].last_seen < slots_[best].last_seen))
        best = si;
    if (best == unknown) return false;
    ++stats_.evictions;
    kill(best, drop_reason::capacity);
    return true;
  }
  void free_slot(u32 si) {
    slot& s = slots_[si];
    if (!s.complete) erase_index(si);
    if (hooks_.release)
      for (u32 i = 0; i < s.nfrags; ++i) hooks_.release(hooks_.ctx, frags_[si * cfg_.max_fragments + i].tok);
    const u16 g = s.gen;
    s = slot{};
    s.gen = g;
    free_.push_back(si);
    if (pending_release_ && pending_ == handle(si)) pending_release_ = false;
  }

  reassembly_config cfg_;
  hooks hooks_;
  std::size_t pstride_ = 0, mask_ = 0;
  std::vector<slot> slots_;
  std::vector<frag_rec> frags_;
  std::vector<std::span<const std::byte>> spans_, scratch_spans_;
  std::vector<u32> poff_, scratch_off_;
  std::vector<u32> index_;
  std::vector<u32> free_;
  reassembly_stats stats_{};
  bool pending_release_ = false;
  u32 pending_ = 0;
};

/// Materialize segments into one contiguous buffer (the only copying path). Returns bytes
/// written, or 0 when `out` is too small.
inline std::size_t copy_to(const nanom::segments& s, mut_bytes out) noexcept {
  if (out.size() < s.size()) return 0;
  std::size_t n = 0;
  for (std::size_t i = 0; i < s.parts(); ++i) {
    const auto p = s.part(i);
    if (!p.empty()) std::memcpy(out.data() + n, p.data(), p.size());
    n += p.size();
  }
  return n;
}

// ---------------------------------------------------------------------------------------------
// keys + feed helpers for IPv4, IPv6 and SOME/IP-TP
// ---------------------------------------------------------------------------------------------
namespace detail {
struct fnv {
  u64 h = 1469598103934665603ull;
  constexpr void add(u64 v, int nbytes) noexcept {
    for (int i = 0; i < nbytes; ++i) h = (h ^ ((v >> (8 * i)) & 0xff)) * 1099511628211ull;
  }
  template <std::size_t N>
  constexpr void add(const std::array<u8, N>& a) noexcept {
    for (u8 b : a) h = (h ^ b) * 1099511628211ull;
  }
};
}  // namespace detail

/// RFC 791: (src, dst, protocol, identification).
struct ipv4_frag_key {
  ipv4_addr src{}, dst{};
  u8 protocol = 0;
  u16 id = 0;
  constexpr bool operator==(const ipv4_frag_key&) const = default;
  struct hasher {
    constexpr std::size_t operator()(const ipv4_frag_key& k) const noexcept {
      detail::fnv f;
      f.add(k.src), f.add(k.dst), f.add(k.protocol, 1), f.add(k.id, 2);
      return std::size_t(f.h);
    }
  };
};
/// RFC 8200: (src, dst, identification).
struct ipv6_frag_key {
  ipv6_addr src{}, dst{};
  u32 id = 0;
  constexpr bool operator==(const ipv6_frag_key&) const = default;
  struct hasher {
    constexpr std::size_t operator()(const ipv6_frag_key& k) const noexcept {
      detail::fnv f;
      f.add(k.src), f.add(k.dst), f.add(k.id, 4);
      return std::size_t(f.h);
    }
  };
};
/// SOME/IP-TP (PRS_SOMEIP): segments of one message share the transport endpoints, Message ID,
/// Client ID, protocol / interface version and message type (TP flag cleared); the Session ID is
/// the epoch (a new session aborts an unfinished message).
struct someip_tp_key {
  std::array<u8, 16> src{}, dst{};  // IPv4 addresses occupy the first 4 bytes
  u16 src_port = 0, dst_port = 0;
  u32 message_id = 0;
  u16 client_id = 0;
  u8 protocol_version = 0, interface_version = 0, message_type = 0;
  u8 ip_version = 0;
  constexpr bool operator==(const someip_tp_key&) const = default;
  struct hasher {
    constexpr std::size_t operator()(const someip_tp_key& k) const noexcept {
      detail::fnv f;
      f.add(k.src), f.add(k.dst), f.add(k.src_port, 2), f.add(k.dst_port, 2), f.add(k.message_id, 4);
      f.add(k.client_id, 2), f.add(k.protocol_version, 1), f.add(k.interface_version, 1);
      f.add(k.message_type, 1), f.add(k.ip_version, 1);
      return std::size_t(f.h);
    }
  };
};

using ipv4_reassembler = reassembler<ipv4_frag_key>;
using ipv6_reassembler = reassembler<ipv6_frag_key>;
/// TP: part 0 of a completed message is its rebuilt 16-byte SOME/IP header (length covers the
/// whole payload, TP flag cleared), followed by the payload segments (TP headers stripped).
using someip_tp_reassembler = reassembler<someip_tp_key, someip_tp_key::hasher, 16>;

/// Defaults suited to each protocol (unit 8 for IP fragments, 16 for TP segments).
constexpr reassembly_config ip_reassembly_defaults() noexcept {
  reassembly_config c;
  c.unit = 8;
  return c;
}
constexpr reassembly_config tp_reassembly_defaults() noexcept {
  reassembly_config c;
  c.unit = 16;
  c.max_datagram = 1u << 20;
  return c;
}

/// Feed an IPv4 fragment from a parsed packet. meta = the IP protocol.
inline ipv4_reassembler::result feed(ipv4_reassembler& r, const packet& pkt, u64 now, u64 token = 0) {
  auto ip = pkt.ipv4();
  if (!ip || !pkt.is_fragment()) return {frag_status::not_fragment};
  return r.add({ip->src(), ip->dst(), ip->protocol(), ip->identification()}, now, ip->frag_offset_bytes(), ip->mf(),
               pkt.fragment_data(), token, 0, ip->protocol());
}
/// Feed an IPv6 fragment from a parsed packet. meta = the Fragment header's next header of the
/// offset-0 fragment (the protocol of the reassembled payload).
inline ipv6_reassembler::result feed(ipv6_reassembler& r, const packet& pkt, u64 now, u64 token = 0) {
  auto ip = pkt.ipv6();
  auto fh = pkt.ipv6_fragment();
  if (!ip || !fh) return {frag_status::not_fragment};
  return r.add({ip->src(), ip->dst(), fh->identification()}, now, fh->offset_bytes(), fh->more(), pkt.fragment_data(),
               token, 0, fh->next_header());
}
/// Feed a SOME/IP-TP segment (msg must be a message of `pkt`, e.g. from pkt.someip_all()).
inline someip_tp_reassembler::result feed(someip_tp_reassembler& r, const packet& pkt, const someip_view& msg, u64 now,
                                          u64 token = 0) {
  auto tp = msg.tp();
  if (!tp || msg.truncated()) return {frag_status::not_fragment};
  someip_tp_key k{};
  if (auto v4 = pkt.ipv4()) {
    const auto s = v4->src(), d = v4->dst();
    std::copy(s.begin(), s.end(), k.src.begin());
    std::copy(d.begin(), d.end(), k.dst.begin());
    k.ip_version = 4;
  } else if (auto v6 = pkt.ipv6()) {
    k.src = v6->src();
    k.dst = v6->dst();
    k.ip_version = 6;
  }
  k.src_port = pkt.src_port();
  k.dst_port = pkt.dst_port();
  k.message_id = msg.message_id();
  k.client_id = msg.client_id();
  k.protocol_version = msg.protocol_version();
  k.interface_version = msg.interface_version();
  k.message_type = msg.message_type_base();
  return r.add(k, now, tp->offset_bytes(), tp->more(), tp->segment(), token, msg.session_id(), 0, msg.header());
}

}  // namespace nanowire

#endif  // NANOWIRE_REASSEMBLY_HPP_INCLUDED
