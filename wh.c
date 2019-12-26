/*
 * Copyright (c) 2016--2019  Wu, Xingbo <wuxb45@gmail.com>
 *
 * All rights reserved. No warranty, explicit or implicit, provided.
 */
#define _GNU_SOURCE

// headers {{{
#include "lib.h"
#include <byteswap.h>
#include <stdatomic.h>
#include <assert.h>

#if defined(__x86_64__)
#include <x86intrin.h>
#elif defined(__aarch64__)
#include <arm_acle.h>
#include <arm_neon.h>
#endif

#include "wh.h"
// }}} headers

// typedef {{{
/* C11 atomic types */
typedef atomic_bool             abool;

typedef atomic_uint_least8_t    au8;
typedef atomic_uint_least16_t   au16;
typedef atomic_uint_least32_t   au32;
typedef atomic_uint_least64_t   au64;

typedef atomic_int_least8_t     as8;
typedef atomic_int_least16_t    as16;
typedef atomic_int_least32_t    as32;
typedef atomic_int_least64_t    as64;

// vector types
#if defined(__x86_64__)
typedef __m128i m128;
#elif defined(__aarch64__)
typedef uint16x8_t m128;
#endif
// }}} typedef

// crc32c {{{
#define CRC32C_SEED ((0xDEADBEEFu))
// for crc of 1 to 3 bytes
  static inline u32
crc32c_inc_123(const u8 * buf, u32 nr, u32 crc)
{
  if (nr == 1)
    return crc32c_u8(crc, buf[0]);

  crc = crc32c_u16(crc, *(u16 *)buf);
  return (nr == 2) ? crc : crc32c_u8(crc, buf[2]);
}

// for crc of 0 to 3 bytes
  static inline u32
crc32c_inc_0123(const u8 * buf, u32 nr, u32 crc)
{
  debug_assert(nr <= 3);
  return nr ? crc32c_inc_123(buf, nr, crc) : crc;
}

  static inline u32
crc32c_inc_x4(const u8 * buf, u32 nr, u32 crc)
{
  debug_assert((nr & 3) == 0);
#pragma nounroll
  while (nr >= sizeof(u64)) {
    crc = crc32c_u64(crc, *((u64*)buf));
    nr -= sizeof(u64);
    buf += sizeof(u64);
  }
  if (nr)
    crc = crc32c_u32(crc, *((u32*)buf));
  return crc;
}

  static inline u32
crc32c_inc(const u8 * buf, u32 nr, u32 crc)
{
#pragma nounroll
  while (nr >= sizeof(u64)) {
    crc = crc32c_u64(crc, *((u64*)buf));
    nr -= sizeof(u64);
    buf += sizeof(u64);
  }
  if (nr >= sizeof(u32)) {
    crc = crc32c_u32(crc, *((u32*)buf));
    nr -= sizeof(u32);
    buf += sizeof(u32);
  }
  return crc32c_inc_0123(buf, nr, crc);
}

  static inline u32
crc32c(const void * const ptr, u32 len)
{
  return crc32c_inc((const u8 *)ptr, len, CRC32C_SEED);
}

  static inline u64
crc32c_extend(const u32 lo)
{
  const u64 hi = (u64)(~lo);
  return (hi << 32) | ((u64)lo);
}
// }}} crc32c

// kv {{{
  inline size_t
kv_size(const struct kv * const kv)
{
  return sizeof(*kv) + kv->klen + kv->vlen;
}

  inline size_t
kv_size_align(const struct kv * const kv, const u64 align)
{
  debug_assert(align && ((align & (align - 1)) == 0));
  return (sizeof(*kv) + kv->klen + kv->vlen + (align - 1)) & (~(align - 1));
}

  inline size_t
key_size(const struct kv *const key)
{
  return sizeof(*key) + key->klen;
}

  inline size_t
key_size_align(const struct kv *const key, const u64 align)
{
  debug_assert(align && ((align & (align - 1)) == 0));
  return (sizeof(*key) + key->klen + (align - 1)) & (~(align - 1));
}

  inline void
kv_update_hash(struct kv * const kv)
{
  const u32 lo = crc32c((const void *)kv->kv, kv->klen);
  kv->hash = crc32c_extend(lo);
}

  inline void
kv_refill(struct kv * const kv, const void * const key, const u32 klen,
    const void * const value, const u32 vlen)
{
  debug_assert(kv);
  kv->klen = klen;
  kv->vlen = vlen;
  if (key && klen)
    memcpy(&(kv->kv[0]), key, klen);
  if (value && vlen)
    memcpy(&(kv->kv[klen]), value, vlen);
  kv_update_hash(kv);
}

  inline void
kv_refill_str_str(struct kv * const kv, const char * const key, const char * const value)
{
  kv_refill(kv, key, (u32)strlen(key), value, (u32)strlen(value));
}

  inline void
kv_refill_str_u64(struct kv * const kv, const char * const key, const u64 value)
{
  kv_refill(kv, key, (u32)strlen(key), &value, sizeof(value));
}

  inline struct kv *
kv_create(const void * const key, const u32 klen, const void * const value, const u32 vlen)
{
  struct kv * const kv = malloc(sizeof(*kv) + klen + vlen);
  if (kv)
    kv_refill(kv, key, klen, value, vlen);
  return kv;
}

  inline struct kv *
kv_create_str(const char * const key, const char * const value)
{
  return kv_create(key, (u32)strlen(key), value, (u32)strlen(value));
}

  inline struct kv *
kv_dup(const struct kv * const kv)
{
  if (kv == NULL)
    return NULL;

  const size_t sz = kv_size(kv);
  struct kv * const new = malloc(sz);
  if (new)
    memcpy(new, kv, sz);
  return new;
}

  inline struct kv *
kv_dup_key(const struct kv * const kv)
{
  if (kv == NULL)
    return NULL;

  const size_t sz = key_size(kv);
  struct kv * const new = malloc(sz);
  if (new)
    memcpy(new, kv, sz);
  return new;
}

  inline struct kv *
kv_dup2(const struct kv * const from, struct kv * const to)
{
  if (from == NULL)
    return NULL;
  const size_t sz = kv_size(from);
  struct kv * const new = to ? to : malloc(sz);
  if (new)
    memcpy(new, from, sz);
  return new;
}

  inline struct kv *
kv_dup2_key(const struct kv * const from, struct kv * const to)
{
  if (from == NULL)
    return NULL;
  const size_t sz = key_size(from);
  struct kv * const new = to ? to : malloc(sz);
  if (new) {
    memcpy(new, from, sz);
    new->vlen = 0;
  }
  return new;
}

  inline struct kv *
kv_dup2_key_prefix(const struct kv * const from, struct kv * const to, const u64 plen)
{
  if (from == NULL)
    return NULL;
  const size_t sz = key_size(from) - from->klen + plen;
  struct kv * const new = to ? to : malloc(sz);
  if (new) {
    new->klen = plen;
    memcpy(new->kv, from->kv, plen);
    new->vlen = 0;
    kv_update_hash(new);
  }
  return new;
}

  inline struct sbuf *
kv_dup2_sbuf(const struct kv * const from, struct sbuf * const to)
{
  if (from == NULL)
    return NULL;
  const size_t sz = sizeof(*to) + from->vlen;
  struct sbuf * const new = to ? to : malloc(sz);
  if (new) {
    new->len = from->vlen;
    memcpy(new->buf, from->kv + from->klen, from->vlen);
  }
  return new;
}

  struct kv *
kv_alloc_malloc(const u64 size, void * const priv)
{
  (void)priv;
  return malloc(size);
}

  void
kv_retire_free(struct kv * const kv, void * const priv)
{
  (void)priv;
  free(kv);
}

  static inline struct kv *
kv_mm_dup(const struct kv * const kv, const struct kvmap_mm * const mm)
{
  const u64 sz = kv_size(kv);
  struct kv * const new = mm->af(sz, mm->ap);
  debug_assert(new);
  memcpy(new, kv, sz);
  return new;
}

// key1 and key2 must be valid ptr
// kv: key1 is the search key; key2 is the index key that is often not in the cache;
  inline bool
kv_keymatch(const struct kv * const key1, const struct kv * const key2)
{
  //cpu_prefetchr(((u8 *)key2) + 64, 0);
  //return (key1->hash == key2->hash)
  //  && (key1->klen == key2->klen)
  //  && (!memcmp(key1->kv, key2->kv, key1->klen));
  return (key1->klen == key2->klen) && (!memcmp(key1->kv, key2->kv, key1->klen));
}

  inline bool
kv_fullmatch(const struct kv * const kv1, const struct kv * const kv2)
{
  return (kv1->kvlen == kv2->kvlen)
    && (!memcmp(kv1, kv2, sizeof(*kv1) + kv1->klen + kv1->vlen));
}

  inline int
kv_keycompare(const struct kv * const kv1, const struct kv * const kv2)
{
  debug_assert(kv1);
  debug_assert(kv2);
  const u32 len = kv1->klen < kv2->klen ? kv1->klen : kv2->klen;
  const int cmp = memcmp(kv1->kv, kv2->kv, (size_t)len);
  if (cmp != 0) {
    return cmp;
  } else {
    if (kv1->klen < kv2->klen)
      return -1;
    else if (kv1->klen > kv2->klen)
      return 1;
    else
      return 0;
  }
}

// for qsort and bsearch
  static int
kv_compare_pp(const void * const p1, const void * const p2)
{
  const struct kv ** const pp1 = (typeof(pp1))p1;
  const struct kv ** const pp2 = (typeof(pp2))p2;
  return kv_keycompare(*pp1, *pp2);
}

  int
kv_compare_vi128(const struct kv * const sk, const u8 * const vi128)
{
  const u32 klen1 = sk->klen;
  u32 klen2 = 0, vlen2 = 0;
  const u8 * const ptr2 = vi128_decode_u32(vi128_decode_u32(vi128, &klen2), &vlen2);
  const u32 len = klen1 < klen2 ? klen1 : klen2;
  const int cmp = memcmp(sk->kv, ptr2, len);
  if (cmp != 0)
    return cmp;
  else
    return ((int)klen1) - ((int)klen2);
}

  inline void
kv_qsort(const struct kv ** const kvs, const size_t nr)
{
  qsort(kvs, nr, sizeof(kvs[0]), kv_compare_pp);
}

  inline void *
kv_vptr(struct kv * const kv)
{
  return (void *)(&(kv->kv[kv->klen]));
}

  inline void *
kv_kptr(struct kv * const kv)
{
  return (void *)(&(kv->kv[0]));
}

  inline const void *
kv_vptr_c(const struct kv * const kv)
{
  return (const void *)(&(kv->kv[kv->klen]));
}

  inline const void *
kv_kptr_c(const struct kv * const kv)
{
  return (const void *)(&(kv->kv[0]));
}

// return the length of longest common prefix of the two keys
  u32
kv_key_lcp(const struct kv * const key1, const struct kv * const key2)
{
  const u32 max = (key1->klen < key2->klen) ? key1->klen : key2->klen;
  u32 clen = 0;
  const u8 * p1 = key1->kv;
  const u8 * p2 = key2->kv;

  const u32 max64 = max >> 3 << 3;
  while (clen < max64) {
    const u64 v1 = *(const u64 *)p1;
    const u64 v2 = *(const u64 *)p2;
    if (v1 != v2)
      return clen + (__builtin_ctzl(v1 ^ v2) >> 3);

    clen += sizeof(u64);
    p1 += sizeof(u64);
    p2 += sizeof(u64);
  }

  if ((clen + sizeof(u32)) <= max) {
    const u32 v1 = *(const u32 *)p1;
    const u32 v2 = *(const u32 *)p2;
    if (v1 != v2)
      return clen + (__builtin_ctz(v1 ^ v2) >> 3);

    clen += sizeof(u32);
    p1 += sizeof(u32);
    p2 += sizeof(u32);
  }

  while ((clen < max) && (*p1 == *p2)) {
    clen++;
    p1++;
    p2++;
  }
  return clen;
}

  static inline void *
u64_to_ptr(const u64 v)
{
  return (void *)v;
}

  static inline u64
ptr_to_u64(const void * const ptr)
{
  return (u64)ptr;
}

// 0 to 0xffff;
  static inline u64
kvmap_pkey(const u64 hash)
{
  const u64 pkey0 = ((hash >> 16) ^ hash) & 0xfffflu;
  return pkey0 ? pkey0 : 1;
}

  static const char *
kv_pattern(const char c)
{
  switch (c) {
  case 's': return "%c";
  case 'x': return " %02hhx";
  case 'd': return " %03hhu";
  case 'X': return " %hhx";
  case 'D': return " %hhu";
  default: return NULL;
  }
}

// cmd "KV" K and V can be 's': string, 'x': hex, 'd': dec, or else for not printing.
// X and D does not add zeros at the beginning
// n for newline after kv
  void
kv_print(const struct kv * const kv, const char * const cmd, FILE * const out)
{
  debug_assert(cmd);
  const u32 klen = kv->klen;
  fprintf(out, "#%04lx #%016lx k[%2u] ", kvmap_pkey(kv->hash), kv->hash, klen);
  const u32 klim = klen < 128 ? klen : 128;

  const char * const kpat = kv_pattern(cmd[0]);
  for (u32 i = 0; i < klim; i++)
    fprintf(out, kpat, kv->kv[i]);
  if (klim < klen)
    fprintf(out, " ...");

  const char * const vpat = kv_pattern(cmd[1]);
  if (vpat) { // may omit value
    const u32 vlen = kv->vlen;
    const u32 vlim = vlen < 128 ? vlen : 128;
    fprintf(out, "  v[%4u] ", vlen);
    for (u32 i = 0; i < vlim; i++)
      fprintf(out, vpat, kv->kv[klen + i]);
    if (vlim < vlen)
      fprintf(out, " ...");
  }
  if (strchr(cmd, 'n'))
    fprintf(out, "\n");
}

  inline size_t
kv_vi128_estimate(const struct kv * const kv)
{
  return vi128_estimate(kv->klen) + vi128_estimate(kv->vlen) + kv->klen + kv->vlen;
}

  u8 *
kv_vi128_encode(u8 * ptr, const struct kv * const kv)
{
  ptr = vi128_encode_u32(ptr, kv->klen);
  ptr = vi128_encode_u32(ptr, kv->vlen);
  memcpy(ptr, kv->kv, kv->klen + kv->vlen);
  return ptr + kv->klen + kv->vlen;
}
// }}} kv

// kvmap {{{
struct entry13 {
  union {
    struct {
      u64 e1:16;
      u64 e3:48;
    };
    u64 v64;
  };
};

static_assert(sizeof(struct entry13) == 8, "sizeof(entry13) != 8");

#define KVBUCKET_NR ((8lu))
struct kvbucket {
  struct entry13 e[KVBUCKET_NR];
};

static_assert(sizeof(struct kvbucket) == 64, "sizeof(kvbucket) != 64");

  static inline int
kvmap_entry_keycompare_vptr(const void * const p1, const void * const p2)
{
  const struct entry13 * const e1 = (typeof(e1))p1;
  const struct entry13 * const e2 = (typeof(e2))p2;
  const struct kv * const k1 = u64_to_ptr(e1->e3);
  const struct kv * const k2 = u64_to_ptr(e2->e3);
  return kv_keycompare(k1, k2);
}

  static inline void
kvmap_entry_qsort(struct entry13 * const es, const u64 nr)
{
  qsort(es, nr, sizeof(es[0]), kvmap_entry_keycompare_vptr);
}

// mm
  static inline void
kvmap_put_entry(struct kvmap_mm * const mm, struct entry13 * const e, const struct kv * const kv)
{
  struct kv * const old = u64_to_ptr(e->e3);
  if (old && mm->rf)
    mm->rf(old, mm->rp);
  if (kv) {
    e->e3 = ptr_to_u64(kv);
    e->e1 = kvmap_pkey(kv->hash);
  } else {
    e->v64 = 0;
  }
}

static const struct kvmap_mm kvmap_mm_default = {
  .af = kv_alloc_malloc,
  .ap = NULL,
  .rf = kv_retire_free,
  .rp = NULL,
};
// }}} kvmap

// wormhole {{{

// def {{{
#define WH_HMAPINIT_SIZE ((1lu << 12)) // 10: 16KB/64KB  12: 64KB/256KB  14: 256KB/1MB
#define WH_SLABMETA_SIZE ((1lu << 21)) // 2MB

#ifndef HEAPCHECKING
#define WH_SLABLEAF_SIZE ((1lu << 21)) // 2MB is ok
#else
#define WH_SLABLEAF_SIZE ((1lu << 21)) // 2MB for valgrind
#endif

#define WH_KPN ((128u)) // keys per node; power of 2
#define WH_HDIV (((1u << 16)) / WH_KPN)
#define WH_MID ((WH_KPN >> 1)) // ideal cut point for split, the closer the better

#define WH_KPN_MRG (((WH_KPN + WH_MID) >> 1 )) // 3/4

// FO is fixed at 256. Don't change it
#define WH_FO  ((256)) // index fan-out
// number of bits in a bitmap
#define WH_BMNR ((WH_FO >> 6)) // number of u64
// }}} def

// struct {{{
struct wormmeta {
  u32 hash32;
  u16 bitmin;
  u16 klen; // we don't expect any 65536-byte meta-key
  struct kv * keyref;
  struct wormleaf * lmost;
  struct wormleaf * rmost;
  u64 bitmap[WH_BMNR];
};
static_assert(sizeof(struct wormmeta) == 64, "sizeof(wormmeta) != 64");

struct wormleaf {
  // first line
  struct wormleaf * prev; // prev leaf
  struct wormleaf * next; // next leaf
  struct kv * anchor;
  u64 nr_sorted;
  u64 nr_keys;
  volatile u64 version;
  u32 klen; // a duplicate of anchor->klen;
  u32 padding;
  rwlock leaflock;
  struct entry13 eh[WH_KPN]; // sorted by hashes
  struct entry13 es[WH_KPN]; // sorted by keys
};

struct wormslot {
  u16 t[KVBUCKET_NR];
};

struct wormmbkt {
  struct wormmeta * e[KVBUCKET_NR];
};

static_assert(sizeof(struct wormslot) == 16, "sizeof(wormslot) != 16");

struct wormhmap {
  u64 version;
  struct wormslot * wmap;
  u32 mask;
  u32 padding1;
  struct wormmbkt * pmap;

  u32 maxplen;
  u32 hmap_id; // 0 or 1
  u64 msize;
  struct slab * slab;
  u64 padding;
};
static_assert(sizeof(struct wormhmap) == 64, "sizeof(wormhmap) != 64");

struct wormhole {
  // 1 line
  struct wormhmap * volatile hmap;
  u64 padding0[6];
  struct wormleaf * leaf0; // usually not used
  // 1 line
  struct kvmap_mm mm;
  struct qsbr * qsbr;
  struct slab * slab_leaf;
  u64 padding1[2];
  // 2 lines
  struct wormhmap hmap2[2];
  // fifth line
  rwlock metalock;
  u64 padding2[7];
};

struct wormhole_iter {
  union {
    struct wormref * ref; // for safe iter
    struct wormhole * map; // for unsafe iter
  };
  struct wormleaf * leaf;
  u32 next_id;
};

struct wormkref { // reference to a key
  u32 hashlo; // little endian
  u32 plen; // prefix length; plen <= klen
  const u8 * key;
};

struct wormref {
  struct wormhole * map;
  volatile u64 qstate;
};
// }}} struct

// helpers {{{

// key/prefix {{{
  static inline u16
wormhole_pkey(const u32 hash32)
{
  const u32 pkey0 = ((u16)hash32) ^ ((u16)(hash32 >> 16));
  return pkey0 ? pkey0 : 1;
}

  static inline u32
wormhole_bswap(const u32 hashlo)
{
  return bswap_32(hashlo);
}

  static inline bool
wormhole_key_meta_match(const struct kv * const key, const struct wormmeta * const meta)
{
  return (key->hashlo == meta->hash32)
    && (key->klen == meta->klen)
    && (!memcmp(key->kv, meta->keyref->kv, key->klen));
}

// called by get_kref_slot
  static inline bool
wormhole_kref_meta_match(const struct wormkref * const kref,
    const struct wormmeta * const meta)
{
  cpu_prefetchr(meta->lmost, 0);
  return (kref->plen == meta->klen)
    && (!memcmp(kref->key, meta->keyref->kv, kref->plen));
}

// called from get_kref1_slot
  static inline bool
wormhole_kref1_meta_match(const struct wormkref * const kref,
    const struct wormmeta * const meta, const u8 cid)
{
  const struct kv * const mkey = meta->keyref;
  cpu_prefetchr(meta->rmost, 0);
  const u32 plen = kref->plen;
  return ((plen + 1) == meta->klen)
    && (!memcmp(kref->key, mkey->kv, plen))
    && (mkey->kv[plen] == cid);
}

// warning: be careful with buffer overflow
  static inline void
wormhole_prefix(struct kv * const pfx, const u32 klen)
{
  pfx->klen = klen;
  kv_update_hash(pfx);
}

// for split
  static inline void
wormhole_prefix_inc1(struct kv * const pfx)
{
  pfx->hashlo = crc32c_u8(pfx->hashlo, pfx->kv[pfx->klen]);
  pfx->klen++;
}

// for split
  static inline void
wormhole_prefix_inc(struct kv * const pfx, const u32 klen)
{
  debug_assert(klen >= pfx->klen);
  pfx->hashlo = crc32c_inc(pfx->kv + pfx->klen, klen - pfx->klen, pfx->hashlo);
  pfx->klen = klen;
}

// meta_lcp only
  static inline void
wormhole_kref_inc(struct wormkref * const kref, const u32 len0,
    const u32 crc, const u32 inc)
{
  kref->hashlo = crc32c_inc(kref->key + len0, inc, crc);
  kref->plen = len0 + inc;
}

// meta_lcp only
  static inline void
wormhole_kref_inc_123(struct wormkref * const kref, const u32 len0,
    const u32 crc, const u32 inc)
{
  kref->hashlo = crc32c_inc_123(kref->key + len0, inc, crc);
  kref->plen = len0 + inc;
}
// }}} key/prefix

// alloc {{{
  static inline struct kv *
wormhole_alloc_akey(const size_t klen)
{
#ifdef ALLOCFAIL
  if (alloc_fail())
    return NULL;
#endif
  return malloc(sizeof(struct kv) + klen);
}

  static inline void
wormhole_free_akey(struct kv * const akey)
{
  free(akey);
}

  static inline struct kv *
wormhole_alloc_mkey(const size_t klen)
{
#ifdef ALLOCFAIL
  if (alloc_fail())
    return NULL;
#endif
  return malloc(sizeof(struct kv) + klen);
}

  static struct kv *
wormhole_alloc_mkey_extend(struct kv * const kv, const u32 klen)
{
  struct kv * const mkey = wormhole_alloc_mkey(klen);
  if (mkey == NULL)
    return NULL;
  kv_dup2_key(kv, mkey);
  if (klen > mkey->klen) {
    memset(&(mkey->kv[mkey->klen]), 0, klen - mkey->klen);
    wormhole_prefix_inc(mkey, klen);
  }
  return mkey;
}

  static inline void
wormhole_free_mkey(struct kv * const mkey)
{
  free(mkey);
}

  static inline struct wormleaf *
wormhole_alloc_leaf(struct wormhole * const map, struct wormleaf * const prev,
    struct wormleaf * const next, struct kv * const anchor)
{
  struct wormleaf * const leaf = slab_alloc(map->slab_leaf);
  if (leaf == NULL)
    return NULL;
  rwlock_init(&(leaf->leaflock));
  leaf->version = 0;
  leaf->anchor = anchor;
  if (anchor)
    leaf->klen = anchor->klen;
  leaf->nr_sorted = 0;
  leaf->nr_keys = 0;
  leaf->prev = prev;
  leaf->next = next;
  // eh required zero init.
  memset(leaf->eh, 0, sizeof(leaf->eh[0]) * WH_KPN);
  return leaf;
}

  static inline struct wormmeta *
wormhole_alloc_meta(struct slab * const slab, struct wormleaf * const lrmost,
    struct kv * const keyref, const u32 hash32, const u32 klen)
{
  struct wormmeta * const meta = slab_alloc_unsafe(slab);
  if (meta == NULL)
    return NULL;
  keyref->refcnt++;
  meta->hash32 = hash32;
  debug_assert(klen < (1lu << 16));
  meta->klen = klen;
  meta->keyref = keyref;
  meta->bitmin = WH_FO; // WH_FO implies bitcount == 0
  meta->lmost = lrmost;
  meta->rmost = lrmost;
  for (u64 i = 0; i < WH_BMNR; i++)
    meta->bitmap[i] = 0;
  return meta;
}

  static inline bool
wormhole_slab_reserve(struct slab * const slab, const u32 nr)
{
#ifdef ALLOCFAIL
  if (alloc_fail())
    return false;
#endif
  return slab ? slab_reserve_unsafe(slab, nr) : true;
}

  static inline void
wormhole_free_meta(struct slab * const slab, struct wormmeta * const meta)
{
  struct kv * const keyref = meta->keyref;
  debug_assert(keyref->refcnt);
  keyref->refcnt--;
  if (keyref->refcnt == 0)
    wormhole_free_mkey(keyref);
  slab_free_unsafe(slab, meta);
}
// }}} alloc

// meta/bitmap {{{
  static inline bool
wormhole_meta_bm_test(const struct wormmeta * const meta, const u32 id)
{
  return (bool)((meta->bitmap[id >> 6] >> (id & 0x3fu)) & 1lu);
}

  static inline void
wormhole_meta_bm_set(struct wormmeta * const meta, const u32 id)
{
  meta->bitmap[id >> 6u] |= (1lu << (id & 0x3fu));
  if (id < meta->bitmin)
    meta->bitmin = id;
}

  static inline u32
wormhole_meta_bm_gt(const struct wormmeta * const meta, const u32 id0)
{
  if ((id0 & 0x3fu) != 0x3fu) { // not at bit 63
    const u32 id = id0 + 1u;
    const u64 bits = meta->bitmap[id >> 6] >> (id & 0x3fu);
    if (bits)
      return id + (u32)__builtin_ctzl(bits);
  }
  for (u32 ix = (id0 >> 6) + 1; ix < 4; ix++)
    if (meta->bitmap[ix])
      return (ix << 6) + (u32)(__builtin_ctzl(meta->bitmap[ix]));

  return WH_FO;
}

  static inline void
wormhole_meta_bm_clear(struct wormmeta * const meta, const u32 id)
{
  meta->bitmap[id >> 6u] &= (~(1lu << (id & 0x3fu)));
  if (id == meta->bitmin) {
    meta->bitmin = wormhole_meta_bm_gt(meta, id);
    debug_assert(meta->bitmin > id);
  }
}

// find the highest bit that is lower than the id0
// return id0 if not found
  static inline u32
wormhole_meta_bm_lt(const struct wormmeta * const meta, const u32 id0)
{
  if (id0 & 0x3fu) { // not at 0
    const u32 id = id0 - 1u;
    const u64 bits = meta->bitmap[id >> 6] << (63u - (id & 0x3fu));
    if (bits)
      return id - (u32)__builtin_clzl(bits);
  }
  for (u32 ixp = id0 >> 6; ixp; ixp--)
    if (meta->bitmap[ixp-1u])
      return (ixp << 6) - 1u - (u32)(__builtin_clzl(meta->bitmap[ixp-1u]));

  return id0;
}
// }}} meta/bitmap

// }}} helpers

// hmap {{{

// hmap is the MetaTrieHT of Wormhole

  static bool
wormhole_hmap_init(struct wormhmap * const hmap, const u64 i)
{
  hmap->slab = slab_create(sizeof(struct wormmeta), WH_SLABMETA_SIZE);
  if (hmap->slab == NULL)
    return false;
  const u64 nr = WH_HMAPINIT_SIZE;
  const u64 wsize = sizeof(hmap->wmap[0]) * nr;
  const u64 psize = sizeof(hmap->pmap[0]) * nr;
  u64 msize = wsize + psize;
  u8 * const mem = pages_alloc_best(msize, true, &msize);
  if (mem == NULL) {
    slab_destroy(hmap->slab);
    hmap->slab = NULL;
    return false;
  }
  hmap->pmap = (typeof(hmap->pmap))mem;
  hmap->wmap = (typeof(hmap->wmap))(mem + psize);
  hmap->msize = msize;
  hmap->mask = nr - 1;
  hmap->version = 0;
  hmap->maxplen = 0;
  hmap->hmap_id = i;
  return true;
}

  static inline void
wormhole_hmap_deinit(struct wormhmap * const hmap)
{
  if (hmap->slab) {
    slab_destroy(hmap->slab);
    hmap->slab = NULL;
  }
  if (hmap->pmap) {
    pages_unmap(hmap->pmap, hmap->msize);
    hmap->pmap = NULL;
    hmap->wmap = NULL;
  }
}

  static inline m128
wormhole_hmap_m128_pkey(const u16 pkey)
{
#if defined(__x86_64__)
  return _mm_set1_epi16(pkey);
#elif defined(__aarch64__)
  return vdupq_n_u16(pkey);
#endif
}

  static inline u32
wormhole_hmap_match_mask(const struct wormslot * const s, const m128 skey)
{
#if defined(__x86_64__)
  const m128 sv = _mm_load_si128((const void *)s);
  return (u32)_mm_movemask_epi8(_mm_cmpeq_epi16(skey, sv));
#elif defined(__aarch64__)
  const m128 sv = vld1q_u16((const u16 *)s);
  const m128 cmp = vceqq_u16(skey, sv); // cmpeq
  const uint32x4_t sr2 = vreinterpretq_u32_u16(vshrq_n_u16(cmp, 14)); // 2-bit x 8
  const uint64x2_t sr4 = vreinterpretq_u64_u32(vsraq_n_u32(sr2, sr2, 14)); // 4-bit x 4
  const m128 sr8 = vreinterpretq_u16_u64(vsraq_n_u64(sr4, sr4, 28)); // 8-bit x 2
  const u32 r = vgetq_lane_u16(sr8, 0) | (vgetq_lane_u16(sr8, 4) << 8);
  return r;
#endif
}

  static inline bool
wormhole_hmap_match_any(const struct wormslot * const s, const m128 skey)
{
#if defined(__x86_64__)
  //return wormhole_hmap_match_mask(s, skey);
  const m128 sv = _mm_load_si128((const void *)s);
  const m128 cmp = _mm_cmpeq_epi16(skey, sv);
  return !_mm_test_all_zeros(cmp, cmp);
#elif defined(__aarch64__)
  const m128 sv = vld1q_u16((const u16 *)s);
  const m128 cmp = vceqq_u16(skey, sv); // cmpeq
  return vmaxvq_u32(vreinterpretq_u32_u16(cmp)) != 0;
#endif
}

  static inline m128
wormhole_hmap_zero(void)
{
#if defined(__x86_64__)
  return _mm_setzero_si128();
#elif defined(__aarch64__)
  return vdupq_n_u16(0);
#endif
}

// meta_lcp only
  static inline bool
wormhole_hmap_peek(const struct wormhmap * const hmap, const u32 hash32)
{
  const m128 sk = wormhole_hmap_m128_pkey(wormhole_pkey(hash32));
  const u32 midx = hash32 & hmap->mask;
  const u32 midy = wormhole_bswap(hash32) & hmap->mask;
  return wormhole_hmap_match_any(&(hmap->wmap[midx]), sk)
    || wormhole_hmap_match_any(&(hmap->wmap[midy]), sk);
}

  static inline struct wormmeta *
wormhole_hmap_get_slot(const struct wormhmap * const hmap, const u32 mid, const m128 skey,
    const struct kv * const key)
{
  u32 mask = wormhole_hmap_match_mask(&(hmap->wmap[mid]), skey);
  while (mask) {
    const u32 i2 = __builtin_ctz(mask);
    struct wormmeta * const meta = hmap->pmap[mid].e[i2>>1];
    if (wormhole_key_meta_match(key, meta))
      return meta;
    mask ^= (3u << i2);
  }
  return NULL;
}

  static inline struct wormmeta *
wormhole_hmap_get(const struct wormhmap * const hmap, const struct kv * const key)
{
  const u32 hash32 = key->hashlo;
  const u32 midx = hash32 & hmap->mask;
  cpu_prefetchr(&(hmap->pmap[midx]), 0);
  const u32 midy = wormhole_bswap(hash32) & hmap->mask;
  cpu_prefetchr(&(hmap->pmap[midy]), 0);
  const m128 skey = wormhole_hmap_m128_pkey(wormhole_pkey(hash32));

  struct wormmeta * const r = wormhole_hmap_get_slot(hmap, midx, skey, key);
  if (r)
    return r;
  return wormhole_hmap_get_slot(hmap, midy, skey, key);
}

// for meta_lcp only
  static inline struct wormmeta *
wormhole_hmap_get_kref_slot(const struct wormhmap * const hmap, const u32 mid, const m128 skey,
    const struct wormkref * const kref)
{
  u32 mask = wormhole_hmap_match_mask(&(hmap->wmap[mid]), skey);
  while (mask) {
    const u32 i2 = __builtin_ctz(mask);
    struct wormmeta * const meta = hmap->pmap[mid].e[i2>>1];
    if (wormhole_kref_meta_match(kref, meta))
      return meta;

    mask ^= (3u << i2);
  }
  return NULL;
}

// for meta_lcp only
  static inline struct wormmeta *
wormhole_hmap_get_kref(const struct wormhmap * const hmap, const struct wormkref * const kref)
{
  const u32 hash32 = kref->hashlo;
  const u32 midx = hash32 & hmap->mask;
  cpu_prefetchr(&(hmap->pmap[midx]), 0);
  const u32 midy = wormhole_bswap(hash32) & hmap->mask;
  cpu_prefetchr(&(hmap->pmap[midy]), 0);
  const m128 skey = wormhole_hmap_m128_pkey(wormhole_pkey(hash32));

  struct wormmeta * const r = wormhole_hmap_get_kref_slot(hmap, midx, skey, kref);
  if (r)
    return r;
  return wormhole_hmap_get_kref_slot(hmap, midy, skey, kref);
}

// for meta_down only
  static inline struct wormmeta *
wormhole_hmap_get_kref1_slot(const struct wormhmap * const hmap, const u32 mid,
    const m128 skey, const struct wormkref * const kref, const u8 cid)
{
  u32 mask = wormhole_hmap_match_mask(&(hmap->wmap[mid]), skey);
  while (mask) {
    const u32 i2 = __builtin_ctz(mask);
    struct wormmeta * const meta = hmap->pmap[mid].e[i2>>1];
    if (wormhole_kref1_meta_match(kref, meta, cid))
      return meta;

    mask ^= (3u << i2);
  }
  return NULL;
}

// for meta_down only
  static inline struct wormmeta *
wormhole_hmap_get_kref1(const struct wormhmap * const hmap, const struct wormkref * const kref,
    const u8 cid)
{
  const u32 hash32 = crc32c_u8(kref->hashlo, cid);
  const u32 midx = hash32 & hmap->mask;
  cpu_prefetchr(&(hmap->pmap[midx]), 0);
  const u32 midy = wormhole_bswap(hash32) & hmap->mask;
  cpu_prefetchr(&(hmap->pmap[midy]), 0);
  const m128 skey = wormhole_hmap_m128_pkey(wormhole_pkey(hash32));

  struct wormmeta * const r = wormhole_hmap_get_kref1_slot(hmap, midx, skey, kref, cid);
  if (r)
    return r;
  return wormhole_hmap_get_kref1_slot(hmap, midy, skey, kref, cid);
}

  static inline u64
wormhole_hmap_slot_count(const struct wormslot * const slot)
{
  const u32 mask = wormhole_hmap_match_mask(slot, wormhole_hmap_zero());
  return mask ? (__builtin_ctz(mask) >> 1) : 8;
}

  static inline void
wormhole_hmap_squeeze(const struct wormhmap * const hmap)
{
  const u64 nrs = ((u64)(hmap->mask)) + 1;
  struct wormslot * const wmap = hmap->wmap;
  struct wormmbkt * const pmap = hmap->pmap;
  const u32 mask = hmap->mask;
  for (u64 si = 0; si < nrs; si++) { // # of buckets
    u64 ci = wormhole_hmap_slot_count(&(wmap[si]));
    for (u64 ei = ci - 1; ei < KVBUCKET_NR; ei--) {
      struct wormmeta * const meta = pmap[si].e[ei];
      const u64 sj = meta->hash32 & mask; // first hash
      if (sj == si)
        continue;

      // move
      const u64 ej = wormhole_hmap_slot_count(&(wmap[sj]));
      if (ej < KVBUCKET_NR) { // has space at home location
        wmap[sj].t[ej] = wmap[si].t[ei];
        pmap[sj].e[ej] = pmap[si].e[ei];
        const u64 ni = ci-1;
        if (ei < ni) {
          wmap[si].t[ei] = wmap[si].t[ni];
          pmap[si].e[ei] = pmap[si].e[ni];
        }
        wmap[si].t[ni] = 0;
        pmap[si].e[ni] = NULL;
        ci--;
      }
    }
  }
}

  static inline void
wormhole_hmap_expand(struct wormhmap * const hmap)
{
  // sync expand
  const u32 mask0 = hmap->mask;
  debug_assert(mask0 < UINT32_MAX);
  const u32 nr0 = mask0 + 1;
  const u32 mask1 = mask0 + nr0;
  debug_assert(mask1 <= UINT32_MAX);
  const u64 nr1 = ((u64)nr0) << 1;
  const u64 wsize = nr1 * sizeof(hmap->wmap[0]);
  const u64 psize = nr1 * sizeof(hmap->pmap[0]);
  u64 msize = wsize + psize;
  u8 * mem = pages_alloc_best(msize, true, &msize);
  if (mem == NULL) {
    // We are at a very deep call stack from wormhole_set().
    // Gracefully handling the failure requires lots of changes.
    // Currently we simply wait for available memory
    // TODO: gracefully return with insertion failure
    char ts[64];
    time_stamp(ts, 64);
    fprintf(stderr, "%s %s sleep-wait for memory allocation %lukB\n",
        __func__, ts, msize >> 10);
    do {
      sleep(1);
      mem = pages_alloc_best(msize, true, &msize);
    } while (mem == NULL);
    time_stamp(ts, 64);
    fprintf(stderr, "%s %s memory allocation done\n", __func__, ts);
  }

  struct wormhmap hmap1 = *hmap;
  hmap1.pmap = (typeof(hmap1.pmap))mem;
  hmap1.wmap = (typeof(hmap1.wmap))(mem + psize);
  hmap1.msize = msize;
  hmap1.mask = mask1;

  const struct wormslot * const wmap0 = hmap->wmap;
  const struct wormmbkt * const pmap0 = hmap->pmap;

  for (u64 s = 0; s < nr0; s++) {
    const struct wormmbkt * const bkt = &pmap0[s];
    for (u64 i = 0; (i < KVBUCKET_NR) && bkt->e[i]; i++) {
      const struct wormmeta * const meta = bkt->e[i];
      const u32 hash32 = meta->hash32;
      const u32 idx0 = hash32 & mask0;
      const u32 idx1 = ((idx0 == s) ? hash32 : wormhole_bswap(hash32)) & mask1;

      const u64 n = wormhole_hmap_slot_count(&(hmap1.wmap[idx1]));
      debug_assert(n < 8);
      hmap1.wmap[idx1].t[n] = wmap0[s].t[i];
      hmap1.pmap[idx1].e[n] = bkt->e[i];
    }
  }
  pages_unmap(hmap->pmap, hmap->msize);
  hmap->pmap = hmap1.pmap;
  hmap->wmap = hmap1.wmap;
  hmap->msize = hmap1.msize;
  hmap->mask = hmap1.mask;
  wormhole_hmap_squeeze(hmap);
}

  static inline bool
wormhole_hmap_cuckoo(struct wormhmap * const hmap, const u32 mid0,
    struct wormmeta * const e0, const u16 s0, const u64 depth)
{
  const u64 ii = wormhole_hmap_slot_count(&(hmap->wmap[mid0]));
  if (ii < KVBUCKET_NR) {
    hmap->wmap[mid0].t[ii] = s0;
    hmap->pmap[mid0].e[ii] = e0;
    return true;
  } else if (depth == 0) {
    return false;
  }

  // depth > 0
  struct wormmbkt * const bkt = &(hmap->pmap[mid0]);
  u16 * const sv = &(hmap->wmap[mid0].t[0]);
  for (u64 i = 0; (i < KVBUCKET_NR) && bkt->e[i]; i++) {
    const struct wormmeta * const meta = bkt->e[i];
    const u32 hash32 = meta->hash32;

    const u32 midx = hash32 & hmap->mask;
    const u32 midy = wormhole_bswap(hash32) & hmap->mask;
    const u32 midt = (midx != mid0) ? midx : midy;
    if (midt != mid0) { // possible
      // no penalty if moving someone back to its 1st hash location
      const u64 depth1 = (midt == midx) ? depth : (depth - 1);
      if (wormhole_hmap_cuckoo(hmap, midt, bkt->e[i], sv[i], depth1)) {
        bkt->e[i] = e0;
        sv[i] = s0;
        return true;
      }
    }
  }
  return false;
}

  static void
wormhole_hmap_set(struct wormhmap * const hmap, struct wormmeta * const meta)
{
  const u32 hash32 = meta->hash32;
  const u32 midx = hash32 & hmap->mask;
  cpu_prefetchr(&(hmap->pmap[midx]), 0);
  const u32 midy = wormhole_bswap(hash32) & hmap->mask;
  cpu_prefetchr(&(hmap->pmap[midy]), 0);
  const u32 pkey = wormhole_pkey(hash32);
  // insert with cuckoo
  if (wormhole_hmap_cuckoo(hmap, midx, meta, pkey, 1))
    return;
  if (wormhole_hmap_cuckoo(hmap, midy, meta, pkey, 1))
    return;
  if (wormhole_hmap_cuckoo(hmap, midx, meta, pkey, 2))
    return;

  // expand
  wormhole_hmap_expand(hmap);

  wormhole_hmap_set(hmap, meta);
}

  static bool
wormhole_hmap_del_slot(struct wormhmap * const hmap, const u32 mid,
    const struct kv * const key, const m128 skey)
{
  u32 mask = wormhole_hmap_match_mask(&(hmap->wmap[mid]), skey);
  while (mask) {
    const u32 i2 = __builtin_ctz(mask);
    const struct wormmeta * const meta = hmap->pmap[mid].e[i2>>1];
    if (wormhole_key_meta_match(key, meta)) {
      const u32 i = i2 >> 1;
      const u64 j = wormhole_hmap_slot_count(&(hmap->wmap[mid])) - 1;
      hmap->wmap[mid].t[i] = hmap->wmap[mid].t[j];
      hmap->wmap[mid].t[j] = 0;
      hmap->pmap[mid].e[i] = hmap->pmap[mid].e[j];
      hmap->pmap[mid].e[j] = NULL;
      return true;
    }
    mask -= (3u << i2);
  }
  return false;
}

  static bool
wormhole_hmap_del(struct wormhmap * const hmap, const struct kv * const key)
{
  const u32 hash32 = key->hashlo;
  const u32 midx = hash32 & hmap->mask;
  cpu_prefetchr(&(hmap->pmap[midx]), 0);
  const u32 midy = wormhole_bswap(hash32) & hmap->mask;
  cpu_prefetchr(&(hmap->pmap[midy]), 0);
  const m128 skey = wormhole_hmap_m128_pkey(wormhole_pkey(hash32));
  return wormhole_hmap_del_slot(hmap, midx, key, skey)
    || wormhole_hmap_del_slot(hmap, midy, key, skey);
}
// }}} hmap

// create {{{
// it's unsafe
  static bool
wormhole_create_leaf0(struct wormhole * const map)
{
  const bool sr1 = wormhole_slab_reserve(map->hmap2[0].slab, 1);
  const bool sr2 = wormhole_slab_reserve(map->hmap2[1].slab, 1);
  if (!(sr1 && sr2))
    return false;

  // create leaf of empty key
  struct kv * const anchor = wormhole_alloc_akey(0);
  if (anchor == NULL)
    return false;
  kv_refill(anchor, NULL, 0, NULL, 0);

  struct wormleaf * const leaf0 = wormhole_alloc_leaf(map, NULL, NULL, anchor);
  if (leaf0 == NULL) {
    wormhole_free_akey(anchor);
    return false;
  }

  struct kv * const mkey = wormhole_alloc_mkey(8);
  if (mkey == NULL) {
    slab_free(map->slab_leaf, leaf0);
    wormhole_free_akey(anchor);
    return false;
  }

  memset(mkey, 0, sizeof(*mkey) + 8);
  wormhole_prefix(mkey, 8);
  const u32 hash32 = CRC32C_SEED;
  // create meta of empty key
  for (u64 i = 0; i < 2; i++) {
    if (map->hmap2[i].slab) {
      struct wormmeta * const m0 = wormhole_alloc_meta(map->hmap2[i].slab, leaf0, mkey, hash32, 0);
      debug_assert(m0); // already reserved enough
      wormhole_hmap_set(&(map->hmap2[i]), m0);
    }
  }

  map->leaf0 = leaf0;
  return true;
}

  struct wormhole *
wormhole_create_internal(const struct kvmap_mm * const mm, const bool hmapx2)
{
  struct wormhole * const map = yalloc(sizeof(*map));
  if (map == NULL)
    return NULL;
  memset(map, 0, sizeof(*map));
  // mm
  map->mm = mm ? (*mm) : kvmap_mm_default;

  // hmap
  if (wormhole_hmap_init(&(map->hmap2[0]), 0) == false)
    goto fail_hmap_0;

  if (hmapx2)
    if (wormhole_hmap_init(&(map->hmap2[1]), 1) == false)
      goto fail_hmap_1;

  // slabs
  map->slab_leaf = slab_create(sizeof(struct wormleaf), WH_SLABLEAF_SIZE);
  if (map->slab_leaf == NULL)
    goto fail_lslab;

  // qsbr
  map->qsbr = qsbr_create();
  if (map->qsbr == NULL)
    goto fail_qsbr;

  // leaf0
  if (wormhole_create_leaf0(map) == false)
    goto fail_leaf0;

  rwlock_init(&(map->metalock));
  map->hmap = &(map->hmap2[0]);
  return map;

fail_leaf0:
  qsbr_destroy(map->qsbr);
fail_qsbr:
  slab_destroy(map->slab_leaf);
fail_lslab:
  wormhole_hmap_deinit(&(map->hmap2[1]));
fail_hmap_1:
  wormhole_hmap_deinit(&(map->hmap2[0]));
fail_hmap_0:
  free(map);
  return NULL;
}

  struct wormhole *
wormhole_create(const struct kvmap_mm * const mm)
{
  return wormhole_create_internal(mm, true);
}

  struct wormhole *
whunsafe_create(const struct kvmap_mm * const mm)
{
  return wormhole_create_internal(mm, false);
}
// }}} create

// jump {{{
// search in the hash table for the Longest Prefix Match of the search key
// The corresponding wormmeta node is returned and the LPM is recorded in kref
  static inline struct wormmeta *
wormhole_meta_lcp(const struct wormhmap * const hmap, struct wormkref * const kref)
{
  // invariant: lo <= lcp < (lo + gd)
  // ending condition: gd == 1
  u32 gd = (hmap->maxplen < kref->plen ? hmap->maxplen : kref->plen) + 1u;
  u32 lo = 0;
  u32 loh = CRC32C_SEED;

#define META_LCP_GAP_1 ((7u))
  while (META_LCP_GAP_1 < gd) {
    const u32 inc = gd >> 3 << 2; // x4
    const u32 hash32 = crc32c_inc_x4(kref->key + lo, inc, loh);
    if (wormhole_hmap_peek(hmap, hash32)) {
      loh = hash32;
      lo += inc;
      gd -= inc;
    } else {
      gd = inc;
    }
  }

  while (1 < gd) {
    const u32 inc = gd >> 1;
    const u32 hash32 = crc32c_inc_123(kref->key + lo, inc, loh);
    if (wormhole_hmap_peek(hmap, hash32)) {
      loh = hash32;
      lo += inc;
      gd -= inc;
    } else {
      gd = inc;
    }
  }
#undef META_LCP_GAP_1

  kref->hashlo = loh;
  kref->plen = lo;
  struct wormmeta * ret = wormhole_hmap_get_kref(hmap, kref);
  if (ret)
    return ret;

  gd = lo;
  lo = 0;
  loh = CRC32C_SEED;

#define META_LCP_GAP_2 ((5u))
  while (META_LCP_GAP_2 < gd) {
    const u32 inc = (gd * 3) >> 2;
    wormhole_kref_inc(kref, lo, loh, inc);
    struct wormmeta * const tmp = wormhole_hmap_get_kref(hmap, kref);
    if (tmp) {
      loh = kref->hashlo;
      lo += inc;
      gd -= inc;
      ret = tmp;
      if (wormhole_meta_bm_test(tmp, kref->key[lo])) {
        loh = crc32c_u8(loh, kref->key[lo]);
        lo++;
        gd--;
        ret = NULL;
      } else {
        gd = 1;
        break;
      }
    } else {
      gd = inc;
    }
  }

  while (1 < gd) {
    const u32 inc = (gd * 3) >> 2;
    wormhole_kref_inc_123(kref, lo, loh, inc);
    struct wormmeta * const tmp = wormhole_hmap_get_kref(hmap, kref);
    if (tmp) {
      loh = kref->hashlo;
      lo += inc;
      gd -= inc;
      ret = tmp;
      if (wormhole_meta_bm_test(tmp, kref->key[lo])) {
        loh = crc32c_u8(loh, kref->key[lo]);
        lo++;
        gd--;
        ret = NULL;
      } else {
        gd = 1;
        break;
      }
    } else {
      gd = inc;
    }
  }
#undef META_LCP_GAP_2

  if (kref->plen != lo) {
    kref->hashlo = loh;
    kref->plen = lo;
  }
  if (ret == NULL)
    ret = wormhole_hmap_get_kref(hmap, kref);
  debug_assert(ret);
  return ret;
}

  static inline struct wormleaf *
wormhole_meta_down(const struct wormhmap * const hmap, const struct wormkref * const kref,
    const struct wormmeta * const meta, const u32 klen)
{
  struct wormleaf * ret;
  if (kref->plen < klen) { // partial match
    const u32 id0 = kref->key[kref->plen];
    debug_assert(meta->bitmin != id0);
    if (meta->bitmin > id0) { // no left-sibling
      ret = meta->lmost;
      if (meta->bitmin < WH_FO) { // has right-sibling
        ret = ret->prev;
        cpu_prefetchr(ret, 0);
      } // otherwise, meta is a leaf node
    } else { // meta->bitmin < id0; has left-sibling
      const u32 id1 = wormhole_meta_bm_lt(meta, id0);
      const struct wormmeta * const child = wormhole_hmap_get_kref1(hmap, kref, id1);
      ret = child->rmost;
    }
  } else { // plen == klen
    debug_assert(kref->plen == klen);
    ret = meta->lmost;
    if (ret->klen > kref->plen) {
      ret = ret->prev;
      cpu_prefetchr(ret, 0);
    }
  }
  return ret;
}

  static struct wormleaf *
wormhole_jump_leaf(const struct wormhmap * const hmap, const struct kv * const key)
{
  struct wormkref kref = {.hashlo = key->hashlo, .plen = key->klen, .key = key->kv};

  const struct wormmeta * const meta = wormhole_meta_lcp(hmap, &kref);
  struct wormleaf * const leaf = wormhole_meta_down(hmap, &kref, meta, key->klen);
  const u64 i = wormhole_pkey(key->hashlo) / WH_HDIV;
  cpu_prefetchr(&(leaf->eh[i]), 0);
  return leaf;
}

  static inline struct wormleaf *
wormhole_jump_leaf_read(struct wormref * const ref, const struct kv * const key)
{
  struct wormhole * const map = ref->map;
  do {
    const struct wormhmap * const hmap = map->hmap;
    ref->qstate = (u64)hmap;
    struct wormleaf * const leaf = wormhole_jump_leaf(hmap, key);
    const u64 v = hmap->version;
    do {
      if (rwlock_trylock_read_nr(&(leaf->leaflock), 64)) {
        if (leaf->version <= v)
          return leaf;
        rwlock_unlock_read(&(leaf->leaflock));
      }
      ref->qstate = (u64)(map->hmap);
      cpu_pause();
    } while (leaf->version <= v);
  } while (true);
}

  static inline struct wormleaf *
wormhole_jump_leaf_write(struct wormref * const ref, const struct kv * const key)
{
  struct wormhole * const map = ref->map;
  do {
    const struct wormhmap * const hmap = map->hmap;
    ref->qstate = (u64)hmap;
    struct wormleaf * const leaf = wormhole_jump_leaf(hmap, key);
    const u64 v = hmap->version;
    do {
      if (rwlock_trylock_write_nr(&(leaf->leaflock), 64)) {
        if (leaf->version <= v)
          return leaf;
        rwlock_unlock_write(&(leaf->leaflock));
      }
      ref->qstate = (u64)(map->hmap);
      cpu_pause();
    } while (leaf->version <= v);
  } while (true);
}
// }}} jump

// leaf-only read {{{
// assumes there in no duplicated keys
// bisect the first key that is >= the given key
  static u64
wormhole_leaf_bisect_sorted(const struct wormleaf * const leaf, const struct kv * const key)
{
  u64 lo = 0;
  u64 hi = leaf->nr_sorted;
  while (lo < hi) {
    u64 i = (lo + hi) >> 1;
    const int cmp = kv_keycompare(u64_to_ptr(leaf->es[i].e3), key);
    if (cmp < 0)  //  [i] < key
      lo = i + 1;
    else if (cmp > 0)
      hi = i;
    else // same key
      return i;
  }
  return lo;
}

// fast point-lookup
// returns WH_KPN if not found
  static u64
wormhole_leaf_match(const struct wormleaf * const leaf, const struct kv * const key)
{
  const u64 pkey = wormhole_pkey(key->hashlo);
  const u64 i0 = pkey / WH_HDIV;
  const struct entry13 * const eh = leaf->eh;

  if (eh[i0].e1 == pkey) {
    struct kv * const curr = u64_to_ptr(eh[i0].e3);
    if (kv_keymatch(key, curr))
      return i0;
  }
  if (eh[i0].e1 == 0)
    return WH_KPN;

  // search left
  u64 i = i0 - 1;
  while (i < WH_KPN) {
    if (eh[i].e1 == pkey) {
      struct kv * const curr = u64_to_ptr(eh[i].e3);
      if (kv_keymatch(key, curr))
        return i;
    } else if (eh[i].e1 < pkey) {
      break;
    }
    i--;
  }

  // search right
  i = i0 + 1;
  while (i < WH_KPN) {
    if (eh[i].e1 == pkey) {
      struct kv * const curr = u64_to_ptr(eh[i].e3);
      if (kv_keymatch(key, curr))
        return i;
    } else if ((eh[i].e1 > pkey) || (eh[i].e1 == 0)) {
      break;
    }
    i++;
  }

  // not found
  return WH_KPN;
}
// }}} leaf-only read

// get/probe {{{
  struct kv *
wormhole_get(struct wormref * const ref, const struct kv * const key, struct kv * const out)
{
  struct wormleaf * const leaf = wormhole_jump_leaf_read(ref, key);
  const u64 i = wormhole_leaf_match(leaf, key);
  struct kv * const tmp = (i < WH_KPN) ? kv_dup2(u64_to_ptr(leaf->eh[i].e3), out) : NULL;
  rwlock_unlock_read(&(leaf->leaflock));
  return tmp;
}

  bool
wormhole_probe(struct wormref * const ref, const struct kv * const key)
{
  struct wormleaf * const leaf = wormhole_jump_leaf_read(ref, key);
  const u64 i = wormhole_leaf_match(leaf, key);
  rwlock_unlock_read(&(leaf->leaflock));
  return i < WH_KPN;
}

  struct kv *
whunsafe_get(struct wormhole * const map, const struct kv * const key, struct kv * const out)
{
  struct wormleaf * const leaf = wormhole_jump_leaf(map->hmap, key);
  const u64 i = wormhole_leaf_match(leaf, key);
  return (i < WH_KPN) ? kv_dup2(u64_to_ptr(leaf->eh[i].e3), out) : NULL;
}

  bool
whunsafe_probe(struct wormhole * const map, const struct kv * const key)
{
  struct wormleaf * const leaf = wormhole_jump_leaf(map->hmap, key);
  return wormhole_leaf_match(leaf, key) < WH_KPN;
}
// }}} get/probe

// single-leaf modification {{{
  static inline void
wormhole_leaf_sort_m2(struct entry13 * const es, const u64 n1, const u64 n2)
{
  if (n1 == 0 || n2 == 0)
    return; // no need to sort

  struct entry13 et[WH_KPN/2]; // min(n1,n2) < KPN/2
  if (n1 <= n2) { // merge left
    memcpy(et, &(es[0]), sizeof(es[0]) * n1);
    struct entry13 * eo = es;
    struct entry13 * e1 = et; // size == n1
    struct entry13 * e2 = &(es[n1]); // size == n2
    const struct entry13 * const z1 = e1 + n1;
    const struct entry13 * const z2 = e2 + n2;
    while ((e1 < z1) && (e2 < z2)) {
      const int cmp = kv_keycompare(u64_to_ptr(e1->e3), u64_to_ptr(e2->e3));
      if (cmp < 0)
        *(eo++) = *(e1++);
      else if (cmp > 0)
        *(eo++) = *(e2++);
      else
        debug_die();

      if (eo == e2)
        break; // finish early
    }
    if (eo < e2)
      memcpy(eo, e1, sizeof(*eo) * (e2 - eo));
  } else {
    memcpy(et, &(es[n1]), sizeof(es[0]) * n2);
    struct entry13 * eo = &(es[n1 + n2 - 1]); // merge backwards
    struct entry13 * e1 = &(es[n1 - 1]); // size == n1
    struct entry13 * e2 = &(et[n2 - 1]); // size == n2
    const struct entry13 * const z1 = e1 - n1;
    const struct entry13 * const z2 = e2 - n2;
    while ((e1 > z1) && (e2 > z2)) {
      const int cmp = kv_keycompare(u64_to_ptr(e1->e3), u64_to_ptr(e2->e3));
      if (cmp < 0)
        *(eo--) = *(e2--);
      else if (cmp > 0)
        *(eo--) = *(e1--);
      else
        debug_die();

      if (eo == e1)
        break;
    }
    if (eo > e1)
      memcpy(e1 + 1, et, sizeof(*eo) * (eo - e1));
  }
}

// make sure all keys are sorted in a leaf node
  static void
wormhole_leaf_sync_sorted(struct wormleaf * const leaf)
{
  const u64 s = leaf->nr_sorted;
  const u64 n = leaf->nr_keys;
  if (s == n)
    return;

  kvmap_entry_qsort(&(leaf->es[s]), n - s);
  // merge-sort inplace
  wormhole_leaf_sort_m2(leaf->es, s, (n - s));
  leaf->nr_sorted = n;
}

  static void
wormhole_leaf_insert_eh(struct entry13 * const eh, const struct entry13 new)
{
  const u64 pkey = new.e1;
  const u32 i0 = pkey / WH_HDIV;
  if (eh[i0].e1 == 0) { // insert
    eh[i0] = new;
    return;
  }

  // find left-most insertion point
  u32 i = i0;
  while (i && eh[i-1].e1 && (eh[i-1].e1 >= pkey))
    i--;
  while ((i < WH_KPN) && eh[i].e1 && (eh[i].e1 < pkey)) // stop at >= or empty
    i++;
  const u32 il = --i; // i in [0, KPN]

  // find left empty slot
  if (i > (i0 - 1))
    i = i0 - 1;
  while ((i < WH_KPN) && eh[i].e1)
    i--;
  const u32 el = i; // el < i0 or el is invalid (>= KPN)

  // find right-most insertion point.
  i = il + 1;
  while ((i < WH_KPN) && eh[i].e1 && (eh[i].e1 == pkey))
    i++;
  const u32 ir = i; // ir >= il, in [0, KPN]

  // find right empty slot
  if (i < (i0 + 1))
    i = i0 + 1;
  while ((i < WH_KPN) && eh[i].e1)
    i++;
  const u32 er = i; // er > i0 or el is invalid (>= KPN)

  // el <= il < ir <= er    (if < WH_KPN)
  const u32 dl = (el < WH_KPN) ? (il - el) : WH_KPN;
  const u32 dr = (er < WH_KPN) ? (er - ir) : WH_KPN;
  if (dl <= dr) { // push left
    debug_assert(dl < WH_KPN);
    if (dl)
      memmove(&(eh[el]), &(eh[el+1]), sizeof(eh[0]) * dl);
    eh[il] = new;
  } else {
    debug_assert(dr < WH_KPN);
    if (dr)
      memmove(&(eh[ir+1]), &(eh[ir]), sizeof(eh[0]) * dr);
    eh[ir] = new;
  }
}

  static void
wormhole_leaf_insert(struct wormleaf * const leaf, const struct kv * const new)
{
  debug_assert(leaf->nr_keys < WH_KPN);
  const u32 nr0 = leaf->nr_keys;
  leaf->nr_keys = nr0 + 1u;

  // append to es (delayed sort)
  leaf->es[nr0].e1 = wormhole_pkey(new->hashlo);
  leaf->es[nr0].e3 = ptr_to_u64(new);
  // optimize for seq insertion
  if (nr0 == leaf->nr_sorted) {
    if (nr0) {
      const struct kv * const kvn = u64_to_ptr(leaf->es[nr0 - 1].e3);
      if (kv_keycompare(new, kvn) > 0)
        leaf->nr_sorted = nr0 + 1u;
    } else {
      leaf->nr_sorted = 1u;
    }
  }

  // insert into eh
  wormhole_leaf_insert_eh(leaf->eh, leaf->es[nr0]);
}

  static void
wormhole_leaf_magnet_eh(struct entry13 * const eh, const u32 im)
{
  // try left
  u32 i = im - 1;
  while ((i < WH_KPN) && eh[i].e1 && ((eh[i].e1 / WH_HDIV) > i)) {
    eh[i+1] = eh[i];
    eh[i].v64 = 0;
    i--;
  }
  // return if moved
  if (eh[im].e1)
    return;

  // try right
  i = im + 1;
  while ((i < WH_KPN) && eh[i].e1 && ((eh[i].e1 / WH_HDIV) < i)) {
    eh[i-1] = eh[i];
    eh[i].v64 = 0;
    i++;
  }
  // eh[im] may still be 0
}

  static struct kv *
wormhole_leaf_remove(struct wormleaf * const leaf, const u64 im)
{
  const u64 nr_keys = leaf->nr_keys;
  const u64 v64 = leaf->eh[im].v64;
  debug_assert(v64);
  // remove from es
  u64 is;
  for (is = 0; is < nr_keys; is++) {
    if (leaf->es[is].v64 == v64) {
      if (is < (nr_keys - 1u))
        leaf->es[is] = leaf->es[nr_keys - 1u];

      break;
    }
  }
  debug_assert(is < nr_keys);
  if (leaf->nr_sorted > is)
    leaf->nr_sorted = is;

  struct kv * const victim = u64_to_ptr(leaf->eh[im].e3);

  // remove from eh
  leaf->eh[im].v64 = 0;
  leaf->nr_keys--;

  // use magnet
  wormhole_leaf_magnet_eh(leaf->eh, im);
  return victim;
}

  static void
wormhole_leaf_update(struct wormhole * const map, struct wormleaf * const leaf, const u64 im,
    const struct kv * const new)
{
  // search entry in es (is)
  const u64 v64 = leaf->eh[im].v64;
  const u64 nr = leaf->nr_keys;
  u64 is;
  for (is = 0; is < nr; is++)
    if (leaf->es[is].v64 == v64)
      break;
  debug_assert(is < nr); // must exist

  kvmap_put_entry(&(map->mm), &(leaf->eh[im]), new);
  leaf->es[is] = leaf->eh[im];
}
// }}} single-leaf modification

// split/merge leaf {{{
// calculate the anchor-key length between two keys
// compare anchor with key0 if i2 == 0; only for split_at()
// return 0 if cannot cut (valid anchor is at least 1 token)
  static u32
wormhole_split_cut_alen(const struct wormleaf * const leaf, const u64 i1, const u64 i2)
{
  debug_assert(leaf->nr_keys == leaf->nr_sorted);
  debug_assert(i2 < leaf->nr_sorted);
  debug_assert((i1 < i2) || (i2 == 0));
  const struct kv * const k1 = i2 ? u64_to_ptr(leaf->es[i1].e3) : leaf->anchor;
  const struct kv * const k2 = u64_to_ptr(leaf->es[i2].e3);
  const u32 lcp = kv_key_lcp(k1, k2);
  if (lcp == k1->klen) { // k1 is k2's prefix
    // no cut if len1 == len2 after removing trailing zeros
    u32 tklen = k2->klen;
    while ((tklen > k1->klen) && (k2->kv[tklen-1] == 0))
      tklen--;
    if (tklen <= k1->klen)
      return 0;
  }
  // have valid cut
  u32 alen = lcp + 1;
  while ((alen < k2->klen) && (k2->kv[alen-1] == 0))
    alen++;
  debug_assert(k2->kv[alen-1]);
  return (alen <= UINT16_MAX) ? alen : 0;
}

// internal use only by split_cut
  static bool
wormhole_split_cut_try_alen(const struct wormleaf * const leaf, const u64 i1, const u64 i2,
    const u32 alen)
{
  debug_assert(i1 < i2);
  struct kv * const k1 = u64_to_ptr(leaf->es[i1].e3);
  struct kv * const k2 = u64_to_ptr(leaf->es[i2].e3);
  const u8 c1 = (k1->klen < alen) ? 0 : k1->kv[alen - 1];
  const u8 c2 = (k2->klen < alen) ? 0 : k2->kv[alen - 1];
  return c1 != c2;
}

// determine where to cut at leaf
// return WH_KPN if there is no valid cut point
// otherwise, return a value in the range [1..(nr_keys-1)]
  static u64
wormhole_split_cut(const struct wormleaf * const leaf)
{
  debug_assert(leaf->nr_keys == leaf->nr_sorted);
  debug_assert(leaf->nr_keys >= 2);
  u64 lo = 0;
  u64 hi = leaf->nr_sorted-1;

  const u32 alen = wormhole_split_cut_alen(leaf, lo, hi);
  if (alen == 0)
    return WH_KPN;

  while ((lo + 1u) < hi) {
    const u64 mid = (lo + hi + 1u) >> 1u;
    if (mid <= WH_MID) { // try right
      if (wormhole_split_cut_try_alen(leaf, mid, hi, alen))
        lo = mid;
      else
        hi = mid;
    } else { // try left
      if (wormhole_split_cut_try_alen(leaf, lo, mid, alen))
        hi = mid;
      else
        lo = mid;
    }
  }
  return hi;
}

  static void
wormhole_split_leaf_move(struct wormleaf * const leaf1, struct wormleaf * const leaf2, const u64 cut)
{
  const u64 nr_move = leaf1->nr_keys - cut;
  // move es
  memcpy(leaf2->es, &(leaf1->es[cut]), sizeof(leaf2->es[0]) * nr_move);
  // valid keys: leaf1 [0, cut-1]; leaf2 [0, nr_all - cut - 1]

  // leaf2's eh is empty
  for (u64 i = 0; i < nr_move; i++) {
    // insert into leaf2->eh
    wormhole_leaf_insert_eh(leaf2->eh, leaf2->es[i]);
    // remove from leaf1->eh
    const struct kv * const key = u64_to_ptr(leaf2->es[i].e3);
    const u64 im = wormhole_leaf_match(leaf1, key);
    debug_assert(im < WH_KPN);
    leaf1->eh[im].v64 = 0; // remove
    wormhole_leaf_magnet_eh(leaf1->eh, im);
  }

  // metadata
  leaf1->nr_keys = cut;
  leaf1->nr_sorted = cut;
  leaf2->nr_keys = nr_move;
  leaf2->nr_sorted = nr_move;
}

// create an anchor for leaf-split
  static struct kv *
wormhole_split_alloc_anchor(const struct kv * const key1, const struct kv * const key2)
{
  // keys are still in leaf1
  const u32 key2len = key2->klen;
  u32 alen = kv_key_lcp(key1, key2) + 1;

  // anchor must end with non-zero
  while ((alen < key2len) && (key2->kv[alen - 1] == 0))
    alen++;
  debug_assert(alen <= key2len);

  // now we have the correct alen
  struct kv * const anchor2 = wormhole_alloc_akey(alen);
  if (anchor2)
    kv_refill(anchor2, key2->kv, alen, NULL, 0);
  return anchor2;
}

// all locked
// move keys starting with [cut] in leaf1 to leaf2
  static struct wormleaf *
wormhole_split_leaf(struct wormhole * const map, struct wormleaf * const leaf1, const u64 cut)
{
  // anchor of leaf2
  struct kv * const key1 = cut ? u64_to_ptr(leaf1->es[cut-1].e3) : leaf1->anchor;
  struct kv * const key2 = u64_to_ptr(leaf1->es[cut].e3);
  struct kv * const anchor2 = wormhole_split_alloc_anchor(key1, key2);
  if (anchor2 == NULL) // anchor alloc failed
    return NULL;

  // create leaf2 with NULL anchor
  struct wormleaf * const leaf2 = wormhole_alloc_leaf(map, leaf1, leaf1->next, anchor2);
  if (leaf2 == NULL) {
    wormhole_free_akey(anchor2);
    return NULL;
  }

  // split_hmap will unlock the leaf nodes; must move now
  wormhole_split_leaf_move(leaf1, leaf2, cut);
  return leaf2;
}

/*
   MERGE is the only operation that deletes a leaf node (leaf2).
   It ALWAYS merges the right node into the left node even if the left is empty.
   This requires both of their writer locks to be acquired.
   This allows iterators to safely probe the next node (but not backwards).
   In other words, if either the reader or the writer lock of node X has been acquired:
   X->next (the pointer) cannot be changed by any other thread.
   X->next cannot be deleted.
   But the content in X->next can still be changed.
 */
  static void
wormhole_merge_leaf_move(struct wormleaf * const leaf1, struct wormleaf * const leaf2)
{
  const u64 nr1 = leaf1->nr_keys;
  const u64 nr2 = leaf2->nr_keys;
  if (nr2 == 0)
    return;

  debug_assert((nr1 + nr2) <= WH_KPN);
  struct entry13 * const eh1 = leaf1->eh;
  struct entry13 * const es2 = leaf2->es;

  for (u64 i = 0; i < nr2; i++) {
    // callers are merger, no need to clear eh2
    debug_assert(es2[i].v64);
    wormhole_leaf_insert_eh(eh1, es2[i]);
  }
  leaf1->nr_keys = nr1 + nr2; // nr_sorted remain unchanged
  // move es
  memcpy(&(leaf1->es[nr1]), &(leaf2->es[0]), sizeof(leaf2->es[0]) * nr2);
  // if leaf1 is already sorted
  if (leaf1->nr_sorted == nr1)
    leaf1->nr_sorted += leaf2->nr_sorted;
}
// }}} split-merge leaf

// split meta {{{
// zero-extend an existing node
  static void
wormhole_split_meta_extend(struct wormhmap * const hmap, struct wormmeta * const meta,
    struct kv * const mkey, struct kv * const mkey2)
{
  debug_assert(meta->lmost == meta->rmost);
  debug_assert(meta->klen == mkey->klen);
  wormhole_meta_bm_set(meta, 0);
  const u32 len0 = mkey->klen;
  struct kv * mkey1 = NULL;

  if (meta->keyref->klen > len0) { // can reuse keyref of the existing meta node
    debug_assert(meta->keyref->kv[len0] == 0);
    mkey1 = meta->keyref;
  } else if (mkey->kv[len0] == 0) {
    mkey1 = mkey;
  } else if (mkey2) { // only at the last step
    debug_assert(mkey2->klen > len0);
    debug_assert(mkey2->kv[len0] == 0); // should have been prepared
    mkey1 = mkey2;
  } else {
    debug_die();
  }
  struct slab * const slab = hmap->slab;
  struct wormleaf * const lmost = meta->lmost;
  const u64 hash321 = crc32c_u8(mkey->hashlo, 0);
  const u32 len1 = len0 + 1; // new anchor at +1
  struct wormmeta * const meta1 = wormhole_alloc_meta(slab, lmost, mkey1, hash321, len1);
  debug_assert(meta1);
  wormhole_hmap_set(hmap, meta1);
}

// return true if a new node is created
  static bool
wormhole_split_meta_touch(struct wormhmap * const hmap, struct kv * const mkey,
    struct kv * const mkey2, struct wormleaf * const leaf)
{
  struct wormmeta * const meta = wormhole_hmap_get(hmap, mkey);
  if (meta) {
    if (meta->bitmin == WH_FO) // push down leaf
      wormhole_split_meta_extend(hmap, meta, mkey, mkey2);
    wormhole_meta_bm_set(meta, mkey->kv[mkey->klen]);
    if (meta->lmost == leaf->next)
      meta->lmost = leaf;
    if (meta->rmost == leaf->prev)
      meta->rmost = leaf;
    return false;
  } else { // create new node
    struct slab * const slab = hmap->slab;
    struct wormmeta * const new = wormhole_alloc_meta(slab, leaf, mkey, mkey->hashlo, mkey->klen);
    debug_assert(new);
    if (mkey->klen < leaf->klen)
      wormhole_meta_bm_set(new, mkey->kv[mkey->klen]);
    wormhole_hmap_set(hmap, new);
    return true;
  }
}

// for leaf1, a leaf2 is already linked at its right side.
// this function updates the meta-map by moving leaf1 and hooking leaf2 at correct positions
  static void
wormhole_split_meta_hmap(struct wormhmap * const hmap, struct wormleaf * const leaf,
    struct kv * const mkey, struct kv * const mkey2)
{
  const struct kv * const anchor = leaf->anchor;
  // save mkey metadata
  const u64 mhash = mkey->hash;
  const u32 mklen = mkey->klen;

  // left branches
  const u32 lcp1 = kv_key_lcp(leaf->prev->anchor, anchor);
  const u32 lcp2 = leaf->next ? kv_key_lcp(anchor, leaf->next->anchor) : 0;
  u32 i = (lcp1 < lcp2) ? lcp1 : lcp2;

  wormhole_prefix(mkey, i);
  do {
    const bool rnew = wormhole_split_meta_touch(hmap, mkey, mkey2, leaf);
    if ((i >= leaf->klen) && rnew)
      break;
    i++;
    wormhole_prefix_inc1(mkey);
    debug_assert(i < mklen);
  } while (true);

  // adjust maxplen; i is the plen of the last _touch()
  if (i > hmap->maxplen)
    hmap->maxplen = i;
  // restore mkey metadata
  mkey->hash = mhash;
  mkey->klen = mklen;
  if (mkey2)
    mkey2->klen = mklen; // hash of mkey2 is not required
}

  static struct kv *
wormhole_split_alloc_mkey(struct wormleaf * const leaf)
{
  u32 buflen = leaf->klen;
  struct wormleaf * const next = leaf->next;
  if (next && (next->klen > buflen)) { // may need a longer mkey
    const u32 lcp = kv_key_lcp(leaf->anchor, next->anchor);
    if (lcp == buflen) { // buflen == leaf->klen
      while ((buflen < next->klen) && (next->anchor->kv[buflen] == 0))
        buflen++;
    }
  }
  buflen += 2; // very safe. mkey is long enough for split
  return wormhole_alloc_mkey_extend(leaf->anchor, buflen);
}

// we may need to allocate a mkey2 if a1 is a prefix of a2
// return true if mkey2 should be allocated
  static bool
wormhole_split_check_mkey2(const struct wormleaf * const leaf2)
{
  const struct kv * const a1 = leaf2->prev->anchor;
  const struct kv * const a2 = leaf2->anchor;
  return (a1->klen <= a2->klen) && (!memcmp(a1->kv, a2->kv, a1->klen));
}

// all locks will be released before returning
  static bool
wormhole_split_meta_ref(struct wormref * const ref, struct wormleaf * const leaf2)
{
  struct kv * const mkey = wormhole_split_alloc_mkey(leaf2);
  if (mkey == NULL)
    return false;
  struct kv * mkey2 = NULL;
  if (wormhole_split_check_mkey2(leaf2)) {
    mkey2 = wormhole_alloc_mkey_extend(leaf2->prev->anchor, mkey->klen);
    if (mkey2 == NULL) {
      wormhole_free_mkey(mkey);
      return false;
    }
  }

  struct wormhole * const map = ref->map;
  // metalock
  while (rwlock_trylock_write_nr(&(map->metalock), 64) == false)
    ref->qstate = (u64)(map->hmap);

  // check slab reserve
  const bool sr1 = wormhole_slab_reserve(map->hmap2[0].slab, mkey->klen);
  const bool sr2 = wormhole_slab_reserve(map->hmap2[1].slab, mkey->klen);
  if (!(sr1 && sr2)) {
    rwlock_unlock_write(&(map->metalock));
    wormhole_free_mkey(mkey);
    wormhole_free_mkey(mkey2);
    return false;
  }

  cpu_cfence();
  struct wormhmap * const hmap0 = map->hmap;
  struct wormhmap * const hmap1 = &(map->hmap2[1-hmap0->hmap_id]);

  // link
  struct wormleaf * const leaf1 = leaf2->prev;
  leaf1->next = leaf2;
  if (leaf2->next)
    leaf2->next->prev = leaf2;

  // update versions
  const u64 v1 = hmap0->version + 1;
  leaf1->version = v1;
  leaf2->version = v1;
  hmap1->version = v1;

  wormhole_split_meta_hmap(hmap1, leaf2, mkey, mkey2);

  ref->qstate = (u64)(hmap1);
  // switch hmap
  cpu_cfence();
  map->hmap = hmap1;
  cpu_cfence();

  rwlock_unlock_write(&(leaf1->leaflock));
  rwlock_unlock_write(&(leaf2->leaflock));

  qsbr_wait(map->qsbr, (u64)hmap1);

  wormhole_split_meta_hmap(hmap0, leaf2, mkey, mkey2);

  rwlock_unlock_write(&(map->metalock));

  if (mkey->refcnt == 0) // this is possible
    wormhole_free_mkey(mkey);
  if (mkey2 && (mkey2->refcnt == 0)) // this is possible
    wormhole_free_mkey(mkey2);
  return true;
}

// all locks (metalock + leaflocks) will be released before returning
// leaf1->lock (write) is already taken
  static bool
wormhole_split_insert_ref(struct wormref * const ref, struct wormleaf * const leaf1,
    struct kv * const new)
{
  wormhole_leaf_sync_sorted(leaf1);
  // check for a corner case that we don't handle for now.
  // TODO: Implement fat node.
  //       Option 1: a pointer in wormleaf pointing to the extra items
  //       Option 2: make eh/es dynamically allocated
  const u64 cut = wormhole_split_cut(leaf1);
  if (cut == WH_KPN) {
    fprintf(stderr, "%s WARNING: Cannot split\n", __func__);
    rwlock_unlock_write(&(leaf1->leaflock));
    return false; // insertion failed
  }

  struct wormleaf * const leaf2 = wormhole_split_leaf(ref->map, leaf1, cut);
  if (leaf2 == NULL) {
    rwlock_unlock_write(&(leaf1->leaflock));
    return false;
  }

  rwlock_lock_write(&(leaf2->leaflock));
  const int cmp = kv_keycompare(new, leaf2->anchor);
  struct wormleaf * const leaf = (cmp < 0) ? leaf1 : leaf2;
  wormhole_leaf_insert(leaf, new);

  const bool rsm = wormhole_split_meta_ref(ref, leaf2);
  if (rsm == false) {
    // undo insertion & merge; free leaf2
    const u64 im = wormhole_leaf_match(leaf, new);
    (void)wormhole_leaf_remove(leaf, im);
    wormhole_merge_leaf_move(leaf1, leaf2);
    rwlock_unlock_write(&(leaf1->leaflock));
    rwlock_unlock_write(&(leaf2->leaflock));
    wormhole_free_akey(leaf2->anchor);
    slab_free(ref->map->slab_leaf, leaf2);
  }
  return rsm;
}

  static bool
whunsafe_split_meta(struct wormhole * const map, struct wormleaf * const leaf2)
{
  struct kv * const mkey = wormhole_split_alloc_mkey(leaf2);
  if (mkey == NULL)
    return false;
  struct kv * mkey2 = NULL;
  if (wormhole_split_check_mkey2(leaf2)) {
    mkey2 = wormhole_alloc_mkey_extend(leaf2->prev->anchor, mkey->klen);
    if (mkey2 == NULL) {
      wormhole_free_mkey(mkey);
      return false;
    }
  }

  const bool sr1 = wormhole_slab_reserve(map->hmap2[0].slab, mkey->klen);
  const bool sr2 = wormhole_slab_reserve(map->hmap2[1].slab, mkey->klen);
  if (!(sr1 && sr2)) {
    rwlock_unlock_write(&(map->metalock));
    wormhole_free_mkey(mkey);
    wormhole_free_mkey(mkey2);
    return false;
  }

  // link
  leaf2->prev->next = leaf2;
  if (leaf2->next)
    leaf2->next->prev = leaf2;

  for (u64 i = 0; i < 2; i++)
    if (map->hmap2[i].pmap)
      wormhole_split_meta_hmap(&(map->hmap2[i]), leaf2, mkey, mkey2);
  if (mkey->refcnt == 0) // this is possible
    wormhole_free_mkey(mkey);
  if (mkey2 && (mkey2->refcnt == 0)) // this is possible
    wormhole_free_mkey(mkey2);
  return true;
}

  static bool
whunsafe_split_insert(struct wormhole * const map, struct wormleaf * const leaf1,
    struct kv * const new)
{
  wormhole_leaf_sync_sorted(leaf1);
  // check for a corner case that we don't handle for now.
  // TODO: Implement fat node.
  //       Option 1: a pointer in wormleaf pointing to the extra items
  //       Option 2: make eh/es dynamically allocated
  const u64 cut = wormhole_split_cut(leaf1);
  if (cut == WH_KPN) {
    fprintf(stderr, "%s WARNING: Cannot split\n", __func__);
    return false; // insertion failed
  }

  struct wormleaf * const leaf2 = wormhole_split_leaf(map, leaf1, cut);
  if (leaf2 == NULL)
    return false;

  const int cmp = kv_keycompare(new, leaf2->anchor);
  struct wormleaf * const leaf = (cmp < 0) ? leaf1 : leaf2;

  wormhole_leaf_insert(leaf, new);

  const bool rsm = whunsafe_split_meta(map, leaf2);
  if (rsm == false) {
    // undo insertion, merge, free leaf2
    const u64 im = wormhole_leaf_match(leaf, new);
    (void)wormhole_leaf_remove(leaf, im);
    wormhole_merge_leaf_move(leaf1, leaf2);
    wormhole_free_akey(leaf2->anchor);
    slab_free(map->slab_leaf, leaf2);
  }
  return rsm;
}
// }}} split meta

// set {{{
  bool
wormhole_set(struct wormref * const ref, const struct kv * const kv)
{
  // we always allocate a new item on SET
  // future optimizations may perform in-place update
  struct kv * const new = kv_mm_dup(kv, &(ref->map->mm));
  if (new == NULL)
    return false;

  struct wormleaf * const leaf = wormhole_jump_leaf_write(ref, new);
  // update
  const u64 im = wormhole_leaf_match(leaf, new);
  if (im < WH_KPN) {
    wormhole_leaf_update(ref->map, leaf, im, new);
    rwlock_unlock_write(&(leaf->leaflock));
    return true;
  }

  // insert
  if (leaf->nr_keys < WH_KPN) { // just insert
    wormhole_leaf_insert(leaf, new);
    rwlock_unlock_write(&(leaf->leaflock));
    return true;
  }

  // split_insert changes hmap
  // all locks should be released in wormhole_split_insert_ref()
  const bool rsi = wormhole_split_insert_ref(ref, leaf, new);
  if (!rsi)
    ref->map->mm.rf(new, ref->map->mm.rp);
  return rsi;
}

  bool
whunsafe_set(struct wormhole * const map, const struct kv * const kv)
{
  struct kv * const new = kv_mm_dup(kv, &(map->mm));
  if (new == NULL)
    return false;

  struct wormleaf * const leaf = wormhole_jump_leaf(map->hmap, new);
  // update
  const u64 im = wormhole_leaf_match(leaf, new);
  if (im < WH_KPN) { // overwrite
    wormhole_leaf_update(map, leaf, im, new);
    return true;
  }

  // insert
  if (leaf->nr_keys < WH_KPN) { // just insert
    wormhole_leaf_insert(leaf, new);
    return true;
  }

  // split_insert changes hmap
  const bool rsi = whunsafe_split_insert(map, leaf, new);
  if (!rsi)
    map->mm.rf(new, map->mm.rp);
  return rsi;
}
// }}} set

// inplace {{{
  bool
wormhole_inplace(struct wormref * const ref, const struct kv * const key,
    kv_inplace_func uf, void * const priv)
{
  struct wormleaf * const leaf = wormhole_jump_leaf_write(ref, key);
  const u64 im = wormhole_leaf_match(leaf, key);
  if (im < WH_KPN) {
    uf(u64_to_ptr(leaf->eh[im].e3), priv);
    rwlock_unlock_write(&(leaf->leaflock));
    return true;
  } else {
    rwlock_unlock_write(&(leaf->leaflock));
    return false;
  }
}

  bool
whunsafe_inplace(struct wormhole * const map, const struct kv * const key,
    kv_inplace_func uf, void * const priv)
{
  struct wormleaf * const leaf = wormhole_jump_leaf(map->hmap, key);
  const u64 im = wormhole_leaf_match(leaf, key);
  if (im < WH_KPN) { // overwrite
    uf(u64_to_ptr(leaf->eh[im].e3), priv);
    return true;
  } else {
    return false;
  }
}
// }}} set

// merge meta {{{
// all locks held
  static void
wormhole_merge_meta_hmap(struct wormhmap * const hmap, struct wormleaf * const leaf,
    struct kv * const pbuf)
{
  struct wormleaf * const prev = leaf->prev;
  struct wormleaf * const next = leaf->next;
  const struct kv * const anchor0 = leaf->anchor;
  const u32 lcp1 = prev ? kv_key_lcp(prev->anchor, anchor0) : 0;
  const u32 lcp2 = next ? kv_key_lcp(next->anchor, anchor0) : 0;

  kv_dup2_key(anchor0, pbuf);
  u32 i = lcp1 < lcp2 ? lcp1 : lcp2;
  struct slab * const slab = hmap->slab;
  // lmost & rmost
  struct wormmeta * parent = NULL;
  wormhole_prefix(pbuf, i);
  do {
    debug_assert(i <= hmap->maxplen);
    struct wormmeta * const meta = wormhole_hmap_get(hmap, pbuf);
    debug_assert(meta);
    if (meta->lmost == meta->rmost) { // delete single-child
      debug_assert(meta->lmost == leaf);
      const u32 bitmin = meta->bitmin;
      wormhole_hmap_del(hmap, pbuf);
      wormhole_free_meta(slab, meta);
      if (parent) {
        wormhole_meta_bm_clear(parent, pbuf->kv[i-1]);
        parent = NULL;
      }
      if (bitmin == WH_FO) // no child
        break;
    } else { // adjust lmost rmost
      if (meta->lmost == leaf)
        meta->lmost = next;

      if (meta->rmost == leaf)
        meta->rmost = prev;
      parent = meta;
    }

    if (i >= anchor0->klen)
      pbuf->kv[i] = 0; // for zero-extended prefixes
    i++;
    wormhole_prefix_inc1(pbuf);
  } while (true);
}

// all locks (metalock + two leaflock) will be released before returning
// merge leaf2 to leaf1, removing all metadata to leaf2 and leaf2 itself
  static void
wormhole_merge_meta_ref(struct wormref * const ref, struct wormleaf * const leaf1,
    struct wormleaf * const leaf2, struct kv * const pbuf)
{
  debug_assert(leaf1->next == leaf2);
  debug_assert(leaf2->prev == leaf1);
  struct wormhole * const map = ref->map;
  while (rwlock_trylock_write_nr(&(map->metalock), 64) == false)
    ref->qstate = (u64)(map->hmap);

  cpu_cfence();
  struct wormhmap * const hmap0 = map->hmap;
  struct wormhmap * const hmap1 = &(map->hmap2[1-hmap0->hmap_id]);
  const u64 v1 = hmap0->version + 1;

  leaf1->next = leaf2->next;
  if (leaf2->next)
    leaf2->next->prev = leaf1;

  leaf1->version = v1;
  leaf2->version = v1;
  hmap1->version = v1;

  wormhole_merge_meta_hmap(hmap1, leaf2, pbuf);
  ref->qstate = (u64)(hmap1);

  cpu_cfence();
  map->hmap = hmap1;
  cpu_cfence();

  rwlock_unlock_write(&(leaf1->leaflock));
  rwlock_unlock_write(&(leaf2->leaflock));

  qsbr_wait(map->qsbr, (u64)hmap1);

  wormhole_merge_meta_hmap(hmap0, leaf2, pbuf);
  // leaf2 is now safe to be removed
  wormhole_free_akey(leaf2->anchor);
  slab_free(map->slab_leaf, leaf2);
  rwlock_unlock_write(&(map->metalock));
}

  static bool
wormhole_merge_ref(struct wormref * const ref, struct wormleaf * const leaf)
{
  struct wormhole * const map = ref->map;
  struct wormleaf * const next = leaf->next;
  debug_assert(next);

  struct kv * const pbuf = wormhole_alloc_mkey(map->hmap->maxplen);
  if (pbuf == NULL) {
    rwlock_unlock_write(&(leaf->leaflock));
    return false;
  }

  while (rwlock_trylock_write_nr(&(next->leaflock), 64) == false)
    ref->qstate = (u64)(map->hmap);

  // leaf and next are write-locked
  cpu_cfence();
  // double check
  if ((leaf->nr_keys + next->nr_keys) <= WH_KPN) {
    wormhole_merge_leaf_move(leaf, next);
    wormhole_merge_meta_ref(ref, leaf, next, pbuf);
  } else { // the next contains more keys than expected
    rwlock_unlock_write(&(leaf->leaflock));
    rwlock_unlock_write(&(next->leaflock));
  }
  wormhole_free_mkey(pbuf);
  return true;
}

  static void
whunsafe_merge(struct wormhole * const map, struct wormleaf * const leaf1,
    struct wormleaf * const leaf2)
{
  struct kv * const pbuf = wormhole_alloc_mkey(map->hmap->maxplen);
  if (pbuf == NULL)
    return;
  debug_assert(leaf1->next == leaf2);
  debug_assert(leaf2->prev == leaf1);
  wormhole_merge_leaf_move(leaf1, leaf2);

  leaf1->next = leaf2->next;
  if (leaf2->next)
    leaf2->next->prev = leaf1;
  for (u64 i = 0; i < 2; i++)
    if (map->hmap2[i].pmap)
      wormhole_merge_meta_hmap(&(map->hmap2[i]), leaf2, pbuf);
  wormhole_free_akey(leaf2->anchor);
  slab_free(map->slab_leaf, leaf2);
  wormhole_free_mkey(pbuf);
}
// }}} merge meta

// del {{{
  bool
wormhole_del(struct wormref * const ref, const struct kv * const key)
{
  struct wormleaf * const leaf = wormhole_jump_leaf_write(ref, key);
  const u64 im = wormhole_leaf_match(leaf, key);
  bool r = false;
  if (im < WH_KPN) { // found
    struct kv * const kv = wormhole_leaf_remove(leaf, im);
    debug_assert(kv);
    ref->map->mm.rf(kv, ref->map->mm.rp);
    r = true;
    const u64 n1 = leaf->nr_keys;
    const u64 n2 = leaf->next ? leaf->next->nr_keys : WH_KPN;
    if ((leaf->next && (n1 == 0)) || ((n1 + n2) < WH_KPN_MRG)) {
      // try merge, it may fail if malloc fails
      (void)wormhole_merge_ref(ref, leaf);
      // locks are already released; immediately return
      return r;
    }
  }

  rwlock_unlock_write(&(leaf->leaflock));
  return r;
}

  bool
whunsafe_del(struct wormhole * const map, const struct kv * const key)
{
  struct wormleaf * const leaf = wormhole_jump_leaf(map->hmap, key);
  const u64 im = wormhole_leaf_match(leaf, key);
  if (im < WH_KPN) { // found
    struct kv * const kv = wormhole_leaf_remove(leaf, im);
    debug_assert(kv);
    map->mm.rf(kv, map->mm.rp);

    const u64 n0 = leaf->prev ? leaf->prev->nr_keys : WH_KPN;
    const u64 n1 = leaf->nr_keys;
    const u64 n2 = leaf->next ? leaf->next->nr_keys : WH_KPN;

    if ((leaf->prev && (n1 == 0)) || ((n0 + n1) < WH_KPN_MRG)) {
      whunsafe_merge(map, leaf->prev, leaf);
    } else if ((leaf->next && (n1 == 0)) || ((n1 + n2) < WH_KPN_MRG)) {
      whunsafe_merge(map, leaf, leaf->next);
    }
    return true;
  }
  return false;
}
// }}} del

// iter {{{
  struct wormhole_iter *
wormhole_iter_create(struct wormref * const ref)
{
  struct wormhole_iter * const iter = malloc(sizeof(*iter));
  if (iter == NULL)
    return NULL;
  iter->ref = ref;
  iter->leaf = NULL;
  iter->next_id = 0;
  wormhole_iter_seek(iter, NULL);
  return iter;
}

  void
wormhole_iter_seek(struct wormhole_iter * const iter, const struct kv * const key)
{
  if (iter->leaf)
    rwlock_unlock_read(&(iter->leaf->leaflock));
  struct wormref * const ref = iter->ref;
  struct wormhole * const map = ref->map;

  if (key == NULL) {
    struct wormleaf * const leaf0 = map->leaf0;
    iter->leaf = leaf0;
    iter->next_id = 0;
    while (rwlock_trylock_write_nr(&(leaf0->leaflock), 64) == false)
      ref->qstate = (u64)(map->hmap);
    wormhole_leaf_sync_sorted(leaf0);
    rwlock_write_to_read(&(leaf0->leaflock));
    return;
  }

  struct wormleaf * const leaf = wormhole_jump_leaf_write(ref, key);
  wormhole_leaf_sync_sorted(leaf);
  rwlock_write_to_read(&(leaf->leaflock));

  const u64 id = wormhole_leaf_bisect_sorted(leaf, key);
  if (id < leaf->nr_sorted) {
    iter->leaf = leaf;
    iter->next_id = id;
  } else {
    struct wormleaf * const next = leaf->next;
    iter->leaf = next;
    iter->next_id = 0;
    if (next) {
      while (rwlock_trylock_write_nr(&(next->leaflock), 64) == false)
        ref->qstate = (u64)(map->hmap);
      wormhole_leaf_sync_sorted(next);
      rwlock_write_to_read(&(next->leaflock));
    }
    rwlock_unlock_read(&(leaf->leaflock));
  }
}

  static struct kv *
wormhole_iter_current(struct wormhole_iter * const iter)
{
  if (iter->leaf == NULL)
    return NULL;
  while (iter->next_id >= iter->leaf->nr_sorted) {
    struct wormleaf * const next = iter->leaf->next;
    if (next) {
      struct wormref * const ref = iter->ref;
      struct wormhole * const map = ref->map;
      while (rwlock_trylock_write_nr(&(next->leaflock), 64) == false)
        ref->qstate = (u64)(map->hmap);
      wormhole_leaf_sync_sorted(next);
      rwlock_write_to_read(&(next->leaflock));
    }
    rwlock_unlock_read(&(iter->leaf->leaflock));
    iter->leaf = next;
    iter->next_id = 0;
    if (next == NULL)
      return NULL;
  }

  debug_assert(iter->next_id < iter->leaf->nr_sorted);
  struct kv * const kv = u64_to_ptr(iter->leaf->es[iter->next_id].e3);
  return kv;
}

  struct kv *
wormhole_iter_peek(struct wormhole_iter * const iter, struct kv * const out)
{
  struct kv * const kv = wormhole_iter_current(iter);
  if (kv) {
    struct kv * const ret = kv_dup2(kv, out);
    return ret;
  }
  return NULL;
}

  struct kv *
wormhole_iter_next(struct wormhole_iter * const iter, struct kv * const out)
{
  struct kv * const kv = wormhole_iter_current(iter);
  if (kv) {
    struct kv * const ret = kv_dup2(kv, out);
    iter->next_id++;
    return ret;
  }
  return NULL;
}

  void
wormhole_iter_skip(struct wormhole_iter * const iter, const u64 nr)
{
  for (u64 i = 0; i < nr; i++) {
    if (wormhole_iter_current(iter) == NULL)
      return;
    iter->next_id++;
  }
}

  bool
wormhole_iter_inplace(struct wormhole_iter * const iter, kv_inplace_func uf, void * const priv)
{
  struct kv * const kv = wormhole_iter_current(iter);
  uf(kv, priv); // call uf even if (kv == NULL)
  return kv != NULL;
}

  void
wormhole_iter_destroy(struct wormhole_iter * const iter)
{
  if (iter->leaf)
    rwlock_unlock_read(&(iter->leaf->leaflock));
  free(iter);
}
// }}} iter

// unsafe iter {{{
  struct wormhole_iter *
whunsafe_iter_create(struct wormhole * const map)
{
  struct wormhole_iter * const iter = malloc(sizeof(*iter));
  if (iter == NULL)
    return NULL;
  iter->map = map;
  iter->leaf = NULL;
  iter->next_id = 0;
  whunsafe_iter_seek(iter, NULL);
  return iter;
}

  void
whunsafe_iter_seek(struct wormhole_iter * const iter, const struct kv * const key)
{
  struct wormhole * const map = iter->map;

  if (key == NULL) {
    struct wormleaf * const leaf0 = map->leaf0;
    iter->leaf = leaf0;
    iter->next_id = 0;
    wormhole_leaf_sync_sorted(leaf0);
    return;
  }

  struct wormleaf * const leaf = wormhole_jump_leaf(map->hmap, key);
  wormhole_leaf_sync_sorted(leaf);

  const u64 id = wormhole_leaf_bisect_sorted(leaf, key);
  if (id < leaf->nr_sorted) {
    iter->leaf = leaf;
    iter->next_id = id;
  } else {
    struct wormleaf * const next = leaf->next;
    iter->leaf = next;
    iter->next_id = 0;
    if (next)
      wormhole_leaf_sync_sorted(next);
  }
}

  static struct kv *
whunsafe_iter_current(struct wormhole_iter * const iter)
{
  if (iter->leaf == NULL)
    return NULL;
  while (iter->next_id >= iter->leaf->nr_sorted) {
    struct wormleaf * const next = iter->leaf->next;
    if (next)
      wormhole_leaf_sync_sorted(next);
    iter->leaf = next;
    iter->next_id = 0;
    if (next == NULL)
      return NULL;
  }

  debug_assert(iter->next_id < iter->leaf->nr_sorted);
  struct kv * const kv = u64_to_ptr(iter->leaf->es[iter->next_id].e3);
  return kv;
}

  struct kv *
whunsafe_iter_peek(struct wormhole_iter * const iter, struct kv * const out)
{
  struct kv * const kv = whunsafe_iter_current(iter);
  if (kv) {
    struct kv * const ret = kv_dup2(kv, out);
    return ret;
  }
  return NULL;
}

  struct kv *
whunsafe_iter_next(struct wormhole_iter * const iter, struct kv * const out)
{
  struct kv * const kv = whunsafe_iter_current(iter);
  if (kv) {
    struct kv * const ret = kv_dup2(kv, out);
    iter->next_id++;
    return ret;
  }
  return NULL;
}

  void
whunsafe_iter_skip(struct wormhole_iter * const iter, const u64 nr)
{
  for (u64 i = 0; i < nr; i++) {
    if (whunsafe_iter_current(iter) == NULL)
      return;
    iter->next_id++;
  }
}

  bool
whunsafe_iter_inplace(struct wormhole_iter * const iter, kv_inplace_func uf, void * const priv)
{
  struct kv * const kv = whunsafe_iter_current(iter);
  uf(kv, priv); // call uf even if (kv == NULL)
  return kv != NULL;
}

  void
whunsafe_iter_destroy(struct wormhole_iter * const iter)
{
  free(iter);
}
// }}} unsafe iter

// misc {{{
  inline struct wormref *
wormhole_ref(struct wormhole * const map)
{
  struct wormref * const ref = malloc(sizeof(*ref));
  if (ref == NULL)
    return NULL;
  ref->qstate = 0;
  ref->map = map;
  if (qsbr_register(map->qsbr, &(ref->qstate)) == false) {
    free(ref);
    return NULL;
  }
  return ref;
}

  inline struct wormhole *
wormhole_unref(struct wormref * const ref)
{
  struct wormhole * const map = ref->map;
  qsbr_unregister(map->qsbr, &(ref->qstate));
  free(ref);
  return map;
}

  inline void
wormhole_refresh_qstate(struct wormref * const ref)
{
  ref->qstate = (u64)(ref->map->hmap);
}

// unsafe
  static void
wormhole_clean1(struct wormhole * const map)
{
  // meta
  for (u64 x = 0; x < 2; x++) {
    if (map->hmap2[x].pmap == NULL)
      continue;
    const u64 nr_slots = map->hmap2[x].mask + 1;
    for (u64 s = 0; s < nr_slots; s++) {
      struct wormmbkt * const slot = &(map->hmap2[x].pmap[s]);
      for (u64 i = 0; i < KVBUCKET_NR; i++) {
        if (slot->e[i] == NULL)
          continue;
        struct wormmeta * const meta = slot->e[i];
        wormhole_free_meta(map->hmap2[x].slab, meta);
        slot->e[i] = NULL;
        map->hmap2[x].wmap[s].t[i] = 0;
      }
    }
    map->hmap2[x].maxplen = 0;
  }
  // leaf
  struct wormleaf * leaf = map->leaf0;
  while (leaf) {
    struct wormleaf * const next = leaf->next;
    wormhole_free_akey(leaf->anchor);
    for (u64 i = 0; i < WH_KPN; i++)
      kvmap_put_entry(&(map->mm), &(leaf->eh[i]), NULL);
    slab_free(map->slab_leaf, leaf);
    leaf = next;
  }
  map->leaf0 = NULL;
}

// unsafe
  void
wormhole_clean(struct wormhole * const map)
{
  wormhole_clean1(map);
  wormhole_create_leaf0(map);
}

  void
wormhole_destroy(struct wormhole * const map)
{
  //wormhole_verify(map);
  wormhole_clean1(map);
  for (u64 x = 0; x < 2; x++)
    wormhole_hmap_deinit(&(map->hmap2[x]));
  qsbr_destroy(map->qsbr);
  slab_destroy(map->slab_leaf);
  free(map);
}
// }}} misc

// }}} wormhole
