/*
 * Copyright (c) 2016--2021  Wu, Xingbo <wuxb45@gmail.com>
 *
 * All rights reserved. No warranty, explicit or implicit, provided.
 */
#define _GNU_SOURCE

// headers {{{
#include <assert.h> // static_assert
#include <ctype.h>
#include "lib.h"
#include "ctypes.h"
#include "kv.h"
// }}} headers

// crc32c {{{
  inline u32
kv_crc32c(const void * const ptr, u32 len)
{
  return crc32c_inc((const u8 *)ptr, len, KV_CRC32C_SEED);
}

  inline u64
kv_crc32c_extend(const u32 lo)
{
  const u64 hi = (u64)(~lo);
  return (hi << 32) | ((u64)lo);
}
// }}} crc32c

// kv {{{

// size {{{
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
// }}} size

// construct {{{
  inline void
kv_update_hash(struct kv * const kv)
{
  const u32 lo = kv_crc32c((const void *)kv->kv, kv->klen);
  kv->hash = kv_crc32c_extend(lo);
}

  inline void
kv_refill_value(struct kv * const kv, const void * const value, const u32 vlen)
{
  debug_assert((vlen == 0) || value);
  memcpy(&(kv->kv[kv->klen]), value, vlen);
  kv->vlen = vlen;
}

  inline void
kv_refill(struct kv * const kv, const void * const key, const u32 klen,
    const void * const value, const u32 vlen)
{
  debug_assert(kv);
  kv->klen = klen;
  memcpy(&(kv->kv[0]), key, klen);
  kv_refill_value(kv, value, vlen);
  kv_update_hash(kv);
}

  inline void
kv_refill_str(struct kv * const kv, const char * const key,
    const void * const value, const u32 vlen)
{
  kv_refill(kv, key, (u32)strlen(key), value, vlen);
}

  inline void
kv_refill_str_str(struct kv * const kv, const char * const key,
    const char * const value)
{
  kv_refill(kv, key, (u32)strlen(key), value, (u32)strlen(value));
}

// the u64 key is filled in big-endian byte order for correct ordering
  inline void
kv_refill_u64(struct kv * const kv, const u64 key, const void * const value, const u32 vlen)
{
  kv->klen = sizeof(u64);
  *(u64 *)(kv->kv) = __builtin_bswap64(key); // bswap on little endian
  kv_refill_value(kv, value, vlen);
  kv_update_hash(kv);
}

  inline void
kv_refill_hex32(struct kv * const kv, const u32 hex, const void * const value, const u32 vlen)
{
  kv->klen = 8;
  strhex_32(kv->kv, hex);
  kv_refill_value(kv, value, vlen);
  kv_update_hash(kv);
}

  inline void
kv_refill_hex64(struct kv * const kv, const u64 hex, const void * const value, const u32 vlen)
{
  kv->klen = 16;
  strhex_64(kv->kv, hex);
  kv_refill_value(kv, value, vlen);
  kv_update_hash(kv);
}

  inline void
kv_refill_hex64_klen(struct kv * const kv, const u64 hex,
    const u32 klen, const void * const value, const u32 vlen)
{
  strhex_64(kv->kv, hex);
  if (klen > 16) {
    kv->klen = klen;
    memset(kv->kv + 16, '!', klen - 16);
  } else {
    kv->klen = 16;
  }
  kv_refill_value(kv, value, vlen);
  kv_update_hash(kv);
}

  inline void
kv_refill_kref(struct kv * const kv, const struct kref * const kref)
{
  kv->klen = kref->len;
  kv->vlen = 0;
  kv->hash = kv_crc32c_extend(kref->hash32);
  memmove(kv->kv, kref->ptr, kref->len);
}

  inline void
kv_refill_kref_v(struct kv * const kv, const struct kref * const kref,
    const void * const value, const u32 vlen)
{
  kv->klen = kref->len;
  kv->vlen = vlen;
  kv->hash = kv_crc32c_extend(kref->hash32);
  memmove(kv->kv, kref->ptr, kref->len);
  memcpy(kv->kv + kv->klen, value, vlen);
}

  inline struct kref
kv_kref(const struct kv * const key)
{
  return (struct kref){.ptr = key->kv, .len = key->klen, .hash32 = key->hashlo};
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
kv_create_str(const char * const key, const void * const value, const u32 vlen)
{
  return kv_create(key, (u32)strlen(key), value, vlen);
}

  inline struct kv *
kv_create_str_str(const char * const key, const char * const value)
{
  return kv_create(key, (u32)strlen(key), value, (u32)strlen(value));
}

  inline struct kv *
kv_create_kref(const struct kref * const kref, const void * const value, const u32 vlen)
{
  return kv_create(kref->ptr, kref->len, value, vlen);
}

static struct kv __kv_null = {};

__attribute__((constructor))
  static void
kv_null_init(void)
{
  kv_update_hash(&__kv_null);
}

  inline const struct kv *
kv_null(void)
{
  return &__kv_null;
}
// }}} construct

// dup {{{
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
  if (new) {
    memcpy(new, kv, sz);
    new->vlen = 0;
  }
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
kv_dup2_key_prefix(const struct kv * const from, struct kv * const to, const u32 plen)
{
  if (from == NULL)
    return NULL;
  debug_assert(plen <= from->klen);
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
// }}} dup

// compare {{{
  static inline int
klen_compare(const u32 len1, const u32 len2)
{
  if (len1 < len2)
    return -1;
  else if (len1 > len2)
    return 1;
  else
    return 0;
}

// compare whether the two keys are identical
// optimistic: do not check hash
  inline bool
kv_match(const struct kv * const key1, const struct kv * const key2)
{
  //cpu_prefetch0(((u8 *)key2) + 64);
  //return (key1->hash == key2->hash)
  //  && (key1->klen == key2->klen)
  //  && (!memcmp(key1->kv, key2->kv, key1->klen));
  return (key1->klen == key2->klen) && (!memcmp(key1->kv, key2->kv, key1->klen));
}

// compare whether the two keys are identical
// check hash first
// pessimistic: return false quickly if their hashes mismatch
  inline bool
kv_match_hash(const struct kv * const key1, const struct kv * const key2)
{
  return (key1->hash == key2->hash)
    && (key1->klen == key2->klen)
    && (!memcmp(key1->kv, key2->kv, key1->klen));
}

  inline bool
kv_match_full(const struct kv * const kv1, const struct kv * const kv2)
{
  return (kv1->kvlen == kv2->kvlen)
    && (!memcmp(kv1, kv2, sizeof(*kv1) + kv1->klen + kv1->vlen));
}

  bool
kv_match_kv128(const struct kv * const sk, const u8 * const kv128)
{
  debug_assert(sk);
  debug_assert(kv128);

  u32 klen128 = 0;
  u32 vlen128 = 0;
  const u8 * const pdata = vi128_decode_u32(vi128_decode_u32(kv128, &klen128), &vlen128);
  (void)vlen128;
  return (sk->klen == klen128) && (!memcmp(sk->kv, pdata, klen128));
}

  inline int
kv_compare(const struct kv * const kv1, const struct kv * const kv2)
{
  const u32 len = kv1->klen < kv2->klen ? kv1->klen : kv2->klen;
  const int cmp = memcmp(kv1->kv, kv2->kv, (size_t)len);
  return cmp ? cmp : klen_compare(kv1->klen, kv2->klen);
}

// for qsort and bsearch
  static int
kv_compare_ptrs(const void * const p1, const void * const p2)
{
  const struct kv * const * const pp1 = (typeof(pp1))p1;
  const struct kv * const * const pp2 = (typeof(pp2))p2;
  return kv_compare(*pp1, *pp2);
}

  int
kv_k128_compare(const struct kv * const sk, const u8 * const k128)
{
  debug_assert(sk);
  const u32 klen1 = sk->klen;
  u32 klen2 = 0;
  const u8 * const ptr2 = vi128_decode_u32(k128, &klen2);
  debug_assert(ptr2);
  const u32 len = (klen1 < klen2) ? klen1 : klen2;
  const int cmp = memcmp(sk->kv, ptr2, len);
  return cmp ? cmp : klen_compare(klen1, klen2);
}

  int
kv_kv128_compare(const struct kv * const sk, const u8 * const kv128)
{
  debug_assert(sk);
  const u32 klen1 = sk->klen;
  u32 klen2 = 0;
  u32 vlen2 = 0;
  const u8 * const ptr2 = vi128_decode_u32(vi128_decode_u32(kv128, &klen2), &vlen2);
  const u32 len = (klen1 < klen2) ? klen1 : klen2;
  const int cmp = memcmp(sk->kv, ptr2, len);
  return cmp ? cmp : klen_compare(klen1, klen2);
}

  inline void
kv_qsort(struct kv ** const kvs, const size_t nr)
{
  qsort(kvs, nr, sizeof(kvs[0]), kv_compare_ptrs);
}

// return the length of longest common prefix of the two keys
  inline u32
kv_key_lcp(const struct kv * const key1, const struct kv * const key2)
{
  const u32 max = (key1->klen < key2->klen) ? key1->klen : key2->klen;
  return memlcp(key1->kv, key2->kv, max);
}

// return the length of longest common prefix of the two keys with a known lcp0
  inline u32
kv_key_lcp_skip(const struct kv * const key1, const struct kv * const key2, const u32 lcp0)
{
  const u32 max = (key1->klen < key2->klen) ? key1->klen : key2->klen;
  debug_assert(max >= lcp0);
  return lcp0 + memlcp(key1->kv+lcp0, key2->kv+lcp0, max-lcp0);
}
// }}}

// psort {{{
  static inline void
kv_psort_exchange(struct kv ** const kvs, const u64 i, const u64 j)
{
  if (i != j) {
    struct kv * const tmp = kvs[i];
    kvs[i] = kvs[j];
    kvs[j] = tmp;
  }
}

  static u64
kv_psort_partition(struct kv ** const kvs, const u64 lo, const u64 hi)
{
  if (lo >= hi)
    return lo;

  const u64 p = (lo+hi) >> 1;
  kv_psort_exchange(kvs, lo, p);
  u64 i = lo;
  u64 j = hi + 1;
  do {
    while (kv_compare(kvs[++i], kvs[lo]) < 0 && i < hi);
    while (kv_compare(kvs[--j], kvs[lo]) > 0);
    if (i >= j)
      break;
    kv_psort_exchange(kvs, i, j);
  } while (true);
  kv_psort_exchange(kvs, lo, j);
  return j;
}

  static void
kv_psort_rec(struct kv ** const kvs, const u64 lo, const u64 hi, const u64 tlo, const u64 thi)
{
  if (lo >= hi)
    return;
  const u64 c = kv_psort_partition(kvs, lo, hi);

  if (c > tlo) // go left
    kv_psort_rec(kvs, lo, c-1, tlo, thi);

  if (c < thi) // go right
    kv_psort_rec(kvs, c+1, hi, tlo, thi);
}

  inline void
kv_psort(struct kv ** const kvs, const u64 nr, const u64 tlo, const u64 thi)
{
  debug_assert(tlo <= thi);
  debug_assert(thi < nr);
  kv_psort_rec(kvs, 0, nr-1, tlo, thi);
}
// }}} psort

// ptr {{{
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
// }}} ptr

// print {{{
// cmd "KV" K and V can be 's': string, 'x': hex, 'd': dec, or else for not printing.
// n for newline after kv
  void
kv_print(const struct kv * const kv, const char * const cmd, FILE * const out)
{
  debug_assert(cmd);
  const u32 klen = kv->klen;
  fprintf(out, "#%016lx k[%3u]", kv->hash, klen);

  switch(cmd[0]) {
  case 's': fprintf(out, " %.*s", klen, kv->kv); break;
  case 'x': str_print_hex(out, kv->kv, klen); break;
  case 'd': str_print_dec(out, kv->kv, klen); break;
  default: break;
  }

  const u32 vlen = kv->vlen;
  switch (cmd[1]) {
  case 's': fprintf(out, "  v[%4u] %.*s", vlen, vlen, kv->kv+klen); break;
  case 'x': fprintf(out, "  v[%4u]", vlen); str_print_hex(out, kv->kv+klen, vlen); break;
  case 'd': fprintf(out, "  v[%4u]", vlen); str_print_dec(out, kv->kv+klen, vlen); break;
  default: break;
  }
  if (strchr(cmd, 'n'))
    fprintf(out, "\n");
}
// }}} print

// mm {{{
  struct kv *
kvmap_mm_in_noop(struct kv * const kv, void * const priv)
{
  (void)priv;
  return kv;
}

// copy-out
  struct kv *
kvmap_mm_out_noop(struct kv * const kv, struct kv * const out)
{
  (void)out;
  return kv;
}

  void
kvmap_mm_free_noop(struct kv * const kv, void * const priv)
{
  (void)kv;
  (void)priv;
}

// copy-in
  struct kv *
kvmap_mm_in_dup(struct kv * const kv, void * const priv)
{
  (void)priv;
  return kv_dup(kv);
}

// copy-out
  struct kv *
kvmap_mm_out_dup(struct kv * const kv, struct kv * const out)
{
  return kv_dup2(kv, out);
}

  void
kvmap_mm_free_free(struct kv * const kv, void * const priv)
{
  (void)priv;
  free(kv);
}

const struct kvmap_mm kvmap_mm_dup = {
  .in = kvmap_mm_in_dup,
  .out = kvmap_mm_out_dup,
  .free = kvmap_mm_free_free,
  .priv = NULL,
};

const struct kvmap_mm kvmap_mm_ndf = {
  .in = kvmap_mm_in_noop,
  .out = kvmap_mm_out_dup,
  .free = kvmap_mm_free_free,
  .priv = NULL,
};

// }}} mm

// kref {{{
  inline void
kref_ref_raw(struct kref * const kref, const u8 * const ptr, const u32 len)
{
  kref->ptr = ptr;
  kref->len = len;
  kref->hash32 = 0;
}

  inline void
kref_ref_hash32(struct kref * const kref, const u8 * const ptr, const u32 len)
{
  kref->ptr = ptr;
  kref->len = len;
  kref->hash32 = kv_crc32c(ptr, len);
}

  inline void
kref_update_hash32(struct kref * const kref)
{
  kref->hash32 = kv_crc32c(kref->ptr, kref->len);
}

  inline void
kref_ref_kv(struct kref * const kref, const struct kv * const kv)
{
  kref->ptr = kv->kv;
  kref->len = kv->klen;
  kref->hash32 = kv->hashlo;
}

  inline void
kref_ref_kv_hash32(struct kref * const kref, const struct kv * const kv)
{
  kref->ptr = kv->kv;
  kref->len = kv->klen;
  kref->hash32 = kv_crc32c(kv->kv, kv->klen);
}

  inline bool
kref_match(const struct kref * const k1, const struct kref * const k2)
{
  return (k1->len == k2->len) && (!memcmp(k1->ptr, k2->ptr, k1->len));
}

// match a kref and a key
  inline bool
kref_kv_match(const struct kref * const kref, const struct kv * const k)
{
  return (kref->len == k->klen) && (!memcmp(kref->ptr, k->kv, kref->len));
}

  inline int
kref_compare(const struct kref * const kref1, const struct kref * const kref2)
{
  const u32 len = kref1->len < kref2->len ? kref1->len : kref2->len;
  const int cmp = memcmp(kref1->ptr, kref2->ptr, (size_t)len);
  return cmp ? cmp : klen_compare(kref1->len, kref2->len);
}

// compare a kref and a key
  inline int
kref_kv_compare(const struct kref * const kref, const struct kv * const k)
{
  debug_assert(kref);
  debug_assert(k);
  const u32 len = kref->len < k->klen ? kref->len : k->klen;
  const int cmp = memcmp(kref->ptr, k->kv, (size_t)len);
  return cmp ? cmp : klen_compare(kref->len, k->klen);
}

  inline u32
kref_lcp(const struct kref * const k1, const struct kref * const k2)
{
  const u32 max = (k1->len < k2->len) ? k1->len : k2->len;
  return memlcp(k1->ptr, k2->ptr, max);
}

  inline u32
kref_kv_lcp(const struct kref * const kref, const struct kv * const kv)
{
  const u32 max = (kref->len < kv->klen) ? kref->len : kv->klen;
  return memlcp(kref->ptr, kv->kv, max);
}

// klen, key, ...
  inline int
kref_k128_compare(const struct kref * const sk, const u8 * const k128)
{
  debug_assert(sk);
  const u32 klen1 = sk->len;
  u32 klen2 = 0;
  const u8 * const ptr2 = vi128_decode_u32(k128, &klen2);
  debug_assert(ptr2);
  const u32 len = (klen1 < klen2) ? klen1 : klen2;
  const int cmp = memcmp(sk->ptr, ptr2, len);
  return cmp ? cmp : klen_compare(klen1, klen2);
}

// klen, vlen, key, ...
  inline int
kref_kv128_compare(const struct kref * const sk, const u8 * const kv128)
{
  debug_assert(sk);
  const u32 klen1 = sk->len;
  u32 klen2 = 0;
  u32 vlen2 = 0;
  const u8 * const ptr2 = vi128_decode_u32(vi128_decode_u32(kv128, &klen2), &vlen2);
  const u32 len = (klen1 < klen2) ? klen1 : klen2;
  const int cmp = memcmp(sk->ptr, ptr2, len);
  return cmp ? cmp : klen_compare(klen1, klen2);
}

static struct kref __kref_null = {.hash32 = KV_CRC32C_SEED};

  inline const struct kref *
kref_null(void)
{
  return &__kref_null;
}
// }}} kref

// kvref {{{
  inline void
kvref_ref_kv(struct kvref * const ref, struct kv * const kv)
{
  ref->kptr = kv->kv;
  ref->vptr = kv->kv + kv->klen;
  ref->hdr = *kv;
}

  struct kv *
kvref_dup2_kv(struct kvref * const ref, struct kv * const to)
{
  if (ref == NULL)
    return NULL;
  const size_t sz = sizeof(*to) + ref->hdr.klen + ref->hdr.vlen;
  struct kv * const new = to ? to : malloc(sz);
  if (new == NULL)
    return NULL;

  *new = ref->hdr;
  memcpy(new->kv, ref->kptr, new->klen);
  memcpy(new->kv + new->klen, ref->vptr, new->vlen);
  return new;
}

  struct kv *
kvref_dup2_key(struct kvref * const ref, struct kv * const to)
{
  if (ref == NULL)
    return NULL;
  const size_t sz = sizeof(*to) + ref->hdr.klen;
  struct kv * const new = to ? to : malloc(sz);
  if (new == NULL)
    return NULL;

  *new = ref->hdr;
  memcpy(new->kv, ref->kptr, new->klen);
  return new;
}

  int
kvref_kv_compare(const struct kvref * const ref, const struct kv * const kv)
{
  const u32 len = ref->hdr.klen < kv->klen ? ref->hdr.klen : kv->klen;
  const int cmp = memcmp(ref->kptr, kv->kv, (size_t)len);
  return cmp ? cmp : klen_compare(ref->hdr.klen, kv->klen);
}
// }}} kvref

// kv128 {{{
// estimate the encoded size
  inline size_t
kv128_estimate_kv(const struct kv * const kv)
{
  return vi128_estimate_u32(kv->klen) + vi128_estimate_u32(kv->vlen) + kv->klen + kv->vlen;
}

// create a kv128 from kv
  u8 *
kv128_encode_kv(const struct kv * const kv, u8 * const out, size_t * const pesize)
{
  u8 * const ptr = out ? out : malloc(kv128_estimate_kv(kv));
  if (!ptr)
    return NULL;

  u8 * const pdata = vi128_encode_u32(vi128_encode_u32(ptr, kv->klen), kv->vlen);
  memcpy(pdata, kv->kv, kv->klen + kv->vlen);

  if (pesize)
    *pesize = (size_t)(pdata - ptr) + kv->klen + kv->vlen;
  return ptr; // return the head of the encoded kv128
}

// dup kv128 to a kv
  struct kv *
kv128_decode_kv(const u8 * const ptr, struct kv * const out, size_t * const pesize)
{
  u32 klen, vlen;
  const u8 * const pdata = vi128_decode_u32(vi128_decode_u32(ptr, &klen), &vlen);
  struct kv * const ret = out ? out : malloc(sizeof(struct kv) + klen + vlen);
  if (ret)
    kv_refill(ret, pdata, klen, pdata + klen, vlen);

  if (pesize)
    *pesize = (size_t)(pdata - ptr) + klen + vlen;
  return ret; // return the kv
}

  inline size_t
kv128_size(const u8 * const ptr)
{
  u32 klen, vlen;
  const u8 * const pdata = vi128_decode_u32(vi128_decode_u32(ptr, &klen), &vlen);
  return ((size_t)(pdata - ptr)) + klen + vlen;
}
// }}} kv128

// }}} kv

// kvmap {{{

// registry {{{
// increase MAX if need more
#define KVMAP_API_MAX ((32))
static struct kvmap_api_reg kvmap_api_regs[KVMAP_API_MAX];
static u64 kvmap_api_regs_nr = 0;

  void
kvmap_api_register(const int nargs, const char * const name, const char * const args_msg,
    void * (*create)(const char *, const struct kvmap_mm *, char **), const struct kvmap_api * const api)
{
  if (kvmap_api_regs_nr < KVMAP_API_MAX) {
    kvmap_api_regs[kvmap_api_regs_nr].nargs = nargs;
    kvmap_api_regs[kvmap_api_regs_nr].name = name;
    kvmap_api_regs[kvmap_api_regs_nr].args_msg = args_msg;
    kvmap_api_regs[kvmap_api_regs_nr].create = create;
    kvmap_api_regs[kvmap_api_regs_nr].api = api;
    kvmap_api_regs_nr++;
  } else {
    fprintf(stderr, "%s failed to register [%s]\n", __func__, name);
  }
}
  void
kvmap_api_helper_message(void)
{
  fprintf(stderr, "%s Usage: api <map-type> <param1> ...\n", __func__);
  for (u64 i = 0; i < kvmap_api_regs_nr; i++) {
    fprintf(stderr, "%s example: api %s %s\n", __func__,
        kvmap_api_regs[i].name, kvmap_api_regs[i].args_msg);
  }
}

  int
kvmap_api_helper(int argc, char ** const argv, const struct kvmap_mm * const mm,
    const struct kvmap_api ** const api_out, void ** const map_out)
{
  // "api" "name" "arg1", ...
  if (argc < 2 || strcmp(argv[0], "api") != 0)
    return -1;

  for (u64 i = 0; i < kvmap_api_regs_nr; i++) {
    const struct kvmap_api_reg * const reg = &kvmap_api_regs[i];
    if (0 != strcmp(argv[1], reg->name))
      continue;

    if ((argc - 2) < reg->nargs)
      return -1;

    void * const map = reg->create(argv[1], mm, argv + 2); // skip "api" "name"
    if (map) {
      *api_out = reg->api;
      *map_out = map;
      return 2 + reg->nargs;
    } else {
      return -1;
    }
  }

  // no match
  return -1;
}
// }}} registry

// misc {{{
  void
kvmap_inp_steal_kv(struct kv * const kv, void * const priv)
{
  // steal the kv pointer out so we don't need a dangerous get_key_interanl()
  if (priv)
    *(struct kv **)priv = kv;
}

  inline void *
kvmap_ref(const struct kvmap_api * const api, void * const map)
{
  return api->ref ? api->ref(map) : map;
}

// return the original map pointer; usually unused by caller
  inline void *
kvmap_unref(const struct kvmap_api * const api, void * const ref)
{
  return api->unref ? api->unref(ref) : ref;
}
// }}} misc

// kvmap_kv_op {{{
  inline struct kv *
kvmap_kv_get(const struct kvmap_api * const api, void * const ref,
    const struct kv * const key, struct kv * const out)
{
  const struct kref kref = kv_kref(key);
  return api->get(ref, &kref, out);
}

  inline bool
kvmap_kv_probe(const struct kvmap_api * const api, void * const ref,
    const struct kv * const key)
{
  const struct kref kref = kv_kref(key);
  return api->probe(ref, &kref);
}

  inline bool
kvmap_kv_put(const struct kvmap_api * const api, void * const ref,
    struct kv * const kv)
{
  return api->put(ref, kv);
}

  inline bool
kvmap_kv_del(const struct kvmap_api * const api, void * const ref,
    const struct kv * const key)
{
  const struct kref kref = kv_kref(key);
  return api->del(ref, &kref);
}

  inline bool
kvmap_kv_inpr(const struct kvmap_api * const api, void * const ref,
    const struct kv * const key, kv_inp_func uf, void * const priv)
{
  const struct kref kref = kv_kref(key);
  return api->inpr(ref, &kref, uf, priv);
}

  inline bool
kvmap_kv_inpw(const struct kvmap_api * const api, void * const ref,
    const struct kv * const key, kv_inp_func uf, void * const priv)
{
  const struct kref kref = kv_kref(key);
  return api->inpw(ref, &kref, uf, priv);
}

  inline bool
kvmap_kv_merge(const struct kvmap_api * const api, void * const ref,
    const struct kv * const key, kv_merge_func uf, void * const priv)
{
  const struct kref kref = kv_kref(key);
  return api->merge(ref, &kref, uf, priv);
}

  inline u64
kvmap_kv_delr(const struct kvmap_api * const api, void * const ref,
    const struct kv * const start, const struct kv * const end)
{
  const struct kref kref0 = kv_kref(start);
  if (end) {
    const struct kref krefz = kv_kref(end);
    return api->delr(ref, &kref0, &krefz);
  } else {
    return api->delr(ref, &kref0, NULL);
  }
}

  inline void
kvmap_kv_iter_seek(const struct kvmap_api * const api, void * const iter,
    const struct kv * const key)
{
  const struct kref kref = kv_kref(key);
  api->iter_seek(iter, &kref);
}
// }}} kvmap_kv_op

// kvmap_raw_op {{{
  inline struct kv *
kvmap_raw_get(const struct kvmap_api * const api, void * const ref,
    const u32 len, const u8 * const ptr, struct kv * const out)
{
  const struct kref kref = {.ptr = ptr, .len = len,
    .hash32 = api->hashkey ? kv_crc32c(ptr, len) : 0};
  return api->get(ref, &kref, out);
}

  inline bool
kvmap_raw_probe(const struct kvmap_api * const api, void * const ref,
    const u32 len, const u8 * const ptr)
{
  const struct kref kref = {.ptr = ptr, .len = len,
    .hash32 = api->hashkey ? kv_crc32c(ptr, len) : 0};
  return api->probe(ref, &kref);
}

  inline bool
kvmap_raw_del(const struct kvmap_api * const api, void * const ref,
    const u32 len, const u8 * const ptr)
{
  const struct kref kref = {.ptr = ptr, .len = len,
    .hash32 = api->hashkey ? kv_crc32c(ptr, len) : 0};
  return api->del(ref, &kref);
}

  inline bool
kvmap_raw_inpr(const struct kvmap_api * const api, void * const ref,
    const u32 len, const u8 * const ptr, kv_inp_func uf, void * const priv)
{
  const struct kref kref = {.ptr = ptr, .len = len,
    .hash32 = api->hashkey ? kv_crc32c(ptr, len) : 0};
  return api->inpr(ref, &kref, uf, priv);
}

  inline bool
kvmap_raw_inpw(const struct kvmap_api * const api, void * const ref,
    const u32 len, const u8 * const ptr, kv_inp_func uf, void * const priv)
{
  const struct kref kref = {.ptr = ptr, .len = len,
    .hash32 = api->hashkey ? kv_crc32c(ptr, len) : 0};
  return api->inpw(ref, &kref, uf, priv);
}

  inline void
kvmap_raw_iter_seek(const struct kvmap_api * const api, void * const iter,
    const u32 len, const u8 * const ptr)
{
  const struct kref kref = {.ptr = ptr, .len = len,
    .hash32 = api->hashkey ? kv_crc32c(ptr, len) : 0};
  api->iter_seek(iter, &kref);
}
// }}}} kvmap_raw_op

// dump {{{
  u64
kvmap_dump_keys(const struct kvmap_api * const api, void * const map, const int fd)
{
  void * const ref = kvmap_ref(api, map);
  void * const iter = api->iter_create(ref);
  api->iter_seek(iter, kref_null());
  u64 i = 0;
  while (api->iter_valid(iter)) {
    struct kvref kvref;
    api->iter_kvref(iter, &kvref);
    dprintf(fd, "%010lu [%3u] %.*s [%u]\n", i, kvref.hdr.klen, kvref.hdr.klen, kvref.kptr, kvref.hdr.vlen);
    i++;
    api->iter_skip1(iter);
  }
  api->iter_destroy(iter);
  kvmap_unref(api, ref);
  return i;
}
// }}} dump

// }}} kvmap

// vim:fdm=marker
