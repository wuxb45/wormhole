/*
 * Copyright (c) 2016--2020  Wu, Xingbo <wuxb45@gmail.com>
 *
 * All rights reserved. No warranty, explicit or implicit, provided.
 */
#pragma once
#ifdef __cplusplus
extern "C" {
#endif

// kv {{{
/*
 * Some internal union names can be ignored:
 * struct kv {
 *   u32 klen;
 *   u32 vlen;
 *   u64 hash;
 *   u8 kv[];
 * };
 */
struct kv {
  union { // the first u64
    u64 kvlen;
    struct {
      u32 klen;
      union {
        u32 vlen;
        u32 refcnt;
      };
    };
  };
  union {
    u64 hash; // hashvalue of the key
    u64 priv; // can hide a value here if hash is not used
    struct {
      u32 hashlo; // little endian
      u32 hashhi;
    };
  };
  u8 kv[];  // len(kv) == klen + vlen
} __attribute__((packed));

struct kref {
  u32 len;
  union {
    u32 hash32;
    u32 priv;
  };
  const u8 * ptr;
} __attribute__((packed));


typedef int  (*kv_kv_cmp_func)(const struct kv *, const struct kv *);

  extern size_t
kv_size(const struct kv * const kv);

  extern size_t
kv_size_align(const struct kv * const kv, const u64 align);

  extern size_t
key_size(const struct kv * const key);

  extern size_t
key_size_align(const struct kv * const key, const u64 align);

  extern void
kv_update_hash(struct kv * const kv);

  extern void
kv_refill(struct kv * const kv, const void * const key, const u32 klen,
    const void * const value, const u32 vlen);

  extern void
kv_refill_str(struct kv * const kv, const char * const key,
    const void * const value, const u32 vlen);

  extern void
kv_refill_str_str(struct kv * const kv, const char * const key,
    const char * const value);

// the u64 key is filled in big-endian byte order
  extern void
kv_refill_u64(struct kv * const kv, const u64 key, const void * const value, const u32 vlen);

  extern void
kv_refill_kref(struct kv * const kv, const struct kref * const kref);

  extern void
kv_refill_kref_v(struct kv * const kv, const struct kref * const kref,
    const void * const value, const u32 vlen);

  extern struct kref
kv_ref(const struct kv * const key);

  extern struct kv *
kv_create(const void * const key, const u32 klen, const void * const value, const u32 vlen);

  extern struct kv *
kv_create_str(const char * const key, const void * const value, const u32 vlen);

  extern struct kv *
kv_create_str_str(const char * const key, const char * const value);

// a static kv with klen == 0
  extern const struct kv *
kv_null(void);

  extern struct kv *
kv_dup(const struct kv * const kv);

  extern struct kv *
kv_dup_key(const struct kv * const kv);

  extern struct kv *
kv_dup2(const struct kv * const from, struct kv * const to);

  extern struct kv *
kv_dup2_key(const struct kv * const from, struct kv * const to);

  extern struct kv *
kv_dup2_key_prefix(const struct kv * const from, struct kv * const to, const u32 plen);

  extern bool
kv_match(const struct kv * const key1, const struct kv * const key2);

  extern bool
kv_match_full(const struct kv * const kv1, const struct kv * const kv2);

  extern int
kv_compare(const struct kv * const kv1, const struct kv * const kv2);

  extern int
kv_compare_k128(const struct kv * const sk, const u8 * const k128);

  extern int
kv_compare_kv128(const struct kv * const sk, const u8 * const kv128);

  extern void
kv_qsort(struct kv ** const kvs, const size_t nr);

  extern u32
kv_key_lcp(const struct kv * const key1, const struct kv * const key2);

  extern void *
kv_vptr(struct kv * const kv);

  extern void *
kv_kptr(struct kv * const kv);

  extern const void *
kv_vptr_c(const struct kv * const kv);

  extern const void *
kv_kptr_c(const struct kv * const kv);

  extern void
kv_print(const struct kv * const kv, const char * const cmd, FILE * const out);

typedef struct kv * (* kvmap_mm_in_func)(struct kv * kv, void * priv);
typedef struct kv * (* kvmap_mm_out_func)(struct kv * kv, struct kv * out);
typedef void        (* kvmap_mm_free_func)(struct kv * kv, void * priv);

// manage internal kv data of kvmap
struct kvmap_mm {
  // to create a private copy of "kv"
  // see set() functions
  kvmap_mm_in_func in;
  // to duplicate a private copy of "kv" to "out"
  // see get() and iter_peek() functions
  kvmap_mm_out_func out;
  // to free an a private kv
  // see del() and set() functions
  kvmap_mm_free_func free;
  void * priv;
};

  extern struct kv *
kvmap_mm_in_noop(struct kv * const kv, void * const priv);

  extern struct kv *
kvmap_mm_out_noop(struct kv * const kv, struct kv * const out);

  extern void
kvmap_mm_free_noop(struct kv * const kv, void * const priv);

  extern struct kv *
kvmap_mm_in_dup(struct kv * const kv, void * const priv);

  extern struct kv *
kvmap_mm_out_dup(struct kv * const kv, struct kv * const out);

  extern void
kvmap_mm_free_free(struct kv * const kv, void * const priv);

// use malloc/free to copy kv
extern const struct kvmap_mm kvmap_mm_dup; // the default mm
// }}} kv

// kref {{{
typedef int (*kref_kv_cmp_func)(const struct kref *, const struct kv *);

// ptr and len only
  extern void
kref_refill_raw(struct kref * const kref, const u8 * const ptr, const u32 len);

// this calculates hash32
  extern void
kref_refill_hash32(struct kref * const kref, const u8 * const ptr, const u32 len);

  extern bool
kref_kv_match(const struct kref * const kref, const struct kv * const k);

  extern int
kref_kv_compare(const struct kref * const kref, const struct kv * const k);

  extern int
kref_k128_compare(const struct kref * const sk, const u8 * const k128);

  extern int
kref_kv128_compare(const struct kref * const sk, const u8 * const kv128);

  extern const struct kref *
kref_null(void);
// }}} kref

// kvmap {{{

// kvmap_api {{{
typedef void (* kv_inp_func)(struct kv * const curr, void * const priv);

struct kvmap_api {
  // feature bits
  bool        hashkey; // true: caller needs to provide correct hash in kv/kref
  bool        ordered; // true: has iter_seek
  bool        threadsafe; // true: support thread_safe access
  bool        readonly; // true: no set() and del()
  bool        reserved[4];

  //// thread-safe basic functions:
  // set: return true on success; false on error
  bool        (* set)     (void * const map, struct kv * const kv);
  // get: return "out" or malloc-ed kv on found
  struct kv * (* get)     (void * const map, const struct kref * const key, struct kv * const out);
  // probe: return true on found, false on not found
  bool        (* probe)   (void * const map, const struct kref * const key);
  // del: return true on something deleted, false on not found
  bool        (* del)     (void * const map, const struct kref * const key);
  // inp: inplace operation if key exists; otherwise return false
  bool        (* inp) (void * const map, const struct kref * const key, kv_inp_func uf, void * const priv);

  // create refs for maps if required
  // if there are ref/unref functions, ref-ptr should be used as map for get/probe/set/del
  // return a malloc-ed ref
  void *      (* ref)     (void * map);
  // return the original map
  void *      (* unref)   (void * ref);

  // unsafe functions:
  // turn locking on/off; returns if locking is on/off
  bool        (* locking) (void * map, const bool locking);
  // empty the map
  void        (* clean)   (void * map);
  // erase everything
  void        (* destroy) (void * map);
  // for debugging
  void        (* fprint)  (void * map, FILE * const out);

  // iter:
  // create iterator from a ref
  void *      (* iter_create)  (void * const ref);
  // move the cursor to the first key >= search-key;
  void        (* iter_seek)    (void * const iter, const struct kref * const key);
  // check if the cursor points to a valid key
  bool        (* iter_valid)   (void * const iter);
  // return the current key; copy to out if (out != NULL)
  struct kv * (* iter_peek)    (void * const iter, struct kv * const out);
  // iter_next == iter_peek + iter_skip
  struct kv * (* iter_next)    (void * const iter, struct kv * const out);
  // move the cursor to the next key
  void        (* iter_skip)    (void * const iter, const u64 nr);
  // perform inplace opeation if the current key is valid; return false if no current key
  bool        (* iter_inp)     (void * const iter, kv_inp_func uf, void * const priv);
  // destroy iter
  void        (* iter_destroy) (void * const iter);
};
// }}} kvmap_api

// helpers {{{
  extern void
kvmap_inp_steal_kv(struct kv * const kv, void * const priv);

  extern void *
kvmap_ref(const struct kvmap_api * const api, void * const map);

  extern void *
kvmap_unref(const struct kvmap_api * const api, void * const ref);

  extern struct kv *
kvmap_kv_get(const struct kvmap_api * const api, void * const map,
    const struct kv * const key, struct kv * const out);

  extern bool
kvmap_kv_probe(const struct kvmap_api * const api, void * const map,
    const struct kv * const key);

  extern bool
kvmap_kv_set(const struct kvmap_api * const api, void * const ref,
    struct kv * const kv);

  extern bool
kvmap_kv_del(const struct kvmap_api * const api, void * const map,
    const struct kv * const key);

  extern bool
kvmap_kv_inp(const struct kvmap_api * const api, void * const map,
    const struct kv * const key, kv_inp_func uf, void * const priv);

  extern void
kvmap_kv_iter_seek(const struct kvmap_api * const api, void * const iter,
    const struct kv * const key);

  extern struct kv *
kvmap_raw_get(const struct kvmap_api * const api, void * const map,
    const u32 len, const u8 * const ptr, struct kv * const out);

  extern bool
kvmap_raw_probe(const struct kvmap_api * const api, void * const map,
    const u32 len, const u8 * const ptr);

  extern bool
kvmap_raw_del(const struct kvmap_api * const api, void * const map,
    const u32 len, const u8 * const ptr);

  extern bool
kvmap_raw_inp(const struct kvmap_api * const api, void * const map,
    const u32 len, const u8 * const ptr, kv_inp_func uf, void * const priv);

  extern void
kvmap_raw_iter_seek(const struct kvmap_api * const api, void * const iter,
    const u32 len, const u8 * const ptr);
// }}} helpers

// }}} kvmap

// wormhole {{{
struct wormhole;
struct wormref;

// the wh created by wormhole_create() can work with all of safe/unsafe operations.
  extern struct wormhole *
wormhole_create(const struct kvmap_mm * const mm);

// the wh created by whunsafe_create() can only work with the unsafe operations.
  extern struct wormhole *
whunsafe_create(const struct kvmap_mm * const mm);

  extern struct kv *
wormhole_get(struct wormref * const ref, const struct kref * const key, struct kv * const out);

  extern bool
wormhole_probe(struct wormref * const ref, const struct kref * const key);

  extern bool
wormhole_set(struct wormref * const ref, struct kv * const kv);

  extern bool
wormhole_inp(struct wormref * const ref, const struct kref * const key,
    kv_inp_func uf, void * const priv);

  extern bool
wormhole_del(struct wormref * const ref, const struct kref * const key);

  extern struct wormhole_iter *
wormhole_iter_create(struct wormref * const ref);

  extern void
wormhole_iter_seek(struct wormhole_iter * const iter, const struct kref * const key);

  extern bool
wormhole_iter_valid(struct wormhole_iter * const iter);

  extern struct kv *
wormhole_iter_peek(struct wormhole_iter * const iter, struct kv * const out);

  extern void
wormhole_iter_skip(struct wormhole_iter * const iter, const u64 nr);

  extern struct kv *
wormhole_iter_next(struct wormhole_iter * const iter, struct kv * const out);

  extern bool
wormhole_iter_inp(struct wormhole_iter * const iter, kv_inp_func uf, void * const priv);

  extern void
wormhole_iter_destroy(struct wormhole_iter * const iter);

  extern struct wormref *
wormhole_ref(struct wormhole * const map);

  extern struct wormhole *
wormhole_unref(struct wormref * const ref);

  extern void
wormhole_refresh_qstate(struct wormref * const ref);

  extern void
wormhole_clean(struct wormhole * const map);

  extern void
wormhole_destroy(struct wormhole * const map);

// unsafe API

  extern struct kv *
whunsafe_get(struct wormhole * const map, const struct kref * const key, struct kv * const out);

  extern bool
whunsafe_probe(struct wormhole * const map, const struct kref * const key);

  extern bool
whunsafe_set(struct wormhole * const map, struct kv * const kv);

  extern bool
whunsafe_inp(struct wormhole * const map, const struct kref * const key,
    kv_inp_func uf, void * const priv);

  extern bool
whunsafe_del(struct wormhole * const map, const struct kref * const key);

  extern struct wormhole_iter *
whunsafe_iter_create(struct wormhole * const map);

  extern void
whunsafe_iter_seek(struct wormhole_iter * const iter, const struct kref * const key);

  extern bool
whunsafe_iter_valid(struct wormhole_iter * const iter);

  extern struct kv *
whunsafe_iter_peek(struct wormhole_iter * const iter, struct kv * const out);

  extern void
whunsafe_iter_skip(struct wormhole_iter * const iter, const u64 nr);

  extern struct kv *
whunsafe_iter_next(struct wormhole_iter * const iter, struct kv * const out);

  extern bool
whunsafe_iter_inp(struct wormhole_iter * const iter, kv_inp_func uf, void * const priv);

  extern void
whunsafe_iter_destroy(struct wormhole_iter * const iter);

  extern void
wormhole_fprint(struct wormhole * const map, FILE * const out);
// }}} wormhole

// kvmap_api {{{
extern const struct kvmap_api kvmap_api_wormhole;
extern const struct kvmap_api kvmap_api_whunsafe;

  extern void
kvmap_api_helper_message(void);

  extern int
kvmap_api_helper(int argc, char ** const argv,
    const struct kvmap_mm * const mm, const bool map_locking,
    const struct kvmap_api ** const api_out, void ** const map_out);
// }}} kvmap_api

#ifdef __cplusplus
}
#endif
// vim:fdm=marker
