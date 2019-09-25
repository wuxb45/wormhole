/*
 * Copyright (c) 2016--2018  Wu, Xingbo <wuxb45@gmail.com>
 *
 * All rights reserved. No warranty, explicit or implicit, provided.
 */
#pragma once
#ifdef __cplusplus
extern "C" {
#endif

// includes {{{
// C headers
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// POSIX headers
#include <unistd.h>
#include <pthread.h>

// Linux headers
#include <sys/mman.h>
#include <sys/resource.h>
// }}} includes

// types {{{
typedef uint_least8_t           u8;
typedef uint_least16_t          u16;
typedef uint_least32_t          u32;
typedef uint_least64_t          u64;
// }}} types

// locks {{{
typedef struct __spinlock {
  union {
    u16 var;
    u64 padding;
  };
} spinlock;

  extern void
spinlock_init(spinlock * const lock);

  extern bool
spinlock_trylock_nr(spinlock * const lock, u64 nr);

  extern void
spinlock_lock(spinlock * const lock);

  extern void
spinlock_unlock(spinlock * const lock);

typedef struct __rwlock {
  union {
    u16 var;
    u64 padding;
  };
} rwlock;

  extern void
rwlock_init(rwlock * const lock);

  extern bool
rwlock_trylock_read(rwlock * const lock);

  extern bool
rwlock_trylock_read_nr(rwlock * const lock, u64 nr);

  extern void
rwlock_lock_read(rwlock * const lock);

  extern void
rwlock_unlock_read(rwlock * const lock);

  extern bool
rwlock_trylock_write(rwlock * const lock);

  extern bool
rwlock_trylock_write_nr(rwlock * const lock, u64 nr);

  extern void
rwlock_lock_write(rwlock * const lock);

  extern void
rwlock_unlock_write(rwlock * const lock);

  extern void
rwlock_write_to_read(rwlock * const lock);
// }}} locks

// timing {{{
  extern u64
rdtsc(void);

  extern u64
time_nsec(void);

  extern double
time_sec(void);

  extern double
time_diff_sec(const double last);
// }}} timing

// debug {{{
  extern void
debug_break(void);

  extern void
debug_backtrace(void);

  extern void
debug_wait_gdb(void);

#ifndef NDEBUG
  extern void
debug_assert(const bool v);
#else
#define debug_assert(expr) ((void)0)
#endif

  extern void
debug_die(void);
// }}} debug

// process/thread {{{
  extern u64
process_affinity_core_count(void);

  extern double
thread_fork_join_private(const u64 nr, void *(*func) (void *), void * const * const argv);

  extern double
thread_fork_join(const u64 nr, void *(*func) (void *), void * const arg);
// }}} process/thread

// mm {{{
  extern void *
yalloc(const u64 size);

/* hugepages */
// force posix allocators: -DVALGRIND_MEMCHECK
  extern void *
pages_alloc_4kb(const size_t nr_4kb);

  extern void *
pages_alloc_2mb(const size_t nr_2mb);

  extern void *
pages_alloc_1gb(const size_t nr_1gb);

  extern void *
pages_alloc_best(const size_t size, const bool try_1gb, u64 * const size_out);

  extern void
pages_unmap(void * const ptr, const size_t size);
// }}} mm

// cpucache {{{
  extern void
cpu_cfence(void);
// }}} cpucache

// qsbr {{{
struct qsbr;

  extern void
qsbr_init(struct qsbr * const q);

  extern struct qsbr *
qsbr_create(void);

  extern bool
qsbr_register(struct qsbr * const q, volatile u64 * const ptr);

  extern void
qsbr_unregister(struct qsbr * const q, volatile u64 * const ptr);

  extern void
qsbr_wait(struct qsbr * const q, const u64 target);

  extern void
qsbr_destroy(struct qsbr * const q);
// }}} qsbr

// hash {{{
  extern u32
crc32c(const void * const ptr, const size_t size);
// }}} hash

// kv {{{
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
  u64 hash; // hashvalue of the key
  u8 kv[];  // len(kv) == klen + vlen
} __attribute__((packed));

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
kv_refill(struct kv * const kv, const void * const key, const u32 klen, const void * const value, const u32 vlen);

  extern void
kv_refill_str(struct kv * const kv, const char * const key, const char * const value);

  extern struct kv *
kv_create(const void * const key, const u32 klen, const void * const value, const u32 vlen);

  extern struct kv *
kv_create_str(const char * const key, const char * const value);

  extern struct kv *
kv_dup(const struct kv * const kv);

  extern struct kv *
kv_dup_key(const struct kv * const kv);

  extern struct kv *
kv_dup2(const struct kv * const from, struct kv * const to);

  extern struct kv *
kv_dup2_key(const struct kv * const from, struct kv * const to);

  extern struct kv *
kv_dup2_key_prefix(const struct kv * const from, struct kv * const to, const u64 plen);

  extern struct kv *
kv_alloc_malloc(const u64 size, void * const priv);

  extern void
kv_retire_free(struct kv * const kv, void * const priv);

  extern bool
kv_keymatch(const struct kv * const key1, const struct kv * const key2);

  extern bool
kv_keymatch_r(const struct kv * const key1, const struct kv * const key2);

  extern bool
kv_fullmatch(const struct kv * const kv1, const struct kv * const kv2);

typedef int  (*kv_compare_func)(const struct kv * const kv1, const struct kv * const kv2);

  extern int
kv_keycompare(const struct kv * const kv1, const struct kv * const kv2);

  extern void
kv_qsort(const struct kv ** const kvs, const size_t nr);

  extern void *
kv_value_ptr(struct kv * const kv);

  extern void *
kv_key_ptr(struct kv * const kv);

  extern const void *
kv_value_ptr_const(const struct kv * const kv);

  extern const void *
kv_key_ptr_const(const struct kv * const kv);

  extern u32
kv_key_lcp(const struct kv * const key1, const struct kv * const key2);

  extern bool
kv_key_is_prefix(const struct kv * const p, const struct kv * const key);

  extern void
kv_print(const struct kv * const kv, const char * const cmd, FILE * const out);
// }}} kv

// kvmap {{{
typedef struct kv * (* kv_alloc_func)(const u64, void * const);

typedef void (* kv_retire_func)(struct kv * const, void * const);

struct kvmap_mm {
  kv_alloc_func af;
  void * ap;
  kv_retire_func rf;
  void * rp;
};
// }}} kvmap

// wormhole {{{
struct wormhole;
struct wormref;

  extern struct wormhole *
wormhole_create(const struct kvmap_mm * const mm);

  extern struct kv *
wormhole_get(struct wormref * const ref, const struct kv * const key, struct kv * const out);

  extern bool
wormhole_probe(struct wormref * const ref, const struct kv * const key);

  extern bool
wormhole_set(struct wormref * const ref, const struct kv * const kv);

  extern bool
wormhole_del(struct wormref * const ref, const struct kv * const key);

  extern struct wormref *
wormhole_ref(struct wormhole * const map);

  extern struct wormhole *
wormhole_unref(struct wormref * const ref);

  extern void
wormhole_clean(struct wormhole * const map);

  extern void
wormhole_destroy(struct wormhole * const map);

  extern struct wormhole_iter *
wormhole_iter_create(struct wormref * const ref);

  extern void
wormhole_iter_seek(struct wormhole_iter * const iter, const struct kv * const key);

  extern void
wormhole_iter_seek_unsafe(struct wormhole_iter * const iter, const struct kv * const key);

  extern struct kv *
wormhole_iter_next(struct wormhole_iter * const iter, struct kv * const out);

  extern struct kv *
wormhole_iter_next_unsafe(struct wormhole_iter * const iter, struct kv * const out);

  extern void
wormhole_iter_destroy(struct wormhole_iter * const iter);

  extern void
wormhole_iter_destroy_unsafe(struct wormhole_iter * const iter);

// the unsafe API

  extern struct kv *
wormhole_get_unsafe(struct wormhole * const map, const struct kv * const key, struct kv * const out);

  extern bool
wormhole_probe_unsafe(struct wormhole * const map, const struct kv * const key);

  extern bool
wormhole_set_unsafe(struct wormhole * const map, const struct kv * const kv0);

  extern bool
wormhole_del_unsafe(struct wormhole * const map, const struct kv * const key);
// }}} wormhole

#ifdef __cplusplus
}
#endif
// vim:fdm=marker
