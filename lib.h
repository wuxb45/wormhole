/*
 * Copyright (c) 2016--2020  Wu, Xingbo <wuxb45@gmail.com>
 *
 * All rights reserved. No warranty, explicit or implicit, provided.
 */
#pragma once
#ifdef __cplusplus
extern "C" {
#endif

// includes {{{
// C headers
#include <errno.h>
#include <inttypes.h>
#include <math.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// POSIX headers
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>

// Linux headers
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
// }}} includes

// types {{{
typedef int_least8_t            s8;
typedef int_least16_t           s16;
typedef int_least32_t           s32;
typedef int_least64_t           s64;
typedef __int128_t              s128;

typedef uint_least8_t           u8;
typedef uint_least16_t          u16;
typedef uint_least32_t          u32;
typedef uint_least64_t          u64;
typedef __uint128_t             u128;
// }}} types

// defs {{{
#define likely(x)   __builtin_expect(x, 1)
#define unlikely(x) __builtin_expect(x, 0)

// ansi colors
// 3X:fg; 4X:bg; 9X:light fg; 10X:light bg;
// X can be one of the following colors:
// 0:black;   1:red;     2:green;  3:yellow;
// 4:blue;    5:magenta; 6:cyan;   7:white;
#define ANSI_ESCAPE(____code____) "\x1b[" #____code____ "m"
// }}} defs

// const {{{
#define PGSZ ((4096lu))
// }}} const

// math {{{
  extern u64
mhash64(const u64 v);

  extern u32
mhash32(const u32 v);

  extern u64
gcd64(u64 a, u64 b);
// }}} math

// timing {{{
  extern u64
time_nsec(void);

  extern double
time_sec(void);

  extern u64
time_diff_nsec(const u64 last);

  extern double
time_diff_sec(const double last);

  extern void
time_stamp(char * str, const size_t size);

  extern void
time_stamp2(char * str, const size_t size);
// }}} timing

// cpucache {{{
  extern void
cpu_pause(void);

  extern void
cpu_mfence(void);

  extern void
cpu_cfence(void);

  extern void
cpu_prefetchr(const void * const ptr, const int hint);

  extern void
cpu_prefetchw(const void * const ptr);
// }}} cpucache

// crc32c {{{
  extern u32
crc32c_u8(const u32 crc, const u8 v);

  extern u32
crc32c_u16(const u32 crc, const u16 v);

  extern u32
crc32c_u32(const u32 crc, const u32 v);

  extern u32
crc32c_u64(const u32 crc, const u64 v);
// }}} crc32c

// debug {{{
  extern void
debug_break(void);

  extern void
debug_backtrace(void);

  extern void
watch_u64_usr1(u64 * const ptr);

  extern void
debug_wait_gdb(void);

#ifndef NDEBUG
  extern void
debug_assert(const bool v);
#else
#define debug_assert(expr) ((void)0)
#endif

__attribute__((noreturn))
  extern void
debug_die(void);

  extern void
debug_dump_maps(FILE * const out);

  extern bool
debug_perf_switch(void);
// }}} debug

// mm {{{
#ifdef ALLOCFAIL
  extern bool
alloc_fail(void);
#endif

  extern void *
xalloc(const u64 align, const u64 size);

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

// process/thread {{{
  extern u64
process_get_rss(void);

  extern u32
process_affinity_core_count(void);

  extern u32
process_affinity_core_list(const u32 max, u32 * const cores);

  extern u64
process_cpu_time_usec(void);

  extern void
thread_set_affinity(const u32 cpu);

// if args == true, argx is void **
// if args == false, argx is void *
  extern u64
thread_fork_join(u32 nr, void *(*func) (void *), const bool args, void * const argx);

  extern int
thread_create_at(const u32 cpu, pthread_t * const thread, void *(*start_routine) (void *), void * const arg);

  extern u32
thread_get_core(void);
// }}} process/thread

// locking {{{
typedef union {
  u64 opaque;
} spinlock;

  extern void
spinlock_init(spinlock * const lock);

  extern void
spinlock_lock(spinlock * const lock);

  extern bool
spinlock_trylock(spinlock * const lock);

  extern bool
spinlock_trylock_nr(spinlock * const lock, u16 nr);

  extern void
spinlock_unlock(spinlock * const lock);

typedef union {
  u32 opaque;
} rwlock;

  extern void
rwlock_init(rwlock * const lock);

  extern bool
rwlock_trylock_read(rwlock * const lock);

  extern bool
rwlock_trylock_read_nr(rwlock * const lock, u16 nr);

  extern void
rwlock_lock_read(rwlock * const lock);

  extern void
rwlock_unlock_read(rwlock * const lock);

  extern bool
rwlock_trylock_write(rwlock * const lock);

  extern bool
rwlock_trylock_write_nr(rwlock * const lock, u16 nr);

  extern void
rwlock_lock_write(rwlock * const lock);

  extern void
rwlock_unlock_write(rwlock * const lock);

  extern void
rwlock_write_to_read(rwlock * const lock);

typedef union {
  u64 opqaue[8];
} mutex;

  extern void
mutex_init(mutex * const lock);

  extern void
mutex_lock(mutex * const lock);

  extern bool
mutex_trylock(mutex * const lock);

  extern void
mutex_unlock(mutex * const lock);
// }}} locking

// coroutine {{{
#if defined(__x86_64__)

extern u64 co_switch_stack(u64 * const saversp, const u64 newrsp, const u64 retval);

struct co;

  extern struct co *
co_create(const u64 stacksize, void * func, void * priv, u64 * const host);

  extern void
co_reuse(struct co * const co, void * func, void * priv, u64 * const host);

  extern struct co *
co_fork(void * func, void * priv);

  extern void *
co_priv(void);

  extern u64
co_enter(struct co * const to, const u64 retval);

  extern u64
co_switch_to(struct co * const to, const u64 retval);

  extern u64
co_back(const u64 retval);

  extern void
co_exit(const u64 retval);

  extern bool
co_valid(struct co * const co);

  extern struct co *
co_self(void);

  extern void
co_destroy(struct co * const co);

struct corr;

  extern struct corr *
corr_create(const u64 stacksize, void * func, void * priv, u64 * const host);

  extern struct corr *
corr_link(const u64 stacksize, void * func, void * priv, struct corr * const prev);

  extern void
corr_reuse(struct corr * const co, void * func, void * priv, u64 * const host);

  extern void
corr_relink(struct corr * const co, void * func, void * priv, struct corr * const prev);

  extern void
corr_enter(struct corr * const co);

  extern void
corr_yield(void);

  extern void
corr_exit(void);

  extern void
corr_destroy(struct corr * const co);

#endif // __x86_64__
// }}} coroutine

// bits {{{
  extern u32
bits_reverse_u32(const u32 v);

  extern u64
bits_reverse_u64(const u64 v);

  extern u64
bits_rotl_u64(const u64 v, const u64 n);

  extern u64
bits_rotr_u64(const u64 v, const u64 n);

  extern u32
bits_rotl_u32(const u32 v, const u64 n);

  extern u32
bits_rotr_u32(const u32 v, const u64 n);

  extern u64
bits_p2_up_u64(const u64 v);

  extern u32
bits_p2_up_u32(const u32 v);

  extern u64
bits_p2_down(const u64 v);

  extern u64
bits_round_up(const u64 v, const u8 power);

  extern u64
bits_round_up_a(const u64 v, const u64 a);

  extern u32
vi128_estimate(const u64 v);

  extern u8 *
vi128_encode_u64(u8 * dst, u64 v);

  extern u8 *
vi128_encode_u32(u8 * dst, u32 v);

  extern const u8 *
vi128_decode_u64(const u8 * src, u64 * const out);

  extern const u8 *
vi128_decode_u32(const u8 * src, u32 * const out);
// }}} bits

// bitmap {{{
struct bitmap;

  extern struct bitmap *
bitmap_create(const u64 bits);

  extern bool
bitmap_test(const struct bitmap * const bm, const u64 idx);

  extern bool
bitmap_test_all1(struct bitmap * const bm);

  extern bool
bitmap_test_all0(struct bitmap * const bm);

  extern void
bitmap_set1(struct bitmap * const bm, const u64 idx);

  extern void
bitmap_set0(struct bitmap * const bm, const u64 idx);

  extern u64
bitmap_count(struct bitmap * const bm);

  extern void
bitmap_set_all1(struct bitmap * const bm);

  extern void
bitmap_set_all0(struct bitmap * const bm);

  extern void
bitmap_static_init(struct bitmap * const bm, const u64 bits);
// }}} bitmap

// bloom filter {{{
struct bf;

  extern struct bf *
bf_create(const u64 bpk, const u64 capacity);

  extern void
bf_add(struct bf * const bf, u64 hash64);

  extern bool
bf_test(const struct bf * const bf, u64 hash64);

  extern void
bf_clean(struct bf * const bf);

  extern void
bf_destroy(struct bf * const bf);
// }}} bloom filter

// slab {{{
struct slab;

  extern struct slab *
slab_create(const u64 obj_size, const u64 blk_size);

  extern bool
slab_reserve_unsafe(struct slab * const slab, const u64 nr);

  extern void *
slab_alloc_unsafe(struct slab * const slab);

  extern void *
slab_alloc(struct slab * const slab);

  extern void
slab_free_unsafe(struct slab * const slab, void * const ptr);

  extern void
slab_free(struct slab * const slab, void * const ptr);

  extern u64
slab_get_inuse(struct slab * const slab);

  extern u64
slab_get_ready(struct slab * const slab);

  extern void
slab_destroy(struct slab * const slab);
// }}}  slab

// qsort {{{
  extern void
qsort_u16(u16 * const array, const size_t nr);

  extern u16 *
bsearch_u16(const u16 v, const u16 * const array, const size_t nr);

  extern void
shuffle_u16(u16 * const array, const u64 nr);

  extern void
qsort_u32(u32 * const array, const size_t nr);

  extern u32 *
bsearch_u32(const u32 v, const u32 * const array, const size_t nr);

  extern void
shuffle_u32(u32 * const array, const u64 nr);

  extern void
qsort_u64(u64 * const array, const size_t nr);

  extern u64 *
bsearch_u64(const u64 v, const u64 * const array, const size_t nr);

  extern void
shuffle_u64(u64 * const array, const u64 nr);

  extern void
qsort_double(double * const array, const size_t nr);

  extern void
qsort_u64_sample(const u64 * const array0, const u64 nr, const u64 res, FILE * const out);

  extern void
qsort_double_sample(const double * const array0, const u64 nr, const u64 res, FILE * const out);
// }}} qsort

// xlog {{{
struct xlog;

  extern struct xlog *
xlog_create(const u64 nr_init, const u64 unit_size);

  extern void
xlog_append(struct xlog * const xlog, const void * const rec);

  extern void
xlog_append_cycle(struct xlog * const xlog, const void * const rec);

  extern void
xlog_reset(struct xlog * const xlog);

  extern u64
xlog_read(struct xlog * const xlog, void * const buf, const u64 nr_max);

  extern void
xlog_dump(struct xlog * const xlog, FILE * const out);

  extern void
xlog_destroy(struct xlog * const xlog);

struct xlog_iter;

  extern struct xlog_iter *
xlog_iter_create(const struct xlog * const xlog);

  extern bool
xlog_iter_next(struct xlog_iter * const iter, void * const out);
// free iter after use
// }}} ulog/dlog

// string {{{
// size of out should be >= 10
  extern u64
a2u64(const void * const str);

  extern u32
a2u32(const void * const str);

  extern s64
a2s64(const void * const str);

  extern s32
a2s32(const void * const str);

// user should free returned ptr after use
  extern char **
string_tokens(const char * const str, const char * const delim);
// }}} string

// damp {{{
struct damp;

  extern struct damp *
damp_create(const u64 cap, const double dshort, const double dlong);

  extern double
damp_average(const struct damp * const d);

  extern double
damp_min(const struct damp * const d);

  extern double
damp_max(const struct damp * const d);

  extern bool
damp_add_test(struct damp * const d, const double v);

  extern void
damp_clean(struct damp * const d);

  extern void
damp_destroy(struct damp * const d);
// }}} damp

// vctr {{{
struct vctr;

  extern struct vctr *
vctr_create(const size_t nr);

  extern size_t
vctr_size(struct vctr * const v);

  extern void
vctr_add(struct vctr * const v, const u64 i, const size_t n);

  extern void
vctr_add1(struct vctr * const v, const u64 i);

  extern void
vctr_add_atomic(struct vctr * const v, const u64 i, const size_t n);

  extern void
vctr_add1_atomic(struct vctr * const v, const u64 i);

  extern void
vctr_set(struct vctr * const v, const u64 i, const size_t n);

  extern size_t
vctr_get(struct vctr * const v, const u64 i);

  extern void
vctr_merge(struct vctr * const to, const struct vctr * const from);

  extern void
vctr_reset(struct vctr * const v);

  extern void
vctr_destroy(struct vctr * const v);
// }}} vctr

// rgen {{{
  extern u64
random_u64(void);

  extern void
srandom_u64(const u64 seed);

  extern double
random_double(void);

struct rgen;

typedef u64 (*rgen_next_func)(struct rgen * const);

extern struct rgen * rgen_new_const(const double percentile, const double range);
extern struct rgen * rgen_new_exp(const double percentile, const double range);
extern struct rgen * rgen_new_incs(const u64 min, const u64 max);
extern struct rgen * rgen_new_incu(const u64 min, const u64 max);
extern struct rgen * rgen_new_skips(const u64 min, const u64 max, const s64 inc);
extern struct rgen * rgen_new_skipu(const u64 min, const u64 max, const s64 inc);
extern struct rgen * rgen_new_decs(const u64 min, const u64 max);
extern struct rgen * rgen_new_decu(const u64 min, const u64 max);
extern struct rgen * rgen_new_zipfian(const u64 min, const u64 max);
extern struct rgen * rgen_new_xzipfian(const u64 min, const u64 max);
extern struct rgen * rgen_new_unizipf(const u64 min, const u64 max, const u64 ufactor);
extern struct rgen * rgen_new_uniform(const u64 min, const u64 max);
extern struct rgen * rgen_new_trace32(const char * const filename, const u64 bufsize);

  extern u64
rgen_min(struct rgen * const gen);

  extern u64
rgen_max(struct rgen * const gen);

  extern u64
rgen_next_wait(struct rgen * const gen);

  extern u64
rgen_next_nowait(struct rgen * const gen);

  extern void
rgen_destroy(struct rgen * const gen);

  extern void
rgen_helper_message(void);

  extern int
rgen_helper(const int argc, char ** const argv, struct rgen ** const gen_out);

  extern struct rgen *
rgen_dup(struct rgen * const gen0);

  extern bool
rgen_async_convert(struct rgen * const gen0, const u32 cpu);

  extern void
rgen_async_wait(struct rgen * const gen);

  extern void
rgen_async_wait_all(struct rgen * const gen);
// }}} rgen

// rcu {{{
struct rcu_node;

  extern struct rcu_node *
rcu_node_create(void);

  extern void
rcu_node_init(struct rcu_node * const node);

  extern struct rcu_node *
rcu_node_create(void);

  extern void *
rcu_node_ref(struct rcu_node * const node);

  extern void
rcu_node_unref(struct rcu_node * const node, void * const ptr);

  extern void
rcu_node_update(struct rcu_node * const node, void * const ptr);

struct rcu;

  extern void
rcu_init(struct rcu * const rcu, const u64 nr);

  extern struct rcu *
rcu_create(const u64 nr);

  extern void *
rcu_ref(struct rcu * const rcu, const u64 magic);

  extern void
rcu_unref(struct rcu * const rcu, void * const ptr, const u64 magic);

  extern void
rcu_update(struct rcu * const rcu, void * const ptr);

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
// }}} rcu

// forker {{{
#define FORKER_END_TIME ((0))
#define FORKER_END_COUNT ((1))
typedef bool (*forker_perf_analyze_func)(struct vctr * const, const u64, struct damp * const, char * const);

typedef void * (*forker_worker_func)(void *);

struct pass_info {
  struct rgen * gen0;
  const struct kvmap_api * api;
  void * map;
  u64 vctr_size;
  forker_worker_func wf;
  forker_perf_analyze_func af;
};

struct forker_papi_info {
  u64 nr;
  int events[];
};

struct forker_worker_info {
  struct rgen * gen;
  rgen_next_func rgen_next;
  const struct kvmap_api * api;
  void * map;
  void * priv;
  u32 end_type;
  u64 end_magic;
  struct vctr * vctr;
  u64 worker_id; // <= conc
  u32 conc; // number of threads
  // user args
  int argc;
  char ** argv;
  u64 seed;
  void * (*thread_func)(void *);
  // PAPI
  struct forker_papi_info * papi_info;
  struct vctr * papi_vctr;
};

  extern int
forker_pass(const int argc, char ** const argv, char ** const pref,
    struct pass_info * const pi, const int nr_wargs0);

  extern int
forker_passes(int argc, char ** argv, char ** const pref0,
    struct pass_info * const pi, const int nr_wargs0);

  extern void
forker_passes_message(void);

  extern bool
forker_main(int argc, char ** argv, int(*test_func)(const int, char ** const));
// }}} forker

#ifdef __cplusplus
}
#endif
// vim:fdm=marker
