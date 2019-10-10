/*
 * Copyright (c) 2016--2019  Wu, Xingbo <wuxb45@gmail.com>
 *
 * All rights reserved. No warranty, explicit or implicit, provided.
 */
#define _GNU_SOURCE

// headers {{{
#include "wh.h"
#include <sched.h>
#include <execinfo.h>
#include <signal.h>
#include <stdatomic.h>
#include <byteswap.h>
#include <errno.h>
#include <x86intrin.h>
#include <assert.h>
// POSIX headers
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Linux headers
#include <sys/mman.h>
#include <sys/resource.h>
// }}} headers

// {{{ helpers

// atomic {{{
/* C11 atomic types */
typedef atomic_uint_least16_t   au16;
typedef atomic_uint_least64_t   au64;
// }}} atomic

// locks {{{
typedef struct __spinlock {
  union {
    au16 var;
    u64 padding;
  };
} spinlock;

typedef struct __rwlock {
  union {
    au16 var;
    u64 padding;
  };
} rwlock;
// }}} locks

// debug {{{
#ifndef NDEBUG
  extern void
debug_assert(const bool v);
#else
#define debug_assert(expr) ((void)0)
#endif
// }}} debug

// ansi colors {{{
#define ANSI_FR  "\x1b[31m"
#define ANSI_X   "\x1b[0m"
// }}} ansi colors

// mm {{{
#define PGSZ ((UINT64_C(4096)))
// alloc cache-line aligned address
  static void *
yalloc(const u64 size)
{
  void * p;
  const int r = posix_memalign(&p, 64, size);
  if (r == 0) return p;
  else return NULL;
}

  static inline void
pages_unmap(void * const ptr, const size_t size)
{
#ifndef HEAPCHECKING
  munmap(ptr, size);
#else
  (void)size;
  free(ptr);
#endif
}

  static inline void *
__pages_alloc(const size_t size, const int flags)
{
  // vi /etc/security/limits.conf
  // * - memlock unlimited
  void * const p = mmap(NULL, size, PROT_READ | PROT_WRITE, flags, -1, 0);
  if (p == MAP_FAILED) {
    return NULL;
  }
  mlock(p, size); // ignore if cannot pin memory. see memlock in /etc/security/limits.conf
  return p;
}

  static inline void *
pages_alloc_1gb(const size_t nr_1gb)
{
  const u64 sz = nr_1gb << 30;
#ifndef HEAPCHECKING
  return __pages_alloc(sz, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | (30 << MAP_HUGE_SHIFT));
#else
  void * const p = xalloc(UINT64_C(1) << 30, sz);
  if (p) memset(p, 0, sz);
  return p;
#endif
}

  static inline void *
pages_alloc_2mb(const size_t nr_2mb)
{
  const u64 sz = nr_2mb << 21;
#ifndef HEAPCHECKING
  return __pages_alloc(sz, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | (21 << MAP_HUGE_SHIFT));
#else
  void * const p = xalloc(UINT64_C(1) << 21, sz);
  if (p) memset(p, 0, sz);
  return p;
#endif
}

  static inline void *
pages_alloc_4kb(const size_t nr_4kb)
{
  const size_t sz = nr_4kb << 12;
#ifndef HEAPCHECKING
  return __pages_alloc(sz, MAP_PRIVATE | MAP_ANONYMOUS);
#else
  void * const p = xalloc(UINT64_C(1) << 12, sz);
  if (p) memset(p, 0, sz);
  return p;
#endif
}

  void *
pages_alloc_best(const size_t size, const bool try_1gb, u64 * const size_out)
{
  if (try_1gb) {
    const size_t nr_1gb = (size + ((UINT64_C(1) << 30) - UINT64_C(1))) >> 30;
    // 1gb super huge page: waste < 1/16 or 6.25%
    if (((nr_1gb << 30) - size) < (size >> 4)) {
      void * const p1 = pages_alloc_1gb(nr_1gb);
      if (p1) {
        *size_out = nr_1gb << 30;
        return p1;
      }
    }
  }

  // 2mb huge page: at least 1MB
  if (size >= (UINT64_C(1) << 20)) {
    const size_t nr_2mb = (size + ((UINT64_C(1) << 21) - UINT64_C(1))) >> 21;
    void * const p2 = pages_alloc_2mb(nr_2mb);
    if (p2) {
      *size_out = nr_2mb << 21;
      return p2;
    }
  }

  const size_t nr_4kb = (size + ((UINT64_C(1) << 12) - UINT64_C(1))) >> 12;
  void * const p3 = pages_alloc_4kb(nr_4kb);
  if (p3) {
    *size_out = nr_4kb << 12;
  }
  return p3;
}
// }}} mm

// bits {{{
  static inline u64
bits_p2_up(const u64 v)
{
  // clz(0) is undefined
  return (v > 1) ? (1lu << (64lu - (u64)__builtin_clzl(v - 1lu))) : v;
}

  static inline u64
bits_round_up(const u64 v, const u8 power)
{
  return (v + (1lu << power) - 1lu) >> power << power;
}
// }}} bits

// cpucache {{{
// compiler fence
  static inline void
cpu_cfence(void)
{
  atomic_thread_fence(memory_order_acq_rel);
}

  static inline void
cpu_prefetchr(const void * const ptr, const int hint)
{
  // will be reduced by optimization
  switch (hint) {
    case 0: __builtin_prefetch(ptr, 0, 0); break;
    case 1: __builtin_prefetch(ptr, 0, 1); break;
    case 2: __builtin_prefetch(ptr, 0, 2); break;
    case 3: __builtin_prefetch(ptr, 0, 3); break;
    default: break;
  }
}
// }}} cpucache

// locking {{{
  static inline void
spinlock_init(spinlock * const lock)
{
  atomic_store(&lock->var, 0);
}

  static inline bool
spinlock_trylock_nr(spinlock * const lock, u64 nr)
{
  au16 * const pvar = (typeof(pvar))&(lock->var);
  if (0u == atomic_fetch_add(pvar, 1u))
    return true;

  do {
    u16 z = 0u; // atomic cxhg changes z
    if (atomic_compare_exchange_weak(pvar, &z, 1u))
      return true;
    _mm_pause();
  } while (nr--);
  return false;
}

  static inline void
spinlock_lock(spinlock * const lock)
{
  au16 * const pvar = (typeof(pvar))&(lock->var);
  do {
    if (0u == atomic_fetch_add(pvar, 1u))
      return;
    do {
      _mm_pause();
    } while (atomic_load(pvar));
  } while (true);
}

  static inline void
spinlock_unlock(spinlock * const lock)
{
  atomic_store(&lock->var, 0);
}

#define RWLOCK_WSHIFT ((15))
#define RWLOCK_WBIT ((1u << RWLOCK_WSHIFT))

  static inline void
rwlock_init(rwlock * const lock)
{
  au16 * const pvar = (typeof(pvar))(&(lock->var));
  atomic_store(pvar, 0);
}

  static inline bool
rwlock_trylock_read(rwlock * const lock)
{
  au16 * const pvar = (typeof(pvar))(&(lock->var));
  if ((atomic_fetch_add(pvar, 1u) >> RWLOCK_WSHIFT) == 0u) {
    return true;
  } else {
    atomic_fetch_sub(pvar, 1u);
    return false;
  }
}

// actually nr + 1
  static inline bool
rwlock_trylock_read_nr(rwlock * const lock, u64 nr)
{
  if (rwlock_trylock_read(lock))
    return true;
  do {
    if (((atomic_load(&lock->var) >> RWLOCK_WSHIFT) == 0u) && rwlock_trylock_read(lock))
      return true;
    _mm_pause();
  } while (nr--);
  return false;
}

  static inline void
rwlock_unlock_read(rwlock * const lock)
{
  au16 * const pvar = (typeof(pvar))(&(lock->var));
  atomic_fetch_sub(pvar, 1u);
}

  static inline bool
rwlock_trylock_write(rwlock * const lock)
{
  au16 * const pvar = (typeof(pvar))(&(lock->var));
  u16 v0 = atomic_load(pvar);
  if (v0 == 0u) {
    if (atomic_compare_exchange_weak(pvar, &v0, RWLOCK_WBIT))
      return true;
  }
  return false;
}

// actually nr + 1
  static inline bool
rwlock_trylock_write_nr(rwlock * const lock, u64 nr)
{
  do {
    if (rwlock_trylock_write(lock))
      return true;
    _mm_pause();
  } while (nr--);
  return false;
}

  static inline void
rwlock_lock_write(rwlock * const lock)
{
  while (rwlock_trylock_write(lock) == false)
    while (atomic_load(&lock->var))
      _mm_pause();
}

  static inline void
rwlock_unlock_write(rwlock * const lock)
{
  au16 * const pvar = (typeof(pvar))(&(lock->var));
  atomic_fetch_sub(pvar, RWLOCK_WBIT);
}

  static inline void
rwlock_write_to_read(rwlock * const lock)
{
  au16 * const pvar = (typeof(pvar))(&(lock->var));
  do {
    u16 v0 = atomic_load(pvar);
    debug_assert(v0 & RWLOCK_WBIT);
    debug_assert(((v0 + 1u - RWLOCK_WBIT) & RWLOCK_WBIT) == 0u); // corner case
    // +R -W
    if (atomic_compare_exchange_weak(pvar, &v0, v0 + 1u - RWLOCK_WBIT))
      break;
  } while (true);
}
#undef RWLOCK_WBIT
// }}} locking

// timing {{{
  inline u64
rdtsc(void)
{
  return _rdtsc();
}

  inline u64
time_nsec(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * UINT64_C(1000000000) + ts.tv_nsec;
}

  inline double
time_sec(void)
{
  const u64 nsec = time_nsec();
  return ((double)nsec) / 1000000000.0;
}

  inline double
time_diff_sec(const double last)
{
  return time_sec() - last;
}
// }}} timing

// debug {{{
  static void
debug_backtrace(void)
{
  void *array[100];
  const int size = backtrace(array, 100);
  dprintf(2, "Backtrace (%d):\n", size);
  // skip this call
  backtrace_symbols_fd(array + 1, size, 2);
}

  static void
debug_wait_gdb(void)
{
  debug_backtrace();
  bool wait = true;
  volatile bool * const v = &wait;
  *v = true;

  time_t now;
  time(&now);
  struct tm nowtm;
  localtime_r(&now, &nowtm);
  char timestamp[64] = {};
  strftime(timestamp, 64, "%F %T %Z (%z)", &nowtm);

  char hostname[256] = {};
  gethostname(hostname, 256);
  char threadname[256];
  pthread_getname_np(pthread_self(), threadname, 256);

  const char * const pattern = "[Waiting GDB] %s %s @ %s\n"
    "    Attach me:   " ANSI_FR "sudo -Hi gdb -p %d" ANSI_X "\n";
  fprintf(stderr, pattern, timestamp, threadname, hostname, getpid());
  fflush(stderr);
  // to continue: gdb> set var *v = 0
  while (*v) {
    sleep(1);
  }
}

#ifndef NDEBUG
  inline void
debug_assert(const bool v)
{
  if (!v) debug_wait_gdb();
}
#endif

__attribute__((noreturn))
  static void
debug_die(void)
{
  debug_wait_gdb();
  exit(0);
}

  static void
__signal_handler_wait_gdb(const int sig, siginfo_t * const info, void * const context)
{
  (void)info;
  (void)context;
  printf("[SIGNAL] %s\n", strsignal(sig));
  debug_wait_gdb();
}

__attribute__((constructor))
  static void
debug_catch_fatals(void)
{
  struct sigaction sa = {};
  sa.sa_sigaction = __signal_handler_wait_gdb;
  sigemptyset(&(sa.sa_mask));
  sa.sa_flags = SA_SIGINFO;
  const int fatals[] = {SIGSEGV, SIGFPE, SIGILL, SIGBUS, 0};
  for (int i = 0; fatals[i]; i++) {
    if (sigaction(fatals[i], &sa, NULL) == -1) {
      fprintf(stderr, "Failed to set signal handler for %s\n", strsignal(fatals[i]));
      fflush(stderr);
    }
  }
}
// }}} debug

// process/thread {{{
static u64 process_ncpu;
static u64 process_cpu_set_size;

__attribute__((constructor))
  static void
process_init(void)
{
  process_ncpu = sysconf(_SC_NPROCESSORS_CONF);
  const size_t s1 = CPU_ALLOC_SIZE(process_ncpu);
  const size_t s2 = sizeof(cpu_set_t);
  process_cpu_set_size = s1 > s2 ? s1 : s2;
}

  u64
process_get_rss(void)
{
  u64 size, rss = 0;
  FILE * const fp = fopen("/proc/self/statm", "r");
  if (fp == NULL)
    return 0;
  fscanf(fp, "%lu %lu", &size, &rss);
  fclose(fp);
  return rss * (u64)sysconf(_SC_PAGESIZE);
}

  static inline cpu_set_t *
process_cpu_set_alloc(void)
{
  return malloc(process_cpu_set_size);
}

  u64
process_affinity_core_count(void)
{
  cpu_set_t * const set = process_cpu_set_alloc();
  if (sched_getaffinity(0, process_cpu_set_size, set) != 0) {
    free(set);
    return process_ncpu;
  }

  const u64 nr = (u64)CPU_COUNT_S(process_cpu_set_size, set);
  free(set);
  return nr ? nr : process_ncpu;
}

  u64
process_affinity_core_list(const u64 max, u64 * const cores)
{
  memset(cores, 0, max * sizeof(cores[0]));
  cpu_set_t * const set = process_cpu_set_alloc();
  if (sched_getaffinity(0, process_cpu_set_size, set) != 0)
    return 0;

  const u64 nr_affinity = CPU_COUNT_S(process_cpu_set_size, set);
  const u64 nr = nr_affinity < max ? nr_affinity : max;
  u64 j = 0;
  for (u64 i = 0; i < process_ncpu; i++) {
    if (CPU_ISSET_S((int)i, process_cpu_set_size, set)) {
      cores[j++] = i;
    }
    if (j >= nr) break;
  }
  free(set);
  return j;
}

  u64
process_cpu_time_usec(void)
{
  struct rusage r;
  getrusage(RUSAGE_SELF, &r);
  const u64 usr = (r.ru_utime.tv_sec * 1000000lu) + r.ru_utime.tv_usec;
  const u64 sys = (r.ru_stime.tv_sec * 1000000lu) + r.ru_stime.tv_usec;
  return usr + sys;
}

  void
thread_set_affinity(const u64 cpu)
{
  cpu_set_t * const set = process_cpu_set_alloc();

  CPU_ZERO_S(process_cpu_set_size, set);
  CPU_SET_S(cpu % process_ncpu, process_cpu_set_size, set);
  sched_setaffinity(0, process_cpu_set_size, set);
  free(set);
}

struct fork_join_info {
  u64 tot;
  u64 rank; // 0 to n-1
  u64 core;
  pthread_t tid;
  void *(*func)(void *);
  void * argv;
  struct fork_join_info * all;
  u64 padding[1];
};

// recursive tree fork-join
  static void *
thread_do_fork_join_worker(void * const ptr)
{
  struct fork_join_info * const fji = (typeof(fji))ptr;
  const u64 rank = fji->rank;
  const u64 span0 = (rank ? (rank & -rank) : bits_p2_up(fji->tot)) >> 1;
  if (span0) {
    cpu_set_t * const set = process_cpu_set_alloc();
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    for (u64 span = span0; span; span >>= 1) {
      const u64 cr = rank + span;
      if (cr >= fji->tot)
        continue;
      struct fork_join_info * const cfji = &(fji->all[cr]);
      CPU_ZERO_S(process_cpu_set_size, set);
      CPU_SET_S(cfji->core, process_cpu_set_size, set);
      pthread_attr_setaffinity_np(&attr, process_cpu_set_size, set);
      const int r = pthread_create(&(cfji->tid), &attr, thread_do_fork_join_worker, cfji);
      if (r == 0) {
        char thname[24];
        sprintf(thname, "fj_%lu", cr);
        pthread_setname_np(cfji->tid, thname);
      } else {
        cfji->tid = 0;
      }
    }
    pthread_attr_destroy(&attr);
    free(set);
  }
  void * const ret = fji->func(fji->argv);
  for (u64 span = 1; span <= span0; span <<= 1) {
    const u64 cr = rank + span;
    if (cr >= fji->tot)
      break;
    struct fork_join_info * const cfji = &(fji->all[cr]);
    if (cfji->tid)
      pthread_join(cfji->tid, NULL);
  }
  return ret;
}

  double
thread_fork_join_private(const u64 nr, void *(*func) (void *), void * const * const argv)
{
  if (nr == 0)
    return 0.0;
  u64 cores[process_ncpu];
  cpu_set_t * const set0 = process_cpu_set_alloc();

  const bool force_all = (sched_getaffinity(0, process_cpu_set_size, set0) != 0) ? true : false;
  u64 j = 0;
  for (u64 i = 0; i < process_ncpu; i++)
    if (force_all || CPU_ISSET_S((int)i, process_cpu_set_size, set0))
      cores[j++] = i;

  const u64 ncores = j;
  const u64 nr_threads = nr ? nr : ncores;

  struct fork_join_info * const fjis = yalloc(sizeof(*fjis) * nr_threads);
  for (u64 i = 0; i < nr_threads; i++) {
    fjis[i].tot = nr_threads;
    fjis[i].rank = i;
    fjis[i].core = cores[i % ncores];
    fjis[i].tid = 0;
    fjis[i].func = func;
    fjis[i].argv = argv[i];
    fjis[i].all = fjis;
  }

  // master thread shares thread0's core
  cpu_set_t * const set = process_cpu_set_alloc();
  CPU_ZERO_S(process_cpu_set_size, set);
  CPU_SET_S(fjis[0].core, process_cpu_set_size, set);
  sched_setaffinity(0, process_cpu_set_size, set);
  free(set);

  const double t0 = time_sec();
  thread_do_fork_join_worker(&(fjis[0]));
  const double dt = time_diff_sec(t0);

  // restore original affinity
  sched_setaffinity(0, process_cpu_set_size, set0);
  free(set0);
  free(fjis);
  return dt;
}

  double
thread_fork_join(const u64 nr, void *(*func) (void *), void * const arg)
{
  const u64 nthreads = nr ? nr : process_affinity_core_count();
  void * argv[nthreads];
  for (u64 i = 0; i < nthreads; i++)
    argv[i] = arg;

  return thread_fork_join_private(nthreads, func, argv);
}
// }}} process/thread

// slab {{{
struct slab_object {
  struct slab_object * next;
};

struct slab {
  spinlock lock;
  u64 obj_size;
  struct slab_object * obj_head;
  u64 blk_size; // size of each memory block
  u64 blk_nr; // number of blocks
  u64 nr_alloc; // number of objects in use
  struct slab_object * blk_head; // list of all blocks
};

  static void
slab_expand(struct slab * const slab)
{
  size_t blk_size;
  struct slab_object * const blk = pages_alloc_best(slab->blk_size, true, &blk_size);
  (void)blk_size;
  debug_assert(blk_size == slab->blk_size);
  blk->next = slab->blk_head;
  slab->blk_head = blk;

  const u64 nr_objs = (slab->blk_size - 128u) / slab->obj_size;
  for (u64 i = nr_objs; i; i--) {
    struct slab_object * const obj = (typeof(obj))(((u8 *)blk) + 128u + ((i - 1lu) * slab->obj_size));
    obj->next = slab->obj_head;
    slab->obj_head = obj;
  }
}

  static struct slab *
slab_create(const u64 obj_size, const u64 blk_size)
{
  // obj must be 8-byte aligned
  // blk must be at least of page size and power of 2
  if ((obj_size % 8lu) || (blk_size < 4096lu) || (blk_size & (blk_size - 1lu)))
    return NULL;

  struct slab * const slab = (typeof(slab))malloc(sizeof(*slab));
  debug_assert(slab);
  spinlock_init(&(slab->lock));
  slab->obj_size = obj_size;
  slab->obj_head = NULL;
  slab->blk_size = blk_size;
  slab->blk_nr = 0lu;
  slab->blk_head = NULL;
  slab->nr_alloc = 0lu;
  slab_expand(slab);
  return slab;
}

  static inline void *
slab_alloc_unsafe(struct slab * const slab)
{
  if (slab->obj_head == NULL) {
    slab_expand(slab);
  }
  debug_assert(slab->obj_head);
  struct slab_object * const obj = slab->obj_head;
  slab->obj_head = obj->next;
  slab->nr_alloc++;
  return (void *)obj;
}

  static inline void *
slab_alloc(struct slab * const slab)
{
  spinlock_lock(&(slab->lock));
  void * const ptr = slab_alloc_unsafe(slab);
  spinlock_unlock(&(slab->lock));
  return ptr;
}

  static inline void
slab_free_unsafe(struct slab * const slab, void * const ptr)
{
  struct slab_object * const obj = (typeof(obj))ptr;
  obj->next = slab->obj_head;
  slab->obj_head = obj;
  slab->nr_alloc--;
}

  static inline void
slab_free(struct slab * const slab, void * const ptr)
{
  spinlock_lock(&(slab->lock));
  slab_free_unsafe(slab, ptr);
  spinlock_unlock(&(slab->lock));
}

  static void
slab_destroy(struct slab * const slab)
{
  struct slab_object * iter = slab->blk_head;
  while (iter) {
    struct slab_object * const next = iter->next;
    pages_unmap(iter, slab->blk_size);
    iter = next;
  }
  free(slab);
}
// }}} slab

// }}} helpers

// crc32c {{{
#define CRC32C_SEED ((0xDEADBEEFu))
  static inline u32
crc32c_inc_short_nz(const u8 * buf, size_t nr, u32 crc)
{
  // nr == 1
  crc = _mm_crc32_u8(crc, buf[0]);
  if (nr == 1)
    return crc;

  crc = _mm_crc32_u8(crc, buf[1]);
  return (nr == 2) ? crc : _mm_crc32_u8(crc, buf[2]);
}

// for crc less than 3 bytes
  static inline u32
crc32c_inc_short(const u8 * buf, size_t nr, u32 crc)
{
  debug_assert(nr <= 3);
  return nr ? crc32c_inc_short_nz(buf, nr, crc) : crc;
}

  static inline u32
crc32c_inc_x4(const u8 * buf, size_t nr, u32 crc)
{
  debug_assert((nr & 3) == 0);
#pragma nounroll
  while (nr >= sizeof(u64)) {
    crc = _mm_crc32_u64(crc, *((u64*)buf));
    nr -= sizeof(u64);
    buf += sizeof(u64);
  }
  if (nr)
    crc = _mm_crc32_u32(crc, *((u32*)buf));
  return crc;
}

  static inline u32
crc32c_inc(const u8 * buf, size_t nr, u32 crc)
{
#pragma nounroll
  while (nr >= sizeof(u64)) {
    crc = _mm_crc32_u64(crc, *((u64*)buf));
    nr -= sizeof(u64);
    buf += sizeof(u64);
  }
  if (nr >= sizeof(u32)) {
    crc = _mm_crc32_u32(crc, *((u32*)buf));
    nr -= sizeof(u32);
    buf += sizeof(u32);
  }
  return crc32c_inc_short(buf, nr, crc);
}

  static inline u32
crc32c(const void * const ptr, size_t len)
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

// qsbr {{{
#define QSBR_STATES_NR ((22)) // 3*8-2
#define QSBR_BITMAP_FULL ((1lu << QSBR_STATES_NR) - 1lu)
#define QSBR_SHARDS_NR  ((32))
#define QSBR_CAPACITY ((QSBR_STATES_NR * QSBR_SHARDS_NR))
// QSBR_CAPACITY == 22 * 32 == 704
struct qsbr { // 1 + (3 * 32) = 97 lines
  volatile u64 target;
  u64 padding0[7];
  struct qshard {
    spinlock lock;
    u64 bitmap;
    volatile u64 * ptrs[QSBR_STATES_NR];
  } shards[QSBR_SHARDS_NR];
  volatile u64 * wait_ptrs[QSBR_CAPACITY];
};

  static struct qsbr *
qsbr_create(void)
{
  struct qsbr * const q = yalloc(sizeof(*q));
  memset(q, 0, sizeof(*q));
  return q;
}

  static inline struct qshard *
qsbr_shard(struct qsbr * const q, volatile u64 * const ptr)
{
  const u32 sid = _mm_crc32_u64(0xDEADBEEFu, (u64)ptr) & ((u32)(QSBR_SHARDS_NR-1));
  debug_assert(sid < QSBR_SHARDS_NR);
  return &(q->shards[sid]);
}

  static bool
qsbr_register(struct qsbr * const q, volatile u64 * const ptr)
{
  if (ptr == NULL)
    return false;
  struct qshard * const shard = qsbr_shard(q, ptr);
  spinlock_lock(&(shard->lock));

  if (shard->bitmap < QSBR_BITMAP_FULL) {
    const u64 pos = __builtin_ctzl(~(shard->bitmap));
    debug_assert(pos < QSBR_STATES_NR);
    shard->bitmap |= (1lu << pos);
    shard->ptrs[pos] = ptr;
    spinlock_unlock(&(shard->lock));
    return true;
  }
  spinlock_unlock(&(shard->lock));
  return false;
}

  static void
qsbr_unregister(struct qsbr * const q, volatile u64 * const ptr)
{
  if (ptr == NULL)
    return;
  struct qshard * const shard = qsbr_shard(q, ptr);
  while (spinlock_trylock_nr(&(shard->lock), 64) == false) {
    (*ptr) = q->target;
    _mm_pause();
  }

  u64 bits = shard->bitmap;
  debug_assert(bits < QSBR_BITMAP_FULL);
  while (bits) { // bits contains ones
    const u64 pos = __builtin_ctzl(bits);
    debug_assert(pos < QSBR_STATES_NR);
    if (shard->ptrs[pos] == ptr) {
      shard->bitmap &= (~(1lu << pos));
      shard->ptrs[pos] = NULL;
      spinlock_unlock(&(shard->lock));
      return;
    }
    bits &= (~(1lu << pos));
  }
  debug_die();
  spinlock_unlock(&(shard->lock));
}

// waiters needs external synchronization
  static void
qsbr_wait(struct qsbr * const q, const u64 target)
{
  q->target = target;
  for (u64 i = 0; i < QSBR_SHARDS_NR; i++)
    spinlock_lock(&(q->shards[i].lock));

  // collect wait_ptrs
  volatile u64 ** const wait_ptrs = q->wait_ptrs;
  u64 nwait = 0;
  for (u64 i = 0; i < QSBR_SHARDS_NR; i++) {
    struct qshard * const shard = &(q->shards[i]);
    u64 bits = shard->bitmap;
    while (bits) { // bits contains ones
      const u64 pos = __builtin_ctzl(bits);
      debug_assert(pos < QSBR_STATES_NR);
      if (*(shard->ptrs[pos]) != target)
        wait_ptrs[nwait++] = shard->ptrs[pos];
      bits &= (~(1lu << pos));
    }
  }

  // wait
  while (nwait) {
    for (u64 i = nwait - 1; i + 1; i--) { // nwait - 1 to 0
      if ((*(wait_ptrs[i])) == target) {
        if (i < (nwait - 1))
          wait_ptrs[i] = wait_ptrs[nwait - 1];
        nwait--;
      }
    }
  }
  for (u64 i = 0; i < QSBR_SHARDS_NR; i++)
    spinlock_unlock(&(q->shards[i].lock));
}

  static void
qsbr_destroy(struct qsbr * const q)
{
  free(q);
}
#undef QSBR_STATES_NR
#undef QSBR_BITMAP_NR
// }}} qsbr

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
  const u32 lo = crc32c((const void *)kv->kv, (const size_t)kv->klen);
  kv->hash = crc32c_extend(lo);
}

  inline void
kv_refill(struct kv * const kv, const void * const key, const u32 klen,
    const void * const value, const u32 vlen)
{
  debug_assert(kv);
  kv->klen = klen;
  kv->vlen = vlen;
  memcpy(&(kv->kv[0]), key, klen);
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
  memcpy(new, from, sz);
  new->vlen = 0;
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
  new->len = from->vlen;
  memcpy(new->buf, from->kv + from->klen, from->vlen);
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

// key1 and key2 must be valid ptr
  inline bool
kv_keymatch(const struct kv * const key1, const struct kv * const key2)
{
  return (key1->hash == key2->hash) && (key1->klen == key2->klen) && (!memcmp(key1->kv, key2->kv, key1->klen));
}

  inline bool
kv_fullmatch(const struct kv * const kv1, const struct kv * const kv2)
{
  return (kv1->kvlen == kv2->kvlen) && (!memcmp(kv1, kv2, sizeof(*kv1) + kv1->klen + kv1->vlen));
}

  inline int
kv_keycompare(const struct kv * const kv1, const struct kv * const kv2)
{
  debug_assert(kv1);
  debug_assert(kv2);
  const u32 len = kv1->klen < kv2->klen ? kv1->klen : kv2->klen;
  const int cmp = memcmp(kv1->kv, kv2->kv, (size_t)len);
  if (cmp == 0) {
    if (kv1->klen < kv2->klen)
      return -1;
    else if (kv1->klen > kv2->klen)
      return 1;
    else
      return 0;
  } else {
    return cmp;
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
  static inline u32
kv_key_lcp(const struct kv * const key1, const struct kv * const key2)
{
  const u32 max = (key1->klen < key2->klen) ? key1->klen : key2->klen;
  const u32 max128 = max & (~0xfu);
  u32 clen = 0;
  const u8 * p1 = key1->kv;
  const u8 * p2 = key2->kv;
  // inc by 4
  while (clen < max128) {
    const __m128i cmp = _mm_cmpeq_epi8(_mm_load_si128((__m128i *)p1), _mm_load_si128((__m128i *)p2));
    const u32 lcpinc = (u32)__builtin_ctz(~_mm_movemask_epi8(cmp));
    if (lcpinc < sizeof(__m128i))
      return clen + lcpinc;
    clen += sizeof(__m128i);
    p1 += sizeof(__m128i);
    p2 += sizeof(__m128i);
  }

  const u32 max32 = max & (~0x3u);
  // inc by 4
  while (clen < max32) {
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

// return true if p is a prefix of key
  static inline bool
kv_key_is_prefix(const struct kv * const p, const struct kv * const key)
{
  return ((p->klen <= key->klen) && (kv_key_lcp(p, key) == p->klen)) ? true : false;
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
  return ((hash >> 16) ^ hash) & 0xfffflu;
}

  static const char *
kv_pattern(const char c)
{
  switch (c) {
    case 's': return "%c";
    case 'x': return " %02hhx";
    case 'd': return " %03hhu";
    default: return NULL;
  }
}

// cmd "KV" K and V can be 's' for string, 'x' for hex, 'd' for dec, or else for not printing.
// n for newline after kv
  void
kv_print(const struct kv * const kv, const char * const cmd, FILE * const out)
{
  debug_assert(cmd);
  const u32 klen = kv->klen;
  fprintf(out, "#%04lx #%016lx k[%2u] ", kvmap_pkey(kv->hash), kv->hash, klen);
  const u32 klim = klen < 1024u ? klen : 1024u;

  const char * const kpat = kv_pattern(cmd[0]);
  for (u32 i = 0; i < klim; i++)
    fprintf(out, kpat, kv->kv[i]);
  if (klim < klen)
    fprintf(out, " ...");

  const char * const vpat = kv_pattern(cmd[1]);
  if (vpat) { // may omit value
    const u32 vlen = kv->vlen;
    const u32 vlim = vlen < 1024u ? vlen : 1024u;
    fprintf(out, "  v[%4u] ", vlen);
    for (u32 i = 0; i < vlim; i++)
      fprintf(out, vpat, kv->kv[klen + i]);
    if (vlim < vlen)
      fprintf(out, " ...");
  }
  if (strchr(cmd, 'n'))
    fprintf(out, "\n");
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
#define KVBUCKET_NR ((8lu))
struct kvbucket {
  struct entry13 e[KVBUCKET_NR];
};

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
kvmap_entry_qsort(struct entry13 * const es, const size_t nr)
{
  qsort(es, nr, sizeof(es[0]), kvmap_entry_keycompare_vptr);
}

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
    e->v64 = 0lu;
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
#define WH_HMAPINIT_SIZE ((1lu << 14)) // 256k/1MB
#define WH_SLABMETA_SIZE ((1lu << 21)) // 2MB
#define WH_SLABLEAF_SIZE ((1lu << 21)) // 1GB; change to 2MB if no 1GB hugepages
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
  u16 klen;
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
  u64 version;
  u64 klen;
  rwlock leaflock;
  struct entry13 eh[WH_KPN]; // sorted by hashes
  struct entry13 es[WH_KPN]; // sorted by keys
};

struct wormslot {
  u16 t[KVBUCKET_NR];
};
static_assert(sizeof(struct wormslot) == 16, "sizeof(wormslot) != 16");

struct wormhmap {
  u64 version;
  struct wormslot * wmap;
  u64 mask;
  struct kvbucket * pmap;

  u32 maxplen;
  u32 hmap_id; // 0 or 1
  struct wormhole * map;
  u64 msize;
  struct wormhmap * sibling;
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
  struct slab * slab_meta[2];
  struct slab * slab_leaf;
  // 2 lines
  struct wormhmap hmap2[2];
  // fifth line
  rwlock metalock;
  u64 padding1[7];
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
  union {
    u64 hash;
    struct {
      u32 hashlo; // little endian
      u32 hashhi;
    };
  };
  u32 plen; // prefix length; plen <= klen
  u32 klen; // the original klen
  const u8 * key;
};

struct wormref {
  struct wormhole * map;
  volatile u64 qstate;
};
// }}} struct

// helpers {{{

// alloc {{{
  static inline struct kv *
wormhole_alloc_akey(const size_t klen)
{
  // evaluation says slab and yalloc are worse...
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
  // evaluation says slab and yalloc are worse...
  return malloc(sizeof(struct kv) + klen);
  // current wh impl: refill/dup2_key will clear vlen/refcnt
  // ret->refcnt = 0; // this is safely omitted now
}

  static inline void
wormhole_free_mkey(struct kv * const mkey)
{
  free(mkey);
}

  static inline struct kv *
wormhole_alloc_kv(struct wormhole * const map, const size_t klen, const size_t vlen)
{
  const size_t size = sizeof(struct kv) + klen + vlen;
  return map->mm.af(size, map->mm.ap);
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
  leaf->nr_sorted = 0u;
  leaf->nr_keys = 0u;
  leaf->prev = prev;
  leaf->next = next;
  // eh required zero init.
  memset(leaf->eh, 0, sizeof(leaf->eh[0]) * WH_KPN);
  return leaf;
}

  static inline struct wormmeta *
wormhole_alloc_meta_keyref(struct slab * const slab, struct wormleaf * const lrmost,
    struct kv * const keyref, const u64 hash, const u32 klen)
{
  struct wormmeta * const meta = slab_alloc_unsafe(slab);
  if (meta == NULL)
    return NULL;
  keyref->refcnt++;
  meta->hash32 = (u32)hash;
  meta->klen = klen;
  meta->keyref = keyref;
  meta->bitmin = WH_FO; // WH_FO implies bitcount == 0
  meta->lmost = lrmost;
  meta->rmost = lrmost;
  for (u64 i = 0; i < WH_BMNR; i++)
    meta->bitmap[i] = 0;
  return meta;
}

  static inline struct wormmeta *
wormhole_alloc_meta(struct slab * const slab, struct wormleaf * const lrmost,
    struct kv * const key)
{
  return wormhole_alloc_meta_keyref(slab, lrmost, key, key->hash, key->klen);
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

// key/prefix {{{
  static inline bool
wormhole_key_meta_match(const struct kv * const key, const struct wormmeta * const meta)
{
  return (((u32)(key->hash)) == meta->hash32) && (key->klen == meta->klen) &&
    (!memcmp(key->kv, meta->keyref->kv, key->klen));
}

  static inline bool
wormhole_kref_meta_match(const struct wormkref * const ref, const struct wormmeta * const meta)
{
  return (((u32)(ref->hash)) == meta->hash32) && (ref->plen == meta->klen) &&
    (!memcmp(ref->key, meta->keyref->kv, ref->plen));
}

  static inline bool
wormhole_kref1_meta_match(const struct wormkref * const ref, const struct wormmeta * const meta,
    const u32 cid)
{
  const struct kv * const mkey = meta->keyref;
  const u32 plen = ref->plen;
  return ((plen + 1) == meta->klen) && (!memcmp(ref->key, mkey->kv, plen)) &&
    (mkey->kv[plen] == cid);
}

// warning: buffer overflow risk, call it carefully
  static inline void
wormhole_prefix(struct kv * const pfx, const u32 klen)
{
  pfx->klen = klen;
  kv_update_hash(pfx);
}

  static inline void
wormhole_prefix_inc_short(struct kv * const pfx, const u32 klen)
{
  debug_assert(klen >= pfx->klen);
  const u32 lo = crc32c_inc_short(pfx->kv + pfx->klen, klen - pfx->klen, (u32)pfx->hash);
  pfx->hash = crc32c_extend(lo);
  pfx->klen = klen;
}

  static inline void
wormhole_prefix_inc_long(struct kv * const pfx, const u32 klen)
{
  debug_assert(klen >= pfx->klen);
  const u32 lo = crc32c_inc(pfx->kv + pfx->klen, klen - pfx->klen, (u32)pfx->hash);
  pfx->hash = crc32c_extend(lo);
  pfx->klen = klen;
}

  static inline void
wormhole_kref_inc_long(struct wormkref * const ref, const u32 plen, const u32 seed, const u32 slen)
{
  ref->hash = crc32c_extend(crc32c_inc(ref->key + slen, plen - slen, seed));
  ref->plen = plen;
}

  static inline void
wormhole_kref_inc_x4(struct wormkref * const ref, const u32 plen, const u32 seed, const u32 slen)
{
  ref->hash = crc32c_extend(crc32c_inc_x4(ref->key + slen, plen - slen, seed));
  ref->plen = plen;
}

  static inline void
wormhole_kref_inc_short_nz(struct wormkref * const ref, const u32 plen, const u32 seed,
    const u32 slen)
{
  ref->hash = crc32c_extend(crc32c_inc_short_nz(ref->key + slen, plen - slen, seed));
  ref->plen = plen;
}
// }}} key/prefix

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
  if ((id0 & 0x3fu) != 0x3fu) { // not at 63
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

// find the highest bit that is lower to the given id in the bitmap
// returns original id if not found
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
// skey is only used for wormslot where all hashes are non-zero
// this function converts 0 to 1 and return any other value as is.
  static inline u16
wormhole_hmap_skey(const u16 pkey)
{
  return pkey ? pkey : 1;
}

  static inline u64
wormhole_hmap_peek_slot(const struct wormslot * const s, const __m128i skey)
{
  return (u64)_mm_movemask_epi8(_mm_cmpeq_epi16(skey, _mm_load_si128((const void *)(s))));
}

  static inline bool
wormhole_hmap_peek(const struct wormhmap * const hmap, const u64 hash)
{
  const __m128i sk = _mm_set1_epi16(wormhole_hmap_skey(kvmap_pkey(hash)));
  const u64 midx = hash & hmap->mask;
  const u64 midy = bswap_64(hash) & hmap->mask;
  if (wormhole_hmap_peek_slot(&(hmap->wmap[midx]), sk))
    return true;
  return wormhole_hmap_peek_slot(&(hmap->wmap[midy]), sk);
}

  static inline u64
wormhole_hmap_count_entry(const struct wormhmap * const hmap, const u64 mid)
{
  const u64 mask = wormhole_hmap_peek_slot(&(hmap->wmap[mid]), _mm_setzero_si128());
  return mask ? (__builtin_ctzl(mask) >> 1) : 8;
}

  static inline struct wormmeta *
wormhole_hmap_get_slot(const struct wormhmap * const hmap, const u64 mid, const __m128i skey,
    const struct kv * const key)
{
  u64 mask = wormhole_hmap_peek_slot(&(hmap->wmap[mid]), skey);
  while (mask) {
    const u32 i = __builtin_ctzl(mask) >> 1;
    struct wormmeta * const meta = u64_to_ptr(hmap->pmap[mid].e[i].e3);
    if (wormhole_key_meta_match(key, meta))
      return meta;
    mask ^= (3lu << (i << 1));
  }
  return NULL;
}

  static inline struct wormmeta *
wormhole_hmap_get(const struct wormhmap * const hmap, const struct kv * const key)
{
  const u64 hash = key->hash;
  const u64 midx = hash & hmap->mask;
  cpu_prefetchr(&(hmap->pmap[midx]), 0);
  const u64 midy = bswap_64(hash) & hmap->mask;
  cpu_prefetchr(&(hmap->pmap[midy]), 0);
  const __m128i skey = _mm_set1_epi16(wormhole_hmap_skey(kvmap_pkey(hash)));

  struct wormmeta * const r = wormhole_hmap_get_slot(hmap, midx, skey, key);
  if (r)
    return r;
  return wormhole_hmap_get_slot(hmap, midy, skey, key);
}

  static inline struct wormmeta *
wormhole_hmap_get_kref_slot(const struct wormhmap * const hmap, const u64 mid, const __m128i skey,
    const struct wormkref * const ref)
{
  u64 mask = wormhole_hmap_peek_slot(&(hmap->wmap[mid]), skey);
  while (mask) {
    const u32 i = __builtin_ctzl(mask) >> 1;
    struct wormmeta * const meta = u64_to_ptr(hmap->pmap[mid].e[i].e3);
    if (wormhole_kref_meta_match(ref, meta)) {
      if ((ref->klen == ref->plen) || (meta->bitmin > ref->key[ref->plen]))
        cpu_prefetchr(meta->lmost, 0);
      return meta;
    }
    mask ^= (3lu << (i << 1));
  }
  return NULL;
}

  static inline struct wormmeta *
wormhole_hmap_get_kref(const struct wormhmap * const hmap, const struct wormkref * const ref)
{
  const u64 hash = ref->hash;
  const u64 midx = hash & hmap->mask;
  cpu_prefetchr(&(hmap->pmap[midx]), 0);
  const u64 midy = bswap_64(hash) & hmap->mask;
  cpu_prefetchr(&(hmap->pmap[midy]), 0);
  const __m128i skey = _mm_set1_epi16(wormhole_hmap_skey(kvmap_pkey(hash)));

  struct wormmeta * const r = wormhole_hmap_get_kref_slot(hmap, midx, skey, ref);
  if (r)
    return r;
  return wormhole_hmap_get_kref_slot(hmap, midy, skey, ref);
}

  static inline struct wormmeta *
wormhole_hmap_get_kref1_slot(const struct wormhmap * const hmap, const u64 mid, const __m128i skey,
    const struct wormkref * const ref, const u32 cid)
{
  u64 mask = wormhole_hmap_peek_slot(&(hmap->wmap[mid]), skey);
  while (mask) {
    const u32 i = __builtin_ctzl(mask) >> 1;
    struct wormmeta * const meta = u64_to_ptr(hmap->pmap[mid].e[i].e3);
    if (wormhole_kref1_meta_match(ref, meta, cid)) {
      cpu_prefetchr(meta->rmost, 0);
      return meta;
    }
    mask ^= (3lu << (i << 1));
  }
  return NULL;
}

  static inline struct wormmeta *
wormhole_hmap_get_kref1(const struct wormhmap * const hmap, const struct wormkref * const ref,
    const u32 cid)
{
  const u64 hash = crc32c_extend(_mm_crc32_u8((u32)ref->hash, cid));
  const u64 midx = hash & hmap->mask;
  cpu_prefetchr(&(hmap->pmap[midx]), 0);
  const u64 midy = bswap_64(hash) & hmap->mask;
  cpu_prefetchr(&(hmap->pmap[midy]), 0);
  const __m128i skey = _mm_set1_epi16(wormhole_hmap_skey(kvmap_pkey(hash)));

  struct wormmeta * const r = wormhole_hmap_get_kref1_slot(hmap, midx, skey, ref, cid);
  if (r)
    return r;
  return wormhole_hmap_get_kref1_slot(hmap, midy, skey, ref, cid);
}

  static inline void
wormhole_hmap_squeeze(const struct wormhmap * const hmap)
{
  const u64 nrs = hmap->mask + 1lu;
  struct wormslot * const wmap = hmap->wmap;
  struct kvbucket * const pmap = hmap->pmap;
  const u64 mask = hmap->mask;
  for (u64 si = 0; si < nrs; si++) { // # of buckets
    u64 ci = wormhole_hmap_count_entry(hmap, si);
    for (u64 ei = ci - 1; ei < KVBUCKET_NR; ei--) {
      struct wormmeta * const meta = u64_to_ptr(pmap[si].e[ei].e3);
      const u64 sj = crc32c_extend(meta->hash32) & mask; // first hash
      if (sj == si)
        continue;

      // move
      const u64 ej = wormhole_hmap_count_entry(hmap, sj);
      if (ej < KVBUCKET_NR) { // has space at home location
        wmap[sj].t[ej] = wmap[si].t[ei];
        pmap[sj].e[ej] = pmap[si].e[ei];
        const u64 ni = ci - 1lu;
        if (ei < ni) {
          wmap[si].t[ei] = wmap[si].t[ni];
          pmap[si].e[ei] = pmap[si].e[ni];
        }
        wmap[si].t[ni] = 0u;
        pmap[si].e[ni].v64 = 0lu;
        ci--;
      }
    }
  }
}

  static inline bool
wormhole_hmap_expand(struct wormhmap * const hmap)
{
  // sync expand
  const u64 mask0 = hmap->mask;
  const u64 nr0 = mask0 + 1lu;
  const u64 mask1 = mask0 + nr0;
  const u64 nr1 = nr0 << 1;
  const u64 wsize = nr1 * sizeof(hmap->wmap[0]);
  const u64 psize = nr1 * sizeof(hmap->pmap[0]);
  u64 msize = bits_round_up(wsize + psize, 21);
  u8 * const mem = pages_alloc_best(msize, true, &msize);
  if (mem == NULL)
    return false;

  struct wormhmap hmap1 = *hmap;
  hmap1.pmap = (typeof(hmap1.pmap))mem;
  hmap1.wmap = (typeof(hmap1.wmap))(mem + psize);
  hmap1.msize = msize;
  hmap1.mask = mask1;

  const struct kvbucket * const pmap0 = hmap->pmap;

  for (u64 s = 0; s < nr0; s++) {
    const struct entry13 * e = &(pmap0[s].e[0]);
    for (u64 i = 0; (i < KVBUCKET_NR) && e->v64; i++, e++) {
      const struct wormmeta * const meta = u64_to_ptr(e->e3);
      const u64 hash = crc32c_extend(meta->hash32);
      const u64 pkey = kvmap_pkey(hash);
      const u64 idx0 = hash & mask0;
      const u64 idx1 = ((idx0 == s) ? hash : bswap_64(hash)) & mask1;

      const u64 n = wormhole_hmap_count_entry(&hmap1, idx1);
      debug_assert(n < 8lu);
      hmap1.wmap[idx1].t[n] = wormhole_hmap_skey(pkey);
      hmap1.pmap[idx1].e[n].e1 = pkey;
      hmap1.pmap[idx1].e[n].e3 = ptr_to_u64(meta);
    }
  }
  pages_unmap(hmap->pmap, hmap->msize);
  *hmap = hmap1;
  wormhole_hmap_squeeze(hmap);
  return true;
}

  static inline bool
wormhole_hmap_cuckoo(struct wormhmap * const hmap, const u64 mid0,
    const struct entry13 e0, const u64 depth)
{
  const u64 ii = wormhole_hmap_count_entry(hmap, mid0);
  if (ii < KVBUCKET_NR) {
    hmap->wmap[mid0].t[ii] = wormhole_hmap_skey(e0.e1);
    hmap->pmap[mid0].e[ii] = e0;
    return true;
  } else if (depth == 0lu) {
    return false;
  }

  // depth > 0
  struct entry13 * e = &(hmap->pmap[mid0].e[0]);
  for (u64 i = 0; (i < KVBUCKET_NR) && e->v64; i++, e++) {
    const struct wormmeta * const meta = u64_to_ptr(e->e3);
    const u64 hash = crc32c_extend(meta->hash32);

    const u64 midx = hash & hmap->mask;
    const u64 midy = bswap_64(hash) & hmap->mask;
    const u64 midt = (midx != mid0) ? midx : midy;
    if (midt != mid0) { // possible
      // no penalty if moving someone back to its 1st place
      const u64 depth1 = (midt == midx) ? depth : (depth - 1);
      if (wormhole_hmap_cuckoo(hmap, midt, *e, depth1)) {
        *e = e0;
        hmap->wmap[mid0].t[i] = wormhole_hmap_skey(e0.e1);
        return true;
      }
    }
  }
  return false;
}

  static bool
wormhole_hmap_set(struct wormhmap * const hmap, const struct wormmeta * const meta)
{
  const u64 hash = crc32c_extend(meta->hash32);
  const u64 midx = hash & hmap->mask;
  cpu_prefetchr(&(hmap->pmap[midx]), 0);
  const u64 midy = bswap_64(hash) & hmap->mask;
  cpu_prefetchr(&(hmap->pmap[midy]), 0);
  const u64 pkey = kvmap_pkey(hash);

  const struct entry13 e = {.e1 = pkey, .e3 = ptr_to_u64(meta)};
  // insert with cuckoo
  if (wormhole_hmap_cuckoo(hmap, midx, e, 1))
    return true;
  if (wormhole_hmap_cuckoo(hmap, midy, e, 1))
    return true;
  if (wormhole_hmap_cuckoo(hmap, midx, e, 2))
    return true;

  // expand
  if (wormhole_hmap_expand(hmap) == false)
    return false;

  return wormhole_hmap_set(hmap, meta);
}

  static bool
wormhole_hmap_del_slot(struct wormhmap * const hmap, const u64 mid,
    const struct kv * const key, const __m128i skey)
{
  u64 mask = wormhole_hmap_peek_slot(&(hmap->wmap[mid]), skey);
  while (mask) {
    const u32 i = __builtin_ctzl(mask) >> 1;
    const struct wormmeta * const meta = u64_to_ptr(hmap->pmap[mid].e[i].e3);
    if (wormhole_key_meta_match(key, meta)) {
      const u64 j = wormhole_hmap_count_entry(hmap, mid) - 1lu;
      hmap->wmap[mid].t[i] = hmap->wmap[mid].t[j];
      hmap->wmap[mid].t[j] = 0u;
      hmap->pmap[mid].e[i] = hmap->pmap[mid].e[j];
      hmap->pmap[mid].e[j].v64 = 0lu;
      return true;
    }
    mask -= (3u << (i << 1));
  }
  return false;
}

  static bool
wormhole_hmap_del(struct wormhmap * const hmap, const struct kv * const key)
{
  const u64 hash = key->hash;
  const u64 midx = hash & hmap->mask;
  cpu_prefetchr(&(hmap->pmap[midx]), 0);
  const u64 midy = bswap_64(hash) & hmap->mask;
  cpu_prefetchr(&(hmap->pmap[midy]), 0);
  const __m128i skey = _mm_set1_epi16(wormhole_hmap_skey(kvmap_pkey(hash)));
  return wormhole_hmap_del_slot(hmap, midx, key, skey)
    || wormhole_hmap_del_slot(hmap, midy, key, skey);
}

  static bool
wormhole_hmap_init(struct wormhmap * const hmap, struct wormhole * const map, const u64 i)
{
  const u64 nr = WH_HMAPINIT_SIZE;
  const u64 wsize = sizeof(hmap->wmap[0]) * nr;
  const u64 psize = sizeof(hmap->pmap[0]) * nr;
  u64 msize = bits_round_up(wsize + psize, 21);
  u8 * const mem = pages_alloc_best(msize, true, &msize);
  if (mem == NULL)
    return false;
  hmap->pmap = (typeof(hmap->pmap))mem;
  hmap->wmap = (typeof(hmap->wmap))(mem + psize);
  hmap->msize = msize;
  hmap->mask = nr - 1lu;
  hmap->version = 0;
  hmap->map = map;
  hmap->maxplen = 0u;
  hmap->hmap_id = i;
  return true;
}
// }}} hmap

// create {{{
// it's unsafe
  static void
wormhole_create_leaf0(struct wormhole * const map)
{
  // create leaf of empty key
  struct kv * const anchor = wormhole_alloc_akey(0);
  debug_assert(anchor);
  kv_refill(anchor, NULL, 0, NULL, 0);
  struct wormleaf * const leaf0 = wormhole_alloc_leaf(map, NULL, NULL, anchor);
  debug_assert(leaf0);
  map->leaf0 = leaf0;

  struct kv * const mkey = wormhole_alloc_mkey(1);
  debug_assert(mkey);
  memset(mkey, 0, sizeof(*mkey) + 1);
  wormhole_prefix(mkey, 1);
  const u64 hash = crc32c_extend(CRC32C_SEED);
  // create meta of empty key
  for (u64 i = 0; i < 2; i++) {
    struct wormmeta * const m0 = wormhole_alloc_meta_keyref(map->slab_meta[i], leaf0, mkey, hash, 0);
    debug_assert(m0);
    const bool rset = wormhole_hmap_set(&(map->hmap2[i]), m0);
    (void)rset;
    debug_assert(rset);
  }
}

  struct wormhole *
wormhole_create(const struct kvmap_mm * const mm)
{
  // TODO: fail gracefully if some memory allocations cannot be made
  struct wormhole * const map = yalloc(sizeof(*map));
  debug_assert(map);
  memset(map, 0, sizeof(*map));
  // mm
  map->mm = mm ? (*mm) : kvmap_mm_default;

  // hmap
  for (u64 i = 0; i < 2; i++) {
    const bool r = wormhole_hmap_init(&(map->hmap2[i]), map, i);
    debug_assert(r);
    (void)r;
    map->hmap2[i].sibling = &(map->hmap2[1-i]);
  }

  // slabs
  map->slab_meta[0] = slab_create(sizeof(struct wormmeta), WH_SLABMETA_SIZE);
  map->slab_meta[1] = slab_create(sizeof(struct wormmeta), WH_SLABMETA_SIZE);
  map->slab_leaf = slab_create(sizeof(struct wormleaf), WH_SLABLEAF_SIZE);
  debug_assert(map->slab_meta[0]);
  debug_assert(map->slab_meta[1]);
  debug_assert(map->slab_leaf);

  // others
  map->qsbr = qsbr_create();
  debug_assert(map->qsbr);
  wormhole_create_leaf0(map);
  rwlock_init(&(map->metalock));
  map->hmap = &(map->hmap2[0]);
  return map;
}
// }}} create

// get {{{

// jump {{{
// search for a wormmeta in the hash table that has the longest prefix match of the requested key
// the corresponding prefix is left at [pbuf] for callers to use at return
  static inline struct wormmeta *
wormhole_meta_up(const struct wormhmap * const hmap, struct wormkref * const ref)
{
  // invariant: lo <= lp < hi
  // finish condition: (lo + 1) == hi
  u32 lo = 0u;
  u32 hi = (hmap->maxplen < ref->klen ? hmap->maxplen : ref->klen) + 1u;
  u64 seed = crc32c_extend(CRC32C_SEED);

#define META_UP_GAP_1 ((7u))
  while ((lo + META_UP_GAP_1) < hi) {
    const u32 pm = ((lo + hi) >> 3) << 2; // x4
    wormhole_kref_inc_x4(ref, pm, (u32)seed, lo);
    if (wormhole_hmap_peek(hmap, ref->hash)) {
      seed = ref->hash;
      lo = pm;
    } else {
      hi = pm;
    }
  }

  while ((lo + 1) < hi) {
    const u32 pm = (lo + hi) >> 1;
    wormhole_kref_inc_short_nz(ref, pm, (u32)seed, lo);
    if (wormhole_hmap_peek(hmap, ref->hash)) {
      seed = ref->hash;
      lo = pm;
    } else {
      hi = pm;
    }
  }

  if (ref->plen != lo) {
    ref->hash = seed;
    ref->plen = lo;
  }
  struct wormmeta * ret = wormhole_hmap_get_kref(hmap, ref);
  if (ret)
    return ret;

  hi = lo;
  lo = 0u;
  seed = crc32c_extend(CRC32C_SEED);

#define META_UP_GAP_2 ((5u))
  while ((lo + META_UP_GAP_2) < hi) {
    const u32 pm = (lo + hi + hi + hi) >> 2;
    wormhole_kref_inc_long(ref, pm, (u32)seed, lo);
    struct wormmeta * const tmp = wormhole_hmap_get_kref(hmap, ref);
    if (tmp) {
      seed = ref->hash;
      lo = pm;
      ret = tmp;
      if (wormhole_meta_bm_test(tmp, ref->key[pm])) {
        lo++;
        seed = crc32c_extend(_mm_crc32_u8((u32)seed, ref->key[pm]));
        ret = NULL;
      } else {
        hi = pm + 1;
        break;
      }
    } else {
      hi = pm;
    }
  }

  while ((lo + 1) < hi) {
    const u32 pm = (lo + hi + hi + hi) >> 2;
    wormhole_kref_inc_short_nz(ref, pm, (u32)seed, lo);
    struct wormmeta * const tmp = wormhole_hmap_get_kref(hmap, ref);
    if (tmp) {
      seed = ref->hash;
      lo = pm;
      ret = tmp;
      if (wormhole_meta_bm_test(tmp, ref->key[pm])) {
        lo++;
        seed = crc32c_extend(_mm_crc32_u8((u32)seed, ref->key[pm]));
        ret = NULL;
      } else {
        hi = pm + 1;
        break;
      }
    } else {
      hi = pm;
    }
  }

  if (ref->plen != lo) {
    ref->hash = seed;
    ref->plen = lo;
  }
  if (ret == NULL)
    ret = wormhole_hmap_get_kref(hmap, ref);
  debug_assert(ret);
  // ref->plen is the current depth, will be used in down()
  // ref now contains the prefix of meta-root
  return ret;
}
#undef META_UP_GAP_1
#undef META_UP_GAP_2

// pbuf: the current matched prefix of node
// klen0: the real key's len
  static inline struct wormleaf *
wormhole_meta_down(const struct wormhmap * const hmap, const struct wormkref * const ref,
    const struct wormmeta * const meta)
{
  struct wormleaf * ret;
  if (ref->plen < ref->klen) {
    const u32 id0 = ref->key[ref->plen];
    debug_assert(meta->bitmin != id0);
    if (meta->bitmin > id0) {
      ret = meta->lmost;
      if (meta->bitmin < WH_FO) {
        ret = ret->prev;
        cpu_prefetchr(ret, 0);
      }
    } else {
      const u32 id1 = wormhole_meta_bm_lt(meta, id0);
      const struct wormmeta * const child = wormhole_hmap_get_kref1(hmap, ref, id1);
      ret = child->rmost;
    }
  } else {
    // plen == klen
    debug_assert(ref->plen == ref->klen);
    ret = meta->lmost;
    if (ret->klen > ref->plen) {
      ret = ret->prev;
      cpu_prefetchr(ret, 0);
    }
  }
  return ret;
}

  static struct wormleaf *
wormhole_jump_leaf(const struct wormhmap * const hmap, const struct kv * const key)
{
  struct wormkref ref = {.hash = key->hash, .plen = key->klen, .klen = key->klen, .key = key->kv};

  const struct wormmeta * const meta = wormhole_meta_up(hmap, &ref);
  struct wormleaf * const leaf = wormhole_meta_down(hmap, &ref, meta);
  const u64 i = kvmap_pkey(key->hash) / WH_HDIV;
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
    } while (leaf->version <= v);
  } while (true);
}
// }}} jump

// leaf-only {{{
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
  const u64 pkey = kvmap_pkey(key->hash);
  const u64 i0 = pkey / WH_HDIV;
  const struct entry13 * const eh = leaf->eh;
  if (eh[i0].v64 == 0)
    return WH_KPN;

  if (eh[i0].e1 == pkey) {
    struct kv * const curr = u64_to_ptr(eh[i0].e3);
    if (kv_keymatch(key, curr))
      return i0;
  }

  // search left
  u64 i = i0 - 1;
  while ((i < WH_KPN) && eh[i].v64 && (eh[i].e1 >= pkey)) {
    if (eh[i].e1 == pkey) {
      struct kv * const curr = u64_to_ptr(eh[i].e3);
      if (kv_keymatch(key, curr))
        return i;
    }
    i--;
  }

  // search right
  i = i0 + 1;
  while ((i < WH_KPN) && eh[i].v64 && (eh[i].e1 <= pkey)) {
    if (eh[i].e1 == pkey) {
      struct kv * const curr = u64_to_ptr(eh[i].e3);
      if (kv_keymatch(key, curr))
        return i;
    }
    i++;
  }

  // not found
  return WH_KPN;
}

  static inline struct kv *
wormhole_leaf_get(const struct wormleaf * const leaf, const struct kv * const key)
{
  const u64 i = wormhole_leaf_match(leaf, key);
  if (i < WH_KPN)
    return u64_to_ptr(leaf->eh[i].e3);
  else
    return NULL;
}
// }}} leaf-only

// get/probe {{{
  struct kv *
wormhole_get(struct wormref * const ref, const struct kv * const key, struct kv * const out)
{
  struct wormleaf * const leaf = wormhole_jump_leaf_read(ref, key);
  struct kv * tmp = wormhole_leaf_get(leaf, key);
  if (tmp) // found
    tmp = kv_dup2(tmp, out);
  rwlock_unlock_read(&(leaf->leaflock));
  return tmp;
}

  struct sbuf *
wormhole_getv(struct wormref * const ref, const struct kv * const key, struct sbuf * const out)
{
  struct wormleaf * const leaf = wormhole_jump_leaf_read(ref, key);
  struct kv * const tmp = wormhole_leaf_get(leaf, key);
  struct sbuf * ret = NULL;
  if (tmp) // found
    ret = kv_dup2_sbuf(tmp, out);
  rwlock_unlock_read(&(leaf->leaflock));
  return ret;
}

  u64
wormhole_getu64(struct wormref * const ref, const struct kv * const key)
{
  struct wormleaf * const leaf = wormhole_jump_leaf_read(ref, key);
  struct kv * const tmp = wormhole_leaf_get(leaf, key);
  u64 ret = 0;
  if (tmp && (tmp->vlen >= 8)) // found and has value
    ret = *(const u64 *)(kv_vptr_c(tmp));
  rwlock_unlock_read(&(leaf->leaflock));
  return ret;
}

  bool
wormhole_probe(struct wormref * const ref, const struct kv * const key)
{
  struct wormleaf * const leaf = wormhole_jump_leaf_read(ref, key);
  struct kv * tmp = wormhole_leaf_get(leaf, key);
  rwlock_unlock_read(&(leaf->leaflock));
  return tmp ? true : false;
}

  struct kv *
wormhole_get_unsafe(struct wormhole * const map, const struct kv * const key, struct kv * const out)
{
  struct wormleaf * const leaf = wormhole_jump_leaf(map->hmap, key);
  struct kv * tmp = wormhole_leaf_get(leaf, key);
  if (tmp) // found
    tmp = kv_dup2(tmp, out);
  return tmp;
}

  struct sbuf *
wormhole_getv_unsafe(struct wormhole * const map, const struct kv * const key, struct sbuf * const out)
{
  struct wormleaf * const leaf = wormhole_jump_leaf(map->hmap, key);
  struct kv * const tmp = wormhole_leaf_get(leaf, key);
  struct sbuf * ret = NULL;
  if (tmp) // found
    ret = kv_dup2_sbuf(tmp, out);
  return ret;
}

  void *
wormhole_getp_unsafe(struct wormhole * const map, const struct kv * const key)
{
  struct wormleaf * const leaf = wormhole_jump_leaf(map->hmap, key);
  struct kv * const tmp = wormhole_leaf_get(leaf, key);
  void * ret = NULL;
  if (tmp) // found
    ret = *(void **)(kv_vptr(tmp));
  return ret;
}

  bool
wormhole_probe_unsafe(struct wormhole * const map, const struct kv * const key)
{
  struct wormleaf * const leaf = wormhole_jump_leaf(map->hmap, key);
  return wormhole_leaf_get(leaf, key) ? true : false;
}
// }}} get/probe

// }}} get

// set {{{

// leaf-only {{{
  static inline void
wormhole_leaf_sort_m2(struct entry13 * const es, const u64 n1, const u64 n2)
{
  if (n1 == 0 || n2 == 0)
    return; // no need to sort

  struct entry13 et[WH_KPN/2]; // min(n1,n2) < KPN/2
  if (n1 <= n2) { // merge left
    memmove(et, &(es[0]), sizeof(es[0]) * n1);
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
      memmove(eo, e1, sizeof(*eo) * (e2 - eo));
  } else {
    memmove(et, &(es[n1]), sizeof(es[0]) * n2);
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
      memmove(e1 + 1, et, sizeof(*eo) * (eo - e1));
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

  if ((n < 8) || (s < 4u) || (((s - 2u) << 2) < n)) { // too few sorted
    kvmap_entry_qsort(leaf->es, n);
  } else { // worth a two-step sort
    kvmap_entry_qsort(&(leaf->es[s]), n - s);
    // merge-sort inplace
    wormhole_leaf_sort_m2(leaf->es, s, (n - s));
  }
  leaf->nr_sorted = n;
}

  static void
wormhole_leaf_insert_eh(struct entry13 * const eh, const struct entry13 new)
{
  const u64 pkey = new.e1;
  const u32 i0 = pkey / WH_HDIV;
  if (eh[i0].v64 == 0) { // insert
    eh[i0] = new;
    return;
  }

  // find left-most insertion point
  u32 i = i0;
  while (i && eh[i-1].v64 && (eh[i-1].e1 >= pkey))
    i--;
  while ((i < WH_KPN) && eh[i].v64 && (eh[i].e1 < pkey)) // stop at >= or empty
    i++;
  const u32 il = --i; // i in [0, KPN]

  // find left empty slot
  if (i > (i0 - 1))
    i = i0 - 1;
  while ((i < WH_KPN) && eh[i].v64)
    i--;
  const u32 el = i; // el < i0 or el is invalid (>= KPN)

  // find right-most insertion point.
  i = il + 1;
  while ((i < WH_KPN) && eh[i].v64 && (eh[i].e1 == pkey))
    i++;
  const u32 ir = i; // ir >= il, in [0, KPN]

  // find right empty slot
  if (i < (i0 + 1))
    i = i0 + 1;
  while ((i < WH_KPN) && eh[i].v64)
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
  leaf->es[nr0].e1 = kvmap_pkey(new->hash);
  leaf->es[nr0].e3 = ptr_to_u64(new);
  // optimize for seq insertion
  if (nr0 == leaf->nr_sorted) {
    if (nr0) {
      const struct kv * const kv0 = u64_to_ptr(leaf->es[nr0 - 1].e3);
      if (kv_keycompare(new, kv0) > 0)
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
  while ((i < WH_KPN) && eh[i].v64 && ((eh[i].e1 / WH_HDIV) > i)) {
    eh[i+1] = eh[i];
    eh[i].v64 = 0;
    i--;
  }
  // return if moved
  if (eh[im].v64)
    return;

  // try right
  i = im + 1;
  while ((i < WH_KPN) && eh[i].v64 && ((eh[i].e1 / WH_HDIV) < i)) {
    eh[i-1] = eh[i];
    eh[i].v64 = 0;
    i++;
  }
  // eh[im] may still be 0
}

// test if leaf->es[ip] is a prefix of leaf->es[ik]
  static bool
wormhole_split_can_cut(const struct entry13 * const es, const u64 i1, const u64 i2)
{
  debug_assert(i1 < i2);
  const struct kv * const k1 = u64_to_ptr(es[i1].e3);
  const struct kv * const k2 = u64_to_ptr(es[i2].e3);
  // rule of no-cut: k1 and k2 have the same TTK.
  // first test if k1 is a prefix of k2, then trim k to see if it has a zero-tail.
  if (kv_key_is_prefix(k1, k2)) {
    u32 tklen = k2->klen;
    while ((tklen > k1->klen) && (k2->kv[tklen - 1u] == 0u))
      tklen--;
    if (tklen <= k1->klen)
      return false;
  }
  return true;
}

// assumes i1/i2 has been verified by split_can_cut
  static u32
wormhole_split_cut_alen(const struct entry13 * const es, const u64 i1, const u64 i2)
{
  debug_assert(i1 < i2);
  struct kv * const k1 = u64_to_ptr(es[i1].e3);
  struct kv * const k2 = u64_to_ptr(es[i2].e3);
  u32 alen = kv_key_lcp(k1, k2) + 1lu;
  while ((alen < k2->klen) && (k2->kv[alen - 1lu] == 0u))
    alen++;
  debug_assert(k2->kv[alen - 1lu]);
  return alen;
}

  static bool
wormhole_split_can_cut_alen(const struct entry13 * const es, const u64 i1, const u64 i2,
    const u32 alen)
{
  debug_assert(i1 < i2);
  struct kv * const k1 = u64_to_ptr(es[i1].e3);
  struct kv * const k2 = u64_to_ptr(es[i2].e3);
  const u8 c1 = (k1->klen < alen) ? 0u : k1->kv[alen - 1u];
  const u8 c2 = (k2->klen < alen) ? 0u : k2->kv[alen - 1u];
  return (c1 == c2) ? false : true;
}

// determine where to cut at leaf
  static u64
wormhole_split_cut(const struct wormleaf * const leaf)
{
  debug_assert(leaf->nr_keys == WH_KPN);
  debug_assert(leaf->nr_sorted == WH_KPN);
  const struct entry13 * const es = leaf->es;
  u64 lo = 0;
  u64 hi = WH_KPN - 1u;
  if (wormhole_split_can_cut(es, lo, hi) == false)
    return WH_KPN;

  const u32 alen = wormhole_split_cut_alen(es, lo, hi);
  while ((lo + 1u) < hi) {
    const u64 mid = (lo + hi + 1u) >> 1u;
    if (mid <= WH_MID) { // try right
      if (wormhole_split_can_cut_alen(es, mid, hi, alen))
        lo = mid;
      else
        hi = mid;
    } else { // try left
      if (wormhole_split_can_cut_alen(es, lo, mid, alen))
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

// create an anchor for leaf2
  static void
wormhole_split_anchor(struct wormleaf * const leaf1, struct wormleaf * const leaf2)
{
  struct kv * const key1 = u64_to_ptr(leaf1->es[leaf1->nr_sorted - 1lu].e3);
  struct kv * const key2 = u64_to_ptr(leaf2->es[0].e3);
  const u32 key2len = key2->klen;
  u32 alen = kv_key_lcp(key1, key2) + 1lu;

  // anchor must end with non-zero
  while ((alen < key2len) && (key2->kv[alen - 1u] == 0u))
    alen++;
  debug_assert(alen <= key2len);

  // now we have the correct alen
  struct kv * const anchor2 = wormhole_alloc_akey(alen);
  debug_assert(anchor2);
  kv_refill(anchor2, key2->kv, alen, NULL, 0);
  leaf2->anchor = anchor2;
  leaf2->klen = anchor2->klen;
}

  static void
wormhole_set_update(struct wormhole * const map, struct wormleaf * const leaf, const u64 im,
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
// }}} leaf-only

// split {{{
// all locked
// move keys starting with [cut] in leaf1 to leaf2
  static struct wormleaf *
wormhole_split_leaf(struct wormhole * const map, struct wormleaf * const leaf1, const u64 cut)
{
  // create leaf (2)
  struct wormleaf * const leaf2 = wormhole_alloc_leaf(map, leaf1, leaf1->next, NULL);
  if (leaf2 == NULL)
    return NULL;

  wormhole_split_leaf_move(leaf1, leaf2, cut);

  // anchor of leaf2
  wormhole_split_anchor(leaf1, leaf2);
  return leaf2;
}

  static void
wormhole_split_meta_new(struct wormhmap * const hmap, struct kv * const pbuf,
    struct wormleaf * const leaf, const bool bitmap)
{
  // create a new node
  struct slab * const slab = hmap->map->slab_meta[hmap->hmap_id];
  struct wormmeta * const meta = wormhole_alloc_meta(slab, leaf, pbuf);
  debug_assert(meta);

  if (bitmap)
    wormhole_meta_bm_set(meta, pbuf->kv[pbuf->klen]);

  wormhole_hmap_set(hmap, meta);
}

// meta->klen == pbuf->klen
  static void
wormhole_split_meta_extend(struct wormhmap * const hmap, struct wormmeta * const meta,
    const struct kv * const pbuf)
{
  debug_assert(meta->lmost == meta->rmost);
  debug_assert(meta->klen == pbuf->klen);
  wormhole_meta_bm_set(meta, 0u);
  const u32 len0 = pbuf->klen;
  const u32 len1 = len0 + 1u;
  struct wormleaf * const lmost = meta->lmost;
  struct slab * const slab = hmap->map->slab_meta[hmap->hmap_id];
  // new anchor at +1
  struct kv * const keyref = meta->keyref;
  if (keyref->klen > len0) { // can reuse keyref
    debug_assert(keyref->kv[len0] == 0u);
    const u64 hash1 = crc32c_extend(_mm_crc32_u8((u32)(pbuf->hash), 0));
    struct wormmeta * const meta1 = wormhole_alloc_meta_keyref(slab, lmost, keyref, hash1, len1);
    debug_assert(meta1);
    wormhole_hmap_set(hmap, meta1);
  } else {
    struct kv * const mkey1 = wormhole_alloc_mkey(len1);
    debug_assert(mkey1);
    kv_dup2_key(pbuf, mkey1);
    mkey1->kv[len0] = 0u;
    wormhole_prefix_inc_short(mkey1, len1);
    struct wormmeta * const meta1 = wormhole_alloc_meta(slab, lmost, mkey1);
    debug_assert(meta1);
    wormhole_hmap_set(hmap, meta1);
  }
}

// return true if a new node is created
  static bool
wormhole_split_meta_one(struct wormhmap * const hmap, struct kv * const pbuf,
    struct wormleaf * const leaf, const bool setchild)
{
  struct wormmeta * const meta = wormhole_hmap_get(hmap, pbuf);
  if (meta == NULL) {
    wormhole_split_meta_new(hmap, pbuf, leaf, setchild);
    return true;
  }

  // push down leaf
  if (meta->bitmin == WH_FO)
    wormhole_split_meta_extend(hmap, meta, pbuf);

  // mark leaf's child bit
  wormhole_meta_bm_set(meta, pbuf->kv[pbuf->klen]);

  // lmost rmost
  if (meta->lmost == leaf->next)
    meta->lmost = leaf;

  if (meta->rmost == leaf->prev)
    meta->rmost = leaf;
  return false;
}

// for leaf1, a leaf2 is already linked at its right side.
// this function updates the meta-map by moving leaf1 and hooking leaf2 at correct positions
  static void
wormhole_split_meta_hmap(struct wormhmap * const hmap, struct wormleaf * const leaf,
    struct kv * const mkey)
{
  const struct kv * const anchor = leaf->anchor;
  const u64 mhash = mkey->hash;
  const u32 mklen = mkey->klen;
  // child bit will be set base on this value

  // left branches
  const u32 lcp1 = kv_key_lcp(leaf->prev->anchor, leaf->anchor);
  const u32 lcp2 = leaf->next ? kv_key_lcp(leaf->anchor, leaf->next->anchor) : 0u;
  u32 i = (lcp1 < lcp2) ? lcp1 : lcp2;

  wormhole_prefix(mkey, i);
  while (i < anchor->klen) {
    wormhole_split_meta_one(hmap, mkey, leaf, true);
    i++;
    wormhole_prefix_inc_short(mkey, i);
  }

  if (!wormhole_split_meta_one(hmap, mkey, leaf, false)) {
    bool done = false;
    do {
      i++;
      struct kv * const pbuf = wormhole_alloc_mkey(i + 1);
      debug_assert(pbuf);
      kv_dup2_key(anchor, pbuf);
      memset(&(pbuf->kv[anchor->klen]), 0, i + 1 - anchor->klen);
      wormhole_prefix_inc_long(pbuf, i);
      done = wormhole_split_meta_one(hmap, pbuf, leaf, false);
      if (pbuf->refcnt == 0)
        wormhole_free_mkey(pbuf);
    } while (!done);
  }

  // adjust maxplen
  if (i > hmap->maxplen)
    hmap->maxplen = i;
  mkey->hash = mhash;
  mkey->klen = mklen;
}

// all locks will be released before returning
  static void
wormhole_split_meta_ref(struct wormref * const ref, struct wormleaf * const leaf2)
{
  struct kv * const mkey = wormhole_alloc_mkey(leaf2->anchor->klen + 2);
  debug_assert(mkey);
  kv_dup2_key(leaf2->anchor, mkey);
  mkey->kv[mkey->klen] = 0u;
  mkey->kv[mkey->klen + 1] = 0u;
  wormhole_prefix_inc_short(mkey, mkey->klen + 2);

  struct wormhole * const map = ref->map;
  // metalock
  while (rwlock_trylock_write_nr(&(map->metalock), 64) == false)
    ref->qstate = (u64)(map->hmap);

  cpu_cfence();
  struct wormhmap * const hmap0 = map->hmap;
  struct wormhmap * const hmap1 = hmap0->sibling;

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

  wormhole_split_meta_hmap(hmap1, leaf2, mkey);

  ref->qstate = (u64)(hmap1);
  // switch hmap
  map->hmap = hmap1;
  cpu_cfence();

  rwlock_unlock_write(&(leaf1->leaflock));
  rwlock_unlock_write(&(leaf2->leaflock));

  qsbr_wait(map->qsbr, (u64)hmap1);

  wormhole_split_meta_hmap(hmap0, leaf2, mkey);

  if (mkey->refcnt == 0) // this is possible
    wormhole_free_mkey(mkey);
  rwlock_unlock_write(&(map->metalock));
}

// all locks (metalock + leaflocks) will be released before returning
// leaf1->lock is already taken
  static bool
wormhole_split_insert(struct wormref * const ref, struct wormleaf * const leaf1,
    const struct kv * const new)
{
  wormhole_leaf_sync_sorted(leaf1);
  // check for a corner case that we don't handle for now.
  // TODO: Implement fat node.
  //       Option 1: a pointer in wormleaf pointing to the extra items
  //       Option 2: make eh/es dynamically allocated
  const u64 cut = wormhole_split_cut(leaf1);
  if (!(cut && (cut < leaf1->nr_keys))) {
    fprintf(stderr, "ERROR: Cannot split\n");
    debug_die();
  }

  struct wormhole * const map = ref->map;
  struct wormleaf * const leaf2 = wormhole_split_leaf(map, leaf1, cut);
  rwlock_lock_write(&(leaf2->leaflock));

  // the compare must regard the anchor's extensions
  const int cmp = kv_keycompare(new, leaf2->anchor);
  struct wormleaf * const leaf = (cmp < 0) ? leaf1 : leaf2;

  wormhole_leaf_insert(leaf, new);

  wormhole_split_meta_ref(ref, leaf2);
  return true;
}

  static void
wormhole_split_meta_unsafe(struct wormhole * const map, struct wormleaf * const leaf2)
{
  struct wormhmap * const hmap0 = map->hmap;

  // new versions
  struct wormleaf * const leaf1 = leaf2->prev;

  // link
  leaf1->next = leaf2;
  if (leaf2->next)
    leaf2->next->prev = leaf2;

  struct kv * const mkey = wormhole_alloc_mkey(leaf2->anchor->klen + 1);
  debug_assert(mkey);
  kv_dup2_key(leaf2->anchor, mkey);
  mkey->kv[mkey->klen] = 0u;
  wormhole_prefix_inc_short(mkey, mkey->klen + 1u);
  wormhole_split_meta_hmap(hmap0->sibling, leaf2, mkey);
  wormhole_split_meta_hmap(hmap0, leaf2, mkey);
  if (mkey->refcnt == 0) // this is possible
    wormhole_free_mkey(mkey);
}

  static bool
wormhole_split_insert_unsafe(struct wormhole * const map, struct wormleaf * const leaf1,
    const struct kv * const new)
{
  wormhole_leaf_sync_sorted(leaf1);
  // check for a corner case that we don't handle for now.
  // TODO: Implement fat node.
  //       Option 1: a pointer in wormleaf pointing to the extra items
  //       Option 2: make eh/es dynamically allocated
  const u64 cut = wormhole_split_cut(leaf1);
  debug_assert(cut && (cut < leaf1->nr_keys));

  struct wormleaf * const leaf2 = wormhole_split_leaf(map, leaf1, cut);

  // the compare must regard the anchor's extensions
  const int cmp = kv_keycompare(new, leaf2->anchor);
  struct wormleaf * const leaf = (cmp < 0) ? leaf1 : leaf2;

  wormhole_leaf_insert(leaf, new);

  wormhole_split_meta_unsafe(map, leaf2);
  return true;
}
// }}} split

// set {{{
  bool
wormhole_set(struct wormref * const ref, const struct kv * const kv0)
{
  struct wormhole * const map = ref->map;
  // we always allocate a new item on SET
  // future optimizations may perform in-place update
  struct kv * const new = wormhole_alloc_kv(map, kv0->klen, kv0->vlen);
  if (new == NULL)
    return false;
  kv_dup2(kv0, new);

  struct wormleaf * const leaf = wormhole_jump_leaf_write(ref, new);
  // update
  const u64 im = wormhole_leaf_match(leaf, new);
  if (im < WH_KPN) {
    wormhole_set_update(map, leaf, im, new);
    rwlock_unlock_write(&(leaf->leaflock));
    return true;
  }

  // insert
  if (leaf->nr_keys < WH_KPN) { // just insert
    wormhole_leaf_insert(leaf, new);
    rwlock_unlock_write(&(leaf->leaflock));
    return true;
  }

  // changes hmap
  return wormhole_split_insert(ref, leaf, new);
}

  bool
wormhole_set_unsafe(struct wormhole * const map, const struct kv * const kv0)
{
  struct kv * const new = wormhole_alloc_kv(map, kv0->klen, kv0->vlen);
  if (new == NULL)
    return false;
  kv_dup2(kv0, new);

  struct wormleaf * const leaf = wormhole_jump_leaf(map->hmap, new);
  // update
  const u64 im = wormhole_leaf_match(leaf, new);
  if (im < WH_KPN) { // overwrite
    wormhole_set_update(map, leaf, im, new);
    return true;
  }

  // insert
  if (leaf->nr_keys < WH_KPN) { // just insert
    wormhole_leaf_insert(leaf, new);
    return true;
  }

  // changes hmap
  return wormhole_split_insert_unsafe(map, leaf, new);
}
// }}} set

// }}} set

// del {{{
  static void
wormhole_leaf_del(struct wormhole * const map, struct wormleaf * const leaf, const u64 im)
{
  // remove from es
  const u64 nr_keys = leaf->nr_keys;
  const u64 v64 = leaf->eh[im].v64;
  debug_assert(v64);
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

  // remove from eh
  struct entry13 * const eh = leaf->eh;
  leaf->nr_keys--;
  kvmap_put_entry(&(map->mm), &(eh[im]), NULL);

  // use magnet
  wormhole_leaf_magnet_eh(eh, im);
}

// all go to leaf1
  static void
wormhole_merge_leaf_move(struct wormleaf * const leaf1, struct wormleaf * const leaf2)
{
  const u64 nr1 = leaf1->nr_keys;
  const u64 nr2 = leaf2->nr_keys;
  debug_assert((nr1 + nr2) <= WH_KPN);
  struct entry13 * const eh1 = leaf1->eh;
  struct entry13 * const eh2 = leaf2->eh;
  for (u64 i = 0; i < WH_KPN; i++) {
    // callers are merger, no need to clear eh2
    if (eh2[i].v64)
      wormhole_leaf_insert_eh(eh1, eh2[i]);
  }
  leaf1->nr_keys = nr1 + nr2; // nr_sorted remain unchanged
  // move es
  memcpy(&(leaf1->es[nr1]), &(leaf2->es[0]), sizeof(leaf2->es[0]) * nr2);
  // if already sorted
  if (leaf1->nr_sorted == nr1)
    leaf1->nr_sorted += leaf2->nr_sorted;
}

// all locks held
  static void
wormhole_merge_meta(struct wormhmap * const hmap, struct wormleaf * const leaf)
{
  struct wormleaf * const prev = leaf->prev;
  struct wormleaf * const next = leaf->next;
  const struct kv * const anchor0 = leaf->anchor;
  const u32 lcp1 = prev ? kv_key_lcp(prev->anchor, anchor0) : 0;
  const u32 lcp2 = next ? kv_key_lcp(next->anchor, anchor0) : 0;
  const u32 maxplen = hmap->maxplen;
  const u64 bsize = sizeof(struct kv) + maxplen;
  struct kv * const pbuf = malloc(bsize);
  debug_assert(pbuf);
  kv_dup2_key(anchor0, pbuf);
  u32 i = lcp1 < lcp2 ? lcp1 : lcp2;
  struct slab * const slab = hmap->map->slab_meta[hmap->hmap_id];
  // lmost & rmost
  struct wormmeta * parent = NULL;
  wormhole_prefix(pbuf, i);
  while (true) {
    debug_assert(i <= maxplen);
    struct wormmeta * const meta = wormhole_hmap_get(hmap, pbuf);
    debug_assert(meta);
    if (meta->lmost == meta->rmost) {
      debug_assert(meta->lmost == leaf);
      const u32 bitmin = meta->bitmin;
      wormhole_hmap_del(hmap, pbuf);
      wormhole_free_meta(slab, meta);
      if (parent) {
        wormhole_meta_bm_clear(parent, pbuf->kv[i - 1u]);
        parent = NULL;
      }
      if (bitmin == WH_FO)
        break;
    } else {
      if (meta->lmost == leaf)
        meta->lmost = next;

      if (meta->rmost == leaf)
        meta->rmost = prev;
      parent = meta;
    }
    if (i >= anchor0->klen)
      pbuf->kv[i] = 0u;
    i++;
    wormhole_prefix_inc_short(pbuf, i);
  }
  free(pbuf); // malloc-ed above
}

// all locks (metalock + two leaflock) will be released before returning
// merge leaf2 to leaf1, removing all metadata to leaf2 and leaf2 itself
  static void
wormhole_merge_ref(struct wormref * const ref, struct wormleaf * const leaf1,
    struct wormleaf * const leaf2)
{
  wormhole_merge_leaf_move(leaf1, leaf2);

  struct wormhole * const map = ref->map;
  struct wormhmap * const hmap0 = map->hmap;
  struct wormhmap * const hmap1 = hmap0->sibling;
  const u64 v1 = hmap0->version + 1;

  leaf1->next = leaf2->next;
  if (leaf2->next)
    leaf2->next->prev = leaf1;

  leaf1->version = v1;
  leaf2->version = v1;
  hmap1->version = v1;

  wormhole_merge_meta(hmap1, leaf2);
  ref->qstate = (u64)(hmap1);

  cpu_cfence();
  map->hmap = hmap1;
  cpu_cfence();

  rwlock_unlock_write(&(leaf1->leaflock));
  rwlock_unlock_write(&(leaf2->leaflock));

  qsbr_wait(map->qsbr, (u64)hmap1);

  wormhole_merge_meta(hmap0, leaf2);
  // leaf2 is now safe to be removed
  wormhole_free_akey(leaf2->anchor);
  slab_free(map->slab_leaf, leaf2);
  rwlock_unlock_write(&(map->metalock));
}

// all locks will be released before returning
// merge may fail if (1) too large combined; (2) didn't acquire lock before timeout
  static bool
wormhole_may_merge(struct wormref * const ref, struct wormleaf * const leaf)
{
  struct wormhole * const map = ref->map;
  while (rwlock_trylock_write_nr(&(map->metalock), 64) == false)
    ref->qstate = (u64)(map->hmap);

  // now leaf and meta are both locked (w)
  struct wormleaf * const next = leaf->next;
  debug_assert(next);
  if (rwlock_trylock_write_nr(&(next->leaflock), 64)) {
    // three locked
    if ((leaf->nr_keys + next->nr_keys) <= WH_KPN) {
      wormhole_merge_ref(ref, leaf, next);
      return true;
    }
    rwlock_unlock_write(&(next->leaflock));
  }

  rwlock_unlock_write(&(map->metalock));
  rwlock_unlock_write(&(leaf->leaflock));
  return false;
}

  static void
wormhole_force_merge(struct wormref * const ref, struct wormleaf * const leaf)
{
  struct wormhole * const map = ref->map;
  while (rwlock_trylock_write_nr(&(map->metalock), 64) == false)
    ref->qstate = (u64)(map->hmap);

  // now leaf and meta are both locked (w)
  struct wormleaf * const next = leaf->next;
  debug_assert(next);
  while (rwlock_trylock_write_nr(&(next->leaflock), 64) == false)
    ref->qstate = (u64)(map->hmap);
  // three locked
  wormhole_merge_ref(ref, leaf, next);
}

  bool
wormhole_del(struct wormref * const ref, const struct kv * const key)
{
  struct wormleaf * const leaf = wormhole_jump_leaf_write(ref, key);
  const u64 im = wormhole_leaf_match(leaf, key);
  bool r = false;
  if (im < WH_KPN) { // found
    wormhole_leaf_del(ref->map, leaf, im);
    r = true;

    // maybe merge
    if ((leaf->nr_keys == 0u) && leaf->next) {
      wormhole_force_merge(ref, leaf); // wormhole_force_merge releases the lock
      return r;
    }
    struct wormleaf * const next = leaf->next;
    if (next && ((leaf->nr_keys + next->nr_keys) < WH_KPN_MRG)) {
      (void)wormhole_may_merge(ref, leaf); // wormhole_may_merge releases the lock
      return r;
    }
  }

  rwlock_unlock_write(&(leaf->leaflock));
  return r;
}

  static void
wormhole_merge_unsafe(struct wormhole * const map, struct wormleaf * const leaf1,
    struct wormleaf * const leaf2)
{
  wormhole_merge_leaf_move(leaf1, leaf2);
  struct wormhmap * const hmap0 = map->hmap;

  leaf1->next = leaf2->next;
  if (leaf2->next)
    leaf2->next->prev = leaf1;
  wormhole_merge_meta(hmap0->sibling, leaf2);
  wormhole_merge_meta(hmap0, leaf2);
  wormhole_free_akey(leaf2->anchor);
  slab_free(map->slab_leaf, leaf2);
}

  bool
wormhole_del_unsafe(struct wormhole * const map, const struct kv * const key)
{
  struct wormleaf * const leaf = wormhole_jump_leaf(map->hmap, key);
  const u64 im = wormhole_leaf_match(leaf, key);
  if (im < WH_KPN) { // found
    wormhole_leaf_del(map, leaf, im);

    struct wormleaf * const next = leaf->next;
    if (next && ((leaf->nr_keys + next->nr_keys) < WH_KPN_MRG))
      wormhole_merge_unsafe(map, leaf, next);
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
  debug_assert(iter);
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

  struct kv *
wormhole_iter_next(struct wormhole_iter * const iter, struct kv * const out)
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
  debug_assert(iter->leaf);
  debug_assert(iter->next_id < iter->leaf->nr_sorted);
  struct kv * const kv = u64_to_ptr(iter->leaf->es[iter->next_id].e3);
  struct kv * const ret = kv_dup2(kv, out);
  iter->next_id++;
  return ret;
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
wormhole_iter_create_unsafe(struct wormhole * const map)
{
  struct wormhole_iter * const iter = malloc(sizeof(*iter));
  debug_assert(iter);
  iter->map = map;
  iter->leaf = NULL;
  iter->next_id = 0;
  wormhole_iter_seek_unsafe(iter, NULL);
  return iter;
}

  void
wormhole_iter_seek_unsafe(struct wormhole_iter * const iter, const struct kv * const key)
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

  struct kv *
wormhole_iter_next_unsafe(struct wormhole_iter * const iter, struct kv * const out)
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
  debug_assert(iter->leaf);
  debug_assert(iter->next_id < iter->leaf->nr_sorted);
  struct kv * const kv = u64_to_ptr(iter->leaf->es[iter->next_id].e3);
  struct kv * const ret = kv_dup2(kv, out);
  iter->next_id++;
  return ret;
}

  void
wormhole_iter_destroy_unsafe(struct wormhole_iter * const iter)
{
  free(iter);
}
// }}} unsafe iter

// misc {{{
  inline struct wormref *
wormhole_ref(struct wormhole * const map)
{
  struct wormref * const ref = malloc(sizeof(*ref));
  debug_assert(ref);
  ref->qstate = 0lu;
  ref->map = map;
  // gently wait if full
  while (qsbr_register(map->qsbr, &(ref->qstate)) == false)
    usleep(1000);
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

// unsafe
  static void
wormhole_clean1(struct wormhole * const map)
{
  // meta
  for (u64 x = 0; x < 2; x++) {
    const u64 nr_slots = map->hmap2[x].mask + 1lu;
    for (u64 s = 0; s < nr_slots; s++) {
      struct kvbucket * const slot = &(map->hmap2[x].pmap[s]);
      for (u64 i = 0; i < KVBUCKET_NR; i++) {
        struct entry13 * const e = &(slot->e[i]);
        if (e->v64 == 0lu)
          continue;
        struct wormmeta * const meta = u64_to_ptr(e->e3);
        wormhole_free_meta(map->slab_meta[x], meta);
        e->v64 = 0lu;
        map->hmap2[x].wmap[s].t[i] = 0u;
      }
    }
    map->hmap2[x].maxplen = 0u;
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
    pages_unmap(map->hmap2[x].pmap, map->hmap2[x].msize);
  qsbr_destroy(map->qsbr);
  slab_destroy(map->slab_meta[0]);
  slab_destroy(map->slab_meta[1]);
  slab_destroy(map->slab_leaf);
  free(map);
}
// }}} misc

// undef {{{
#undef WH_KPN
#undef WH_MID
#undef WH_KPN_MRG
#undef WH_FO
#undef WH_BMNR
// }}} undef

// }}} wormhole

// fdm: marker
