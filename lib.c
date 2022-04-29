/*
 * Copyright (c) 2016--2021  Wu, Xingbo <wuxb45@gmail.com>
 *
 * All rights reserved. No warranty, explicit or implicit, provided.
 */
#define _GNU_SOURCE

// headers {{{
#include "lib.h"
#include "ctypes.h"
#include <assert.h>
#include <execinfo.h>
#include <math.h>
#include <netdb.h>
#include <sched.h>
#include <signal.h>
#include <sys/socket.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <time.h>
#include <stdarg.h> // va_start

#if defined(__linux__)
#include <linux/fs.h>
#include <malloc.h>  // malloc_usable_size
#elif defined(__APPLE__) && defined(__MACH__)
#include <sys/disk.h>
#include <malloc/malloc.h>
#elif defined(__FreeBSD__)
#include <sys/disk.h>
#include <malloc_np.h>
#endif // OS

#if defined(__FreeBSD__)
#include <pthread_np.h>
#endif
// }}} headers

// cpucache {{{
  inline void
cpu_pause(void)
{
#if defined(__x86_64__)
  _mm_pause();
#elif defined(__aarch64__)
  // nop
#endif
}

  inline void
cpu_mfence(void)
{
  atomic_thread_fence(MO_SEQ_CST);
}

// compiler fence
  inline void
cpu_cfence(void)
{
  atomic_thread_fence(MO_ACQ_REL);
}

  inline void
cpu_prefetch0(const void * const ptr)
{
  __builtin_prefetch(ptr, 0, 0);
}

  inline void
cpu_prefetch1(const void * const ptr)
{
  __builtin_prefetch(ptr, 0, 1);
}

  inline void
cpu_prefetch2(const void * const ptr)
{
  __builtin_prefetch(ptr, 0, 2);
}

  inline void
cpu_prefetch3(const void * const ptr)
{
  __builtin_prefetch(ptr, 0, 3);
}

  inline void
cpu_prefetchw(const void * const ptr)
{
  __builtin_prefetch(ptr, 1, 0);
}
// }}} cpucache

// crc32c {{{
  inline u32
crc32c_u8(const u32 crc, const u8 v)
{
#if defined(__x86_64__)
  return _mm_crc32_u8(crc, v);
#elif defined(__aarch64__)
  return __crc32cb(crc, v);
#endif
}

  inline u32
crc32c_u16(const u32 crc, const u16 v)
{
#if defined(__x86_64__)
  return _mm_crc32_u16(crc, v);
#elif defined(__aarch64__)
  return __crc32ch(crc, v);
#endif
}

  inline u32
crc32c_u32(const u32 crc, const u32 v)
{
#if defined(__x86_64__)
  return _mm_crc32_u32(crc, v);
#elif defined(__aarch64__)
  return __crc32cw(crc, v);
#endif
}

  inline u32
crc32c_u64(const u32 crc, const u64 v)
{
#if defined(__x86_64__)
  return (u32)_mm_crc32_u64(crc, v);
#elif defined(__aarch64__)
  return (u32)__crc32cd(crc, v);
#endif
}

  inline u32
crc32c_inc_123(const u8 * buf, u32 nr, u32 crc)
{
  if (nr == 1)
    return crc32c_u8(crc, buf[0]);

  crc = crc32c_u16(crc, *(u16 *)buf);
  return (nr == 2) ? crc : crc32c_u8(crc, buf[2]);
}

  inline u32
crc32c_inc_x4(const u8 * buf, u32 nr, u32 crc)
{
  //debug_assert((nr & 3) == 0);
  const u32 nr8 = nr >> 3;
#pragma nounroll
  for (u32 i = 0; i < nr8; i++)
    crc = crc32c_u64(crc, ((u64*)buf)[i]);

  if (nr & 4u)
    crc = crc32c_u32(crc, ((u32*)buf)[nr8<<1]);
  return crc;
}

  u32
crc32c_inc(const u8 * buf, u32 nr, u32 crc)
{
  crc = crc32c_inc_x4(buf, nr, crc);
  const u32 nr123 = nr & 3u;
  return nr123 ? crc32c_inc_123(buf + nr - nr123, nr123, crc) : crc;
}
// }}} crc32c

// debug {{{
#ifndef NDEBUG
  void
debug_assert(const bool v)
{
  assert(v);
}
#endif

__attribute__((noreturn))
  void
debug_die(void)
{
  assert(false);
}
// }}} debug

// mm {{{
#ifdef ALLOCFAIL
  bool
alloc_fail(void)
{
#define ALLOCFAIL_RECP ((64lu))
#define ALLOCFAIL_MAGIC ((ALLOCFAIL_RECP / 3lu))
  return ((random_u64() % ALLOCFAIL_RECP) == ALLOCFAIL_MAGIC);
}

#ifdef MALLOCFAIL
extern void * __libc_malloc(size_t size);
  void *
malloc(size_t size)
{
  if (alloc_fail())
    return NULL;
  return __libc_malloc(size);
}

extern void * __libc_calloc(size_t nmemb, size_t size);
  void *
calloc(size_t nmemb, size_t size)
{
  if (alloc_fail())
    return NULL;
  return __libc_calloc(nmemb, size);
}

extern void *__libc_realloc(void *ptr, size_t size);

  void *
realloc(void *ptr, size_t size)
{
  if (alloc_fail())
    return NULL;
  return __libc_realloc(ptr, size);
}
#endif // MALLOC_FAIL
#endif // ALLOC_FAIL

  void *
xalloc(const size_t align, const size_t size)
{
#ifdef ALLOCFAIL
  if (alloc_fail())
    return NULL;
#endif
  void * p;
  return (posix_memalign(&p, align, size) == 0) ? p : NULL;
}

// alloc cache-line aligned address
  void *
yalloc(const size_t size)
{
#ifdef ALLOCFAIL
  if (alloc_fail())
    return NULL;
#endif
  void * p;
  return (posix_memalign(&p, 64, size) == 0) ? p : NULL;
}

  void **
malloc_2d(const size_t nr, const size_t size)
{
  const size_t size1 = nr * sizeof(void *);
  const size_t size2 = nr * size;
  void ** const mem = malloc(size1 + size2);
  u8 * const mem2 = ((u8 *)mem) + size1;
  for (size_t i = 0; i < nr; i++)
    mem[i] = mem2 + (i * size);
  return mem;
}

  inline void **
calloc_2d(const size_t nr, const size_t size)
{
  void ** const ret = malloc_2d(nr, size);
  memset(ret[0], 0, nr * size);
  return ret;
}

  inline void
pages_unmap(void * const ptr, const size_t size)
{
#ifndef HEAPCHECKING
  munmap(ptr, size);
#else
  (void)size;
  free(ptr);
#endif
}

  void
pages_lock(void * const ptr, const size_t size)
{
  static bool use_mlock = true;
  if (use_mlock) {
    const int ret = mlock(ptr, size);
    if (ret != 0) {
      use_mlock = false;
      fprintf(stderr, "%s: mlock disabled\n", __func__);
    }
  }
}

#ifndef HEAPCHECKING
  static void *
pages_do_alloc(const size_t size, const int flags)
{
  // vi /etc/security/limits.conf
  // * - memlock unlimited
  void * const p = mmap(NULL, size, PROT_READ | PROT_WRITE, flags, -1, 0);
  if (p == MAP_FAILED)
    return NULL;

  pages_lock(p, size);
  return p;
}

#if defined(__linux__) && defined(MAP_HUGETLB)

#if defined(MAP_HUGE_SHIFT)
#define PAGES_FLAGS_1G ((MAP_HUGETLB | (30 << MAP_HUGE_SHIFT)))
#define PAGES_FLAGS_2M ((MAP_HUGETLB | (21 << MAP_HUGE_SHIFT)))
#else // MAP_HUGE_SHIFT
#define PAGES_FLAGS_1G ((MAP_HUGETLB))
#define PAGES_FLAGS_2M ((MAP_HUGETLB))
#endif // MAP_HUGE_SHIFT

#else
#define PAGES_FLAGS_1G ((0))
#define PAGES_FLAGS_2M ((0))
#endif // __linux__

#endif // HEAPCHECKING

  inline void *
pages_alloc_1gb(const size_t nr_1gb)
{
  const u64 sz = nr_1gb << 30;
#ifndef HEAPCHECKING
  return pages_do_alloc(sz, MAP_PRIVATE | MAP_ANONYMOUS | PAGES_FLAGS_1G);
#else
  void * const p = xalloc(1lu << 21, sz); // Warning: valgrind fails with 30
  if (p)
    memset(p, 0, sz);
  return p;
#endif
}

  inline void *
pages_alloc_2mb(const size_t nr_2mb)
{
  const u64 sz = nr_2mb << 21;
#ifndef HEAPCHECKING
  return pages_do_alloc(sz, MAP_PRIVATE | MAP_ANONYMOUS | PAGES_FLAGS_2M);
#else
  void * const p = xalloc(1lu << 21, sz);
  if (p)
    memset(p, 0, sz);
  return p;
#endif
}

  inline void *
pages_alloc_4kb(const size_t nr_4kb)
{
  const size_t sz = nr_4kb << 12;
#ifndef HEAPCHECKING
  return pages_do_alloc(sz, MAP_PRIVATE | MAP_ANONYMOUS);
#else
  void * const p = xalloc(1lu << 12, sz);
  if (p)
    memset(p, 0, sz);
  return p;
#endif
}

  void *
pages_alloc_best(const size_t size, const bool try_1gb, u64 * const size_out)
{
#ifdef ALLOCFAIL
  if (alloc_fail())
    return NULL;
#endif
  // 1gb huge page: at least 0.25GB
  if (try_1gb) {
    if (size >= (1lu << 28)) {
      const size_t nr_1gb = bits_round_up(size, 30) >> 30;
      void * const p1 = pages_alloc_1gb(nr_1gb);
      if (p1) {
        *size_out = nr_1gb << 30;
        return p1;
      }
    }
  }

  // 2mb huge page: at least 0.5MB
  if (size >= (1lu << 19)) {
    const size_t nr_2mb = bits_round_up(size, 21) >> 21;
    void * const p2 = pages_alloc_2mb(nr_2mb);
    if (p2) {
      *size_out = nr_2mb << 21;
      return p2;
    }
  }

  const size_t nr_4kb = bits_round_up(size, 12) >> 12;
  void * const p3 = pages_alloc_4kb(nr_4kb);
  if (p3)
    *size_out = nr_4kb << 12;
  return p3;
}
// }}} mm

// locking {{{

// spinlock {{{
#if defined(__linux__)
#define SPINLOCK_PTHREAD
#endif // __linux__

#if defined(SPINLOCK_PTHREAD)
static_assert(sizeof(pthread_spinlock_t) <= sizeof(spinlock), "spinlock size");
#else // SPINLOCK_PTHREAD
static_assert(sizeof(au32) <= sizeof(spinlock), "spinlock size");
#endif // SPINLOCK_PTHREAD

  void
spinlock_init(spinlock * const lock)
{
#if defined(SPINLOCK_PTHREAD)
  pthread_spinlock_t * const p = (typeof(p))lock;
  pthread_spin_init(p, PTHREAD_PROCESS_PRIVATE);
#else // SPINLOCK_PTHREAD
  au32 * const p = (typeof(p))lock;
  atomic_store_explicit(p, 0, MO_RELEASE);
#endif // SPINLOCK_PTHREAD
}

  inline void
spinlock_lock(spinlock * const lock)
{
#if defined(CORR)
#pragma nounroll
  while (!spinlock_trylock(lock))
    corr_yield();
#else // CORR
#if defined(SPINLOCK_PTHREAD)
  pthread_spinlock_t * const p = (typeof(p))lock;
  pthread_spin_lock(p); // return value ignored
#else // SPINLOCK_PTHREAD
  au32 * const p = (typeof(p))lock;
#pragma nounroll
  do {
    if (atomic_fetch_sub_explicit(p, 1, MO_ACQUIRE) == 0)
      return;
#pragma nounroll
    do {
      cpu_pause();
    } while (atomic_load_explicit(p, MO_CONSUME));
  } while (true);
#endif // SPINLOCK_PTHREAD
#endif // CORR
}

  inline bool
spinlock_trylock(spinlock * const lock)
{
#if defined(SPINLOCK_PTHREAD)
  pthread_spinlock_t * const p = (typeof(p))lock;
  return !pthread_spin_trylock(p);
#else // SPINLOCK_PTHREAD
  au32 * const p = (typeof(p))lock;
  return atomic_fetch_sub_explicit(p, 1, MO_ACQUIRE) == 0;
#endif // SPINLOCK_PTHREAD
}

  inline void
spinlock_unlock(spinlock * const lock)
{
#if defined(SPINLOCK_PTHREAD)
  pthread_spinlock_t * const p = (typeof(p))lock;
  pthread_spin_unlock(p); // return value ignored
#else // SPINLOCK_PTHREAD
  au32 * const p = (typeof(p))lock;
  atomic_store_explicit(p, 0, MO_RELEASE);
#endif // SPINLOCK_PTHREAD
}
// }}} spinlock

// pthread mutex {{{
static_assert(sizeof(pthread_mutex_t) <= sizeof(mutex), "mutexlock size");
  inline void
mutex_init(mutex * const lock)
{
  pthread_mutex_t * const p = (typeof(p))lock;
  pthread_mutex_init(p, NULL);
}

  inline void
mutex_lock(mutex * const lock)
{
#if defined(CORR)
#pragma nounroll
  while (!mutex_trylock(lock))
    corr_yield();
#else
  pthread_mutex_t * const p = (typeof(p))lock;
  pthread_mutex_lock(p); // return value ignored
#endif
}

  inline bool
mutex_trylock(mutex * const lock)
{
  pthread_mutex_t * const p = (typeof(p))lock;
  return !pthread_mutex_trylock(p); // return value ignored
}

  inline void
mutex_unlock(mutex * const lock)
{
  pthread_mutex_t * const p = (typeof(p))lock;
  pthread_mutex_unlock(p); // return value ignored
}

  inline void
mutex_deinit(mutex * const lock)
{
  pthread_mutex_t * const p = (typeof(p))lock;
  pthread_mutex_destroy(p);
}
// }}} pthread mutex

// rwdep {{{
// poor man's lockdep for rwlock
// per-thread lock list
// it calls debug_die() when local double-(un)locking is detected
// cyclic dependencies can be manually identified by looking at the two lists below in gdb
#ifdef RWDEP
#define RWDEP_NR ((16))
__thread const rwlock * rwdep_readers[RWDEP_NR] = {};
__thread const rwlock * rwdep_writers[RWDEP_NR] = {};

  static void
rwdep_check(const rwlock * const lock)
{
  debug_assert(lock);
  for (u64 i = 0; i < RWDEP_NR; i++) {
    if (rwdep_readers[i] == lock)
      debug_die();
    if (rwdep_writers[i] == lock)
      debug_die();
  }
}
#endif // RWDEP

  static void
rwdep_lock_read(const rwlock * const lock)
{
#ifdef RWDEP
  rwdep_check(lock);
  for (u64 i = 0; i < RWDEP_NR; i++) {
    if (rwdep_readers[i] == NULL) {
      rwdep_readers[i] = lock;
      return;
    }
  }
#else
  (void)lock;
#endif // RWDEP
}

  static void
rwdep_unlock_read(const rwlock * const lock)
{
#ifdef RWDEP
  for (u64 i = 0; i < RWDEP_NR; i++) {
    if (rwdep_readers[i] == lock) {
      rwdep_readers[i] = NULL;
      return;
    }
  }
  debug_die();
#else
  (void)lock;
#endif // RWDEP
}

  static void
rwdep_lock_write(const rwlock * const lock)
{
#ifdef RWDEP
  rwdep_check(lock);
  for (u64 i = 0; i < RWDEP_NR; i++) {
    if (rwdep_writers[i] == NULL) {
      rwdep_writers[i] = lock;
      return;
    }
  }
#else
  (void)lock;
#endif // RWDEP
}

  static void
rwdep_unlock_write(const rwlock * const lock)
{
#ifdef RWDEP
  for (u64 i = 0; i < RWDEP_NR; i++) {
    if (rwdep_writers[i] == lock) {
      rwdep_writers[i] = NULL;
      return;
    }
  }
  debug_die();
#else
  (void)lock;
#endif // RWDEP
}
// }}} rwlockdep

// rwlock {{{
typedef au32 lock_t;
typedef u32 lock_v;
static_assert(sizeof(lock_t) == sizeof(lock_v), "lock size");
static_assert(sizeof(lock_t) <= sizeof(rwlock), "lock size");

#define RWLOCK_WSHIFT ((sizeof(lock_t) * 8 - 1))
#define RWLOCK_WBIT ((((lock_v)1) << RWLOCK_WSHIFT))

  inline void
rwlock_init(rwlock * const lock)
{
  lock_t * const pvar = (typeof(pvar))lock;
  atomic_store_explicit(pvar, 0, MO_RELEASE);
}

  inline bool
rwlock_trylock_read(rwlock * const lock)
{
  lock_t * const pvar = (typeof(pvar))lock;
  if ((atomic_fetch_add_explicit(pvar, 1, MO_ACQUIRE) >> RWLOCK_WSHIFT) == 0) {
    rwdep_lock_read(lock);
    return true;
  } else {
    atomic_fetch_sub_explicit(pvar, 1, MO_RELAXED);
    return false;
  }
}

  inline bool
rwlock_trylock_read_lp(rwlock * const lock)
{
  lock_t * const pvar = (typeof(pvar))lock;
  if (atomic_load_explicit(pvar, MO_CONSUME) >> RWLOCK_WSHIFT) {
    cpu_pause();
    return false;
  }
  return rwlock_trylock_read(lock);
}

// actually nr + 1
  inline bool
rwlock_trylock_read_nr(rwlock * const lock, u16 nr)
{
  lock_t * const pvar = (typeof(pvar))lock;
  if ((atomic_fetch_add_explicit(pvar, 1, MO_ACQUIRE) >> RWLOCK_WSHIFT) == 0) {
    rwdep_lock_read(lock);
    return true;
  }

#pragma nounroll
  do { // someone already locked; wait for a little while
    cpu_pause();
    if ((atomic_load_explicit(pvar, MO_CONSUME) >> RWLOCK_WSHIFT) == 0) {
      rwdep_lock_read(lock);
      return true;
    }
  } while (nr--);

  atomic_fetch_sub_explicit(pvar, 1, MO_RELAXED);
  return false;
}

  inline void
rwlock_lock_read(rwlock * const lock)
{
  lock_t * const pvar = (typeof(pvar))lock;
#pragma nounroll
  do {
    if (rwlock_trylock_read(lock))
      return;
#pragma nounroll
    do {
#if defined(CORR)
      corr_yield();
#else
      cpu_pause();
#endif
    } while (atomic_load_explicit(pvar, MO_CONSUME) >> RWLOCK_WSHIFT);
  } while (true);
}

  inline void
rwlock_unlock_read(rwlock * const lock)
{
  rwdep_unlock_read(lock);
  lock_t * const pvar = (typeof(pvar))lock;
  atomic_fetch_sub_explicit(pvar, 1, MO_RELEASE);
}

  inline bool
rwlock_trylock_write(rwlock * const lock)
{
  lock_t * const pvar = (typeof(pvar))lock;
  lock_v v0 = atomic_load_explicit(pvar, MO_CONSUME);
  if ((v0 == 0) && atomic_compare_exchange_weak_explicit(pvar, &v0, RWLOCK_WBIT, MO_ACQUIRE, MO_RELAXED)) {
    rwdep_lock_write(lock);
    return true;
  } else {
    return false;
  }
}

// actually nr + 1
  inline bool
rwlock_trylock_write_nr(rwlock * const lock, u16 nr)
{
#pragma nounroll
  do {
    if (rwlock_trylock_write(lock))
      return true;
    cpu_pause();
  } while (nr--);
  return false;
}

  inline void
rwlock_lock_write(rwlock * const lock)
{
  lock_t * const pvar = (typeof(pvar))lock;
#pragma nounroll
  do {
    if (rwlock_trylock_write(lock))
      return;
#pragma nounroll
    do {
#if defined(CORR)
      corr_yield();
#else
      cpu_pause();
#endif
    } while (atomic_load_explicit(pvar, MO_CONSUME));
  } while (true);
}

  inline bool
rwlock_trylock_write_hp(rwlock * const lock)
{
  lock_t * const pvar = (typeof(pvar))lock;
  lock_v v0 = atomic_load_explicit(pvar, MO_CONSUME);
  if (v0 >> RWLOCK_WSHIFT)
    return false;

  if (atomic_compare_exchange_weak_explicit(pvar, &v0, v0|RWLOCK_WBIT, MO_ACQUIRE, MO_RELAXED)) {
    rwdep_lock_write(lock);
    // WBIT successfully marked; must wait for readers to leave
    if (v0) { // saw active readers
#pragma nounroll
      while (atomic_load_explicit(pvar, MO_CONSUME) != RWLOCK_WBIT) {
#if defined(CORR)
        corr_yield();
#else
        cpu_pause();
#endif
      }
    }
    return true;
  } else {
    return false;
  }
}

  inline bool
rwlock_trylock_write_hp_nr(rwlock * const lock, u16 nr)
{
#pragma nounroll
  do {
    if (rwlock_trylock_write_hp(lock))
      return true;
    cpu_pause();
  } while (nr--);
  return false;
}

  inline void
rwlock_lock_write_hp(rwlock * const lock)
{
#pragma nounroll
  while (!rwlock_trylock_write_hp(lock)) {
#if defined(CORR)
    corr_yield();
#else
    cpu_pause();
#endif
  }
}

  inline void
rwlock_unlock_write(rwlock * const lock)
{
  rwdep_unlock_write(lock);
  lock_t * const pvar = (typeof(pvar))lock;
  atomic_fetch_sub_explicit(pvar, RWLOCK_WBIT, MO_RELEASE);
}

  inline void
rwlock_write_to_read(rwlock * const lock)
{
  rwdep_unlock_write(lock);
  rwdep_lock_read(lock);
  lock_t * const pvar = (typeof(pvar))lock;
  // +R -W
  atomic_fetch_add_explicit(pvar, ((lock_v)1) - RWLOCK_WBIT, MO_ACQ_REL);
}

#undef RWLOCK_WSHIFT
#undef RWLOCK_WBIT
// }}} rwlock

// }}} locking

// bits {{{
  inline u32
bits_reverse_u32(const u32 v)
{
  const u32 v2 = __builtin_bswap32(v);
  const u32 v3 = ((v2 & 0xf0f0f0f0u) >> 4) | ((v2 & 0x0f0f0f0fu) << 4);
  const u32 v4 = ((v3 & 0xccccccccu) >> 2) | ((v3 & 0x33333333u) << 2);
  const u32 v5 = ((v4 & 0xaaaaaaaau) >> 1) | ((v4 & 0x55555555u) << 1);
  return v5;
}

  inline u64
bits_reverse_u64(const u64 v)
{
  const u64 v2 = __builtin_bswap64(v);
  const u64 v3 = ((v2 & 0xf0f0f0f0f0f0f0f0lu) >>  4) | ((v2 & 0x0f0f0f0f0f0f0f0flu) <<  4);
  const u64 v4 = ((v3 & 0xcccccccccccccccclu) >>  2) | ((v3 & 0x3333333333333333lu) <<  2);
  const u64 v5 = ((v4 & 0xaaaaaaaaaaaaaaaalu) >>  1) | ((v4 & 0x5555555555555555lu) <<  1);
  return v5;
}

  inline u64
bits_rotl_u64(const u64 v, const u8 n)
{
  const u8 sh = n & 0x3f;
  return (v << sh) | (v >> (64 - sh));
}

  inline u64
bits_rotr_u64(const u64 v, const u8 n)
{
  const u8 sh = n & 0x3f;
  return (v >> sh) | (v << (64 - sh));
}

  inline u32
bits_rotl_u32(const u32 v, const u8 n)
{
  const u8 sh = n & 0x1f;
  return (v << sh) | (v >> (32 - sh));
}

  inline u32
bits_rotr_u32(const u32 v, const u8 n)
{
  const u8 sh = n & 0x1f;
  return (v >> sh) | (v << (32 - sh));
}

  inline u64
bits_p2_up_u64(const u64 v)
{
  // clz(0) is undefined
  return (v > 1) ? (1lu << (64 - __builtin_clzl(v - 1lu))) : v;
}

  inline u32
bits_p2_up_u32(const u32 v)
{
  // clz(0) is undefined
  return (v > 1) ? (1u << (32 - __builtin_clz(v - 1u))) : v;
}

  inline u64
bits_p2_down_u64(const u64 v)
{
  return v ? (1lu << (63 - __builtin_clzl(v))) : v;
}

  inline u32
bits_p2_down_u32(const u32 v)
{
  return v ? (1u << (31 - __builtin_clz(v))) : v;
}

  inline u64
bits_round_up(const u64 v, const u8 power)
{
  return (v + (1lu << power) - 1lu) >> power << power;
}

  inline u64
bits_round_up_a(const u64 v, const u64 a)
{
  return (v + a - 1) / a * a;
}

  inline u64
bits_round_down(const u64 v, const u8 power)
{
  return v >> power << power;
}

  inline u64
bits_round_down_a(const u64 v, const u64 a)
{
  return v / a * a;
}
// }}} bits

// misc {{{
  inline struct entry13
entry13(const u16 e1, const u64 e3)
{
  debug_assert((e3 >> 48) == 0);
  return (struct entry13){.v64 = (e3 << 16) | e1};
}

  inline void
entry13_update_e3(struct entry13 * const e, const u64 e3)
{
  debug_assert((e3 >> 48) == 0);
  *e = entry13(e->e1, e3);
}

  inline void *
u64_to_ptr(const u64 v)
{
  return (void *)v;
}

  inline u64
ptr_to_u64(const void * const ptr)
{
  return (u64)ptr;
}

// portable malloc_usable_size
  inline size_t
m_usable_size(void * const ptr)
{
#if defined(__linux__) || defined(__FreeBSD__)
  const size_t sz = malloc_usable_size(ptr);
#elif defined(__APPLE__) && defined(__MACH__)
  const size_t sz = malloc_size(ptr);
#endif // OS

#ifndef HEAPCHECKING
  // valgrind and asan may return unaligned usable size
  debug_assert((sz & 0x7lu) == 0);
#endif // HEAPCHECKING

  return sz;
}

  inline size_t
fdsize(const int fd)
{
  struct stat st;
  st.st_size = 0;
  if (fstat(fd, &st) != 0)
    return 0;

  if (S_ISBLK(st.st_mode)) {
#if defined(__linux__)
    ioctl(fd, BLKGETSIZE64, &st.st_size);
#elif defined(__APPLE__) && defined(__MACH__)
    u64 blksz = 0;
    u64 nblks = 0;
    ioctl(fd, DKIOCGETBLOCKSIZE, &blksz);
    ioctl(fd, DKIOCGETBLOCKCOUNT, &nblks);
    st.st_size = (ssize_t)(blksz * nblks);
#elif defined(__FreeBSD__)
    ioctl(fd, DIOCGMEDIASIZE, &st.st_size);
#endif // OS
  }

  return (size_t)st.st_size;
}

  u32
memlcp(const u8 * const p1, const u8 * const p2, const u32 max)
{
  const u32 max64 = max & (~7u);
  u32 clen = 0;
  while (clen < max64) {
    const u64 v1 = *(const u64 *)(p1+clen);
    const u64 v2 = *(const u64 *)(p2+clen);
    const u64 x = v1 ^ v2;
    if (x)
      return clen + (u32)(__builtin_ctzl(x) >> 3);

    clen += sizeof(u64);
  }

  if ((clen + sizeof(u32)) <= max) {
    const u32 v1 = *(const u32 *)(p1+clen);
    const u32 v2 = *(const u32 *)(p2+clen);
    const u32 x = v1 ^ v2;
    if (x)
      return clen + (u32)(__builtin_ctz(x) >> 3);

    clen += sizeof(u32);
  }

  while ((clen < max) && (p1[clen] == p2[clen]))
    clen++;
  return clen;
}
// }}} misc

// astk {{{
// atomic stack
struct acell { struct acell * next; };

// extract ptr from m value
  static inline struct acell *
astk_ptr(const u64 m)
{
  return (struct acell *)(m >> 16);
}

// calculate the new magic
  static inline u64
astk_m1(const u64 m0, struct acell * const ptr)
{
  return ((m0 + 1) & 0xfffflu) | (((u64)ptr) << 16);
}

// calculate the new magic
  static inline u64
astk_m1_unsafe(struct acell * const ptr)
{
  return ((u64)ptr) << 16;
}

  static bool
astk_try_push(au64 * const pmagic, struct acell * const first, struct acell * const last)
{
  u64 m0 = atomic_load_explicit(pmagic, MO_CONSUME);
  last->next = astk_ptr(m0);
  const u64 m1 = astk_m1(m0, first);
  return atomic_compare_exchange_weak_explicit(pmagic, &m0, m1, MO_RELEASE, MO_RELAXED);
}

  static void
astk_push_safe(au64 * const pmagic, struct acell * const first, struct acell * const last)
{
  while (!astk_try_push(pmagic, first, last));
}

  static void
astk_push_unsafe(au64 * const pmagic, struct acell * const first,
    struct acell * const last)
{
  const u64 m0 = atomic_load_explicit(pmagic, MO_CONSUME);
  last->next = astk_ptr(m0);
  const u64 m1 = astk_m1_unsafe(first);
  atomic_store_explicit(pmagic, m1, MO_RELAXED);
}

//// can fail for two reasons: (1) NULL: no available object; (2) ~0lu: contention
//  static void *
//astk_try_pop(au64 * const pmagic)
//{
//  u64 m0 = atomic_load_explicit(pmagic, MO_CONSUME);
//  struct acell * const ret = astk_ptr(m0);
//  if (ret == NULL)
//    return NULL;
//
//  const u64 m1 = astk_m1(m0, ret->next);
//  if (atomic_compare_exchange_weak_explicit(pmagic, &m0, m1, MO_ACQUIRE, MO_RELAXED))
//    return ret;
//  else
//    return (void *)(~0lu);
//}

  static void *
astk_pop_safe(au64 * const pmagic)
{
  do {
    u64 m0 = atomic_load_explicit(pmagic, MO_CONSUME);
    struct acell * const ret = astk_ptr(m0);
    if (ret == NULL)
      return NULL;

    const u64 m1 = astk_m1(m0, ret->next);
    if (atomic_compare_exchange_weak_explicit(pmagic, &m0, m1, MO_ACQUIRE, MO_RELAXED))
      return ret;
  } while (true);
}

  static void *
astk_pop_unsafe(au64 * const pmagic)
{
  const u64 m0 = atomic_load_explicit(pmagic, MO_CONSUME);
  struct acell * const ret = astk_ptr(m0);
  if (ret == NULL)
    return NULL;

  const u64 m1 = astk_m1_unsafe(ret->next);
  atomic_store_explicit(pmagic, m1, MO_RELAXED);
  return (void *)ret;
}

  static void *
astk_peek_unsafe(au64 * const pmagic)
{
  const u64 m0 = atomic_load_explicit(pmagic, MO_CONSUME);
  return astk_ptr(m0);
}
// }}} astk

// slab {{{
#define SLAB_OBJ0_OFFSET ((64))
struct slab {
  au64 magic; // hi 48: ptr, lo 16: seq
  u64 padding1[7];

  // 2nd line
  struct acell * head_active; // list of blocks in use or in magic
  struct acell * head_backup; // list of unused full blocks
  u64 nr_ready; // UNSAFE only! number of objects under magic
  u64 padding2[5];

  // 3rd line const
  u64 obj_size; // const: aligned size of each object
  u64 blk_size; // const: size of each memory block
  u64 objs_per_slab; // const: number of objects in a slab
  u64 obj0_offset; // const: offset of the first object in a block
  u64 padding3[4];

  // 4th line
  union {
    mutex lock;
    u64 padding4[8];
  };
};
static_assert(sizeof(struct slab) == 256, "sizeof(struct slab) != 256");

  static void
slab_add(struct slab * const slab, struct acell * const blk, const bool is_safe)
{
  // insert into head_active
  blk->next = slab->head_active;
  slab->head_active = blk;

  u8 * const base = ((u8 *)blk) + slab->obj0_offset;
  struct acell * iter = (typeof(iter))base; // [0]
  for (u64 i = 1; i < slab->objs_per_slab; i++) {
    struct acell * const next = (typeof(next))(base + (i * slab->obj_size));
    iter->next = next;
    iter = next;
  }

  // base points to the first block; iter points to the last block
  if (is_safe) { // other threads can poll magic
    astk_push_safe(&slab->magic, (struct acell *)base, iter);
  } else { // unsafe
    astk_push_unsafe(&slab->magic, (struct acell *)base, iter);
    slab->nr_ready += slab->objs_per_slab;
  }
}

// critical section; call with lock
  static bool
slab_expand(struct slab * const slab, const bool is_safe)
{
  struct acell * const old = slab->head_backup;
  if (old) { // pop old from backup and add
    slab->head_backup = old->next;
    slab_add(slab, old, is_safe);
  } else { // more core
    size_t blk_size;
    struct acell * const new = pages_alloc_best(slab->blk_size, true, &blk_size);
    (void)blk_size;
    if (new == NULL)
      return false;

    slab_add(slab, new, is_safe);
  }
  return true;
}

// return 0 on failure; otherwise, obj0_offset
  static u64
slab_check_sizes(const u64 obj_size, const u64 blk_size)
{
  // obj must be non-zero and 8-byte aligned
  // blk must be at least of page size and power of 2
  if ((!obj_size) || (obj_size % 8lu) || (blk_size < 4096lu) || (blk_size & (blk_size - 1)))
    return 0;

  // each slab should have at least one object
  const u64 obj0_offset = (obj_size & (obj_size - 1)) ? SLAB_OBJ0_OFFSET : obj_size;
  if (obj0_offset >= blk_size || (blk_size - obj0_offset) < obj_size)
    return 0;

  return obj0_offset;
}

  static void
slab_init_internal(struct slab * const slab, const u64 obj_size, const u64 blk_size, const u64 obj0_offset)
{
  memset(slab, 0, sizeof(*slab));
  slab->obj_size = obj_size;
  slab->blk_size = blk_size;
  slab->objs_per_slab = (blk_size - obj0_offset) / obj_size;
  debug_assert(slab->objs_per_slab); // >= 1
  slab->obj0_offset = obj0_offset;
  mutex_init(&(slab->lock));
}

  struct slab *
slab_create(const u64 obj_size, const u64 blk_size)
{
  const u64 obj0_offset = slab_check_sizes(obj_size, blk_size);
  if (!obj0_offset)
    return NULL;

  struct slab * const slab = yalloc(sizeof(*slab));
  if (slab == NULL)
    return NULL;

  slab_init_internal(slab, obj_size, blk_size, obj0_offset);
  return slab;
}

// unsafe
  bool
slab_reserve_unsafe(struct slab * const slab, const u64 nr)
{
  while (slab->nr_ready < nr)
    if (!slab_expand(slab, false))
      return false;
  return true;
}

  void *
slab_alloc_unsafe(struct slab * const slab)
{
  void * ret = astk_pop_unsafe(&slab->magic);
  if (ret == NULL) {
    if (!slab_expand(slab, false))
      return NULL;
    ret = astk_pop_unsafe(&slab->magic);
  }
  debug_assert(ret);
  slab->nr_ready--;
  return ret;
}

  void *
slab_alloc_safe(struct slab * const slab)
{
  void * ret = astk_pop_safe(&slab->magic);
  if (ret)
    return ret;

  mutex_lock(&slab->lock);
  do {
    ret = astk_pop_safe(&slab->magic); // may already have new objs
    if (ret)
      break;
    if (!slab_expand(slab, true))
      break;
  } while (true);
  mutex_unlock(&slab->lock);
  return ret;
}

  void
slab_free_unsafe(struct slab * const slab, void * const ptr)
{
  debug_assert(ptr);
  astk_push_unsafe(&slab->magic, ptr, ptr);
  slab->nr_ready++;
}

  void
slab_free_safe(struct slab * const slab, void * const ptr)
{
  astk_push_safe(&slab->magic, ptr, ptr);
}

// UNSAFE
  void
slab_free_all(struct slab * const slab)
{
  slab->magic = 0;
  slab->nr_ready = 0; // backup does not count

  if (slab->head_active) {
    struct acell * iter = slab->head_active;
    while (iter->next)
      iter = iter->next;
    // now iter points to the last blk
    iter->next = slab->head_backup; // active..backup
    slab->head_backup = slab->head_active; // backup gets all
    slab->head_active = NULL; // empty active
  }
}

// unsafe
  u64
slab_get_nalloc(struct slab * const slab)
{
  struct acell * iter = slab->head_active;
  u64 n = 0;
  while (iter) {
    n++;
    iter = iter->next;
  }
  n *= slab->objs_per_slab;

  iter = astk_peek_unsafe(&slab->magic);
  while (iter) {
    n--;
    iter = iter->next;
  }
  return n;
}

  static void
slab_deinit(struct slab * const slab)
{
  debug_assert(slab);
  struct acell * iter = slab->head_active;
  while (iter) {
    struct acell * const next = iter->next;
    pages_unmap(iter, slab->blk_size);
    iter = next;
  }
  iter = slab->head_backup;
  while (iter) {
    struct acell * const next = iter->next;
    pages_unmap(iter, slab->blk_size);
    iter = next;
  }
}

  void
slab_destroy(struct slab * const slab)
{
  slab_deinit(slab);
  free(slab);
}
// }}} slab

// qsbr {{{
#define QSBR_STATES_NR ((23)) // shard capacity; valid values are 3*8-1 == 23; 5*8-1 == 39; 7*8-1 == 55
#define QSBR_SHARD_BITS  ((5)) // 2^n shards
#define QSBR_SHARD_NR    (((1u) << QSBR_SHARD_BITS))
#define QSBR_SHARD_MASK  ((QSBR_SHARD_NR - 1))

struct qsbr_ref_real {
#ifdef QSBR_DEBUG
  pthread_t ptid; // 8
  u32 status; // 4
  u32 nbt; // 4 (number of backtrace frames)
#define QSBR_DEBUG_BTNR ((14))
  void * backtrace[QSBR_DEBUG_BTNR];
#endif
  au64 qstate; // user updates it
  au64 * pptr; // internal only
  struct qsbr_ref_real * park;
};

static_assert(sizeof(struct qsbr_ref) == sizeof(struct qsbr_ref_real), "sizeof qsbr_ref");

// Quiescent-State-Based Reclamation RCU
struct qsbr {
  struct qsbr_ref_real target;
  u64 padding0[5];
  struct qshard {
    au64 bitmap;
    au64 ptrs[QSBR_STATES_NR];
  } shards[QSBR_SHARD_NR];
};

  struct qsbr *
qsbr_create(void)
{
  struct qsbr * const q = yalloc(sizeof(*q));
  memset(q, 0, sizeof(*q));
  return q;
}

  static inline struct qshard *
qsbr_shard(struct qsbr * const q, void * const ptr)
{
  const u32 sid = crc32c_u64(0, (u64)ptr) & QSBR_SHARD_MASK;
  debug_assert(sid < QSBR_SHARD_NR);
  return &(q->shards[sid]);
}

  static inline void
qsbr_write_qstate(struct qsbr_ref_real * const ref, const u64 v)
{
  atomic_store_explicit(&ref->qstate, v, MO_RELAXED);
}

  bool
qsbr_register(struct qsbr * const q, struct qsbr_ref * const qref)
{
  struct qsbr_ref_real * const ref = (typeof(ref))qref;
  struct qshard * const shard = qsbr_shard(q, ref);
  qsbr_write_qstate(ref, 0);

  do {
    u64 bits = atomic_load_explicit(&shard->bitmap, MO_CONSUME);
    const u32 pos = (u32)__builtin_ctzl(~bits);
    if (unlikely(pos >= QSBR_STATES_NR))
      return false;

    const u64 bits1 = bits | (1lu << pos);
    if (atomic_compare_exchange_weak_explicit(&shard->bitmap, &bits, bits1, MO_ACQUIRE, MO_RELAXED)) {
      atomic_store_explicit(&shard->ptrs[pos], (u64)ref, MO_RELAXED);
      //shard->ptrs[pos] = ref;

      ref->pptr = &(shard->ptrs[pos]);
      ref->park = &q->target;
#ifdef QSBR_DEBUG
      ref->ptid = (u64)pthread_self();
      ref->tid = 0;
      ref->status = 1;
      ref->nbt = backtrace(ref->backtrace, QSBR_DEBUG_BTNR);
#endif
      return true;
    }
  } while (true);
}

  void
qsbr_unregister(struct qsbr * const q, struct qsbr_ref * const qref)
{
  struct qsbr_ref_real * const ref = (typeof(ref))qref;
  struct qshard * const shard = qsbr_shard(q, ref);
  const u32 pos = (u32)(ref->pptr - shard->ptrs);
  debug_assert(pos < QSBR_STATES_NR);
  debug_assert(shard->bitmap & (1lu << pos));

  atomic_store_explicit(&shard->ptrs[pos], (u64)(&q->target), MO_RELAXED);
  //shard->ptrs[pos] = &q->target;
  (void)atomic_fetch_and_explicit(&shard->bitmap, ~(1lu << pos), MO_RELEASE);
#ifdef QSBR_DEBUG
  ref->tid = 0;
  ref->ptid = 0;
  ref->status = 0xffff; // unregistered
  ref->nbt = 0;
#endif
  ref->pptr = NULL;
  // wait for qsbr_wait to leave if it's working on the shard
  while (atomic_load_explicit(&shard->bitmap, MO_CONSUME) >> 63)
    cpu_pause();
}

  inline void
qsbr_update(struct qsbr_ref * const qref, const u64 v)
{
  struct qsbr_ref_real * const ref = (typeof(ref))qref;
  debug_assert((*ref->pptr) == (u64)ref); // must be unparked
  // rcu update does not require release or acquire order
  qsbr_write_qstate(ref, v);
}

  inline void
qsbr_park(struct qsbr_ref * const qref)
{
  cpu_cfence();
  struct qsbr_ref_real * const ref = (typeof(ref))qref;
  atomic_store_explicit(ref->pptr, (u64)ref->park, MO_RELAXED);
#ifdef QSBR_DEBUG
  ref->status = 0xfff; // parked
#endif
}

  inline void
qsbr_resume(struct qsbr_ref * const qref)
{
  struct qsbr_ref_real * const ref = (typeof(ref))qref;
  atomic_store_explicit(ref->pptr, (u64)ref, MO_RELAXED);
#ifdef QSBR_DEBUG
  ref->status = 0xf; // resumed
#endif
  cpu_cfence();
}

// waiters needs external synchronization
  void
qsbr_wait(struct qsbr * const q, const u64 target)
{
  cpu_cfence();
  qsbr_write_qstate(&q->target, target);
  u64 cbits = 0; // check-bits; each bit corresponds to a shard
  u64 bms[QSBR_SHARD_NR]; // copy of all bitmap
  // take an unsafe snapshot of active users
  for (u32 i = 0; i < QSBR_SHARD_NR; i++) {
    bms[i] = atomic_load_explicit(&q->shards[i].bitmap, MO_CONSUME);
    if (bms[i])
      cbits |= (1lu << i); // set to 1 if [i] has ptrs
  }

  while (cbits) {
    for (u64 ctmp = cbits; ctmp; ctmp &= (ctmp - 1)) {
      // shard id
      const u32 i = (u32)__builtin_ctzl(ctmp);
      struct qshard * const shard = &(q->shards[i]);
      const u64 bits1 = atomic_fetch_or_explicit(&(shard->bitmap), 1lu << 63, MO_ACQUIRE);
      for (u64 bits = bms[i]; bits; bits &= (bits - 1)) {
        const u64 bit = bits & -bits; // extract lowest bit
        if ((bits1 & bit) == 0) {
          bms[i] &= ~bit;
        } else {
          au64 * pptr = &(shard->ptrs[__builtin_ctzl(bit)]);
          struct qsbr_ref_real * const ptr = (typeof(ptr))atomic_load_explicit(pptr, MO_RELAXED);
          if (atomic_load_explicit(&(ptr->qstate), MO_CONSUME) == target)
            bms[i] &= ~bit;
        }
      }
      (void)atomic_fetch_and_explicit(&(shard->bitmap), ~(1lu << 63), MO_RELEASE);
      if (bms[i] == 0)
        cbits &= ~(1lu << i);
    }
#if defined(CORR)
    corr_yield();
#endif
  }
  debug_assert(cbits == 0);
  cpu_cfence();
}

  void
qsbr_destroy(struct qsbr * const q)
{
  if (q)
    free(q);
}
#undef QSBR_STATES_NR
#undef QSBR_BITMAP_NR
// }}} qsbr

// vim:fdm=marker
