/*
 * Copyright (c) 2016--2020  Wu, Xingbo <wuxb45@gmail.com>
 *
 * All rights reserved. No warranty, explicit or implicit, provided.
 */
#define _GNU_SOURCE

// headers {{{
#include "lib.h"
#include "ctypes.h"
#include <assert.h>
#include <byteswap.h>
#include <execinfo.h>
#include <math.h>
#include <netdb.h>
#include <sched.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/sysinfo.h>
#include <sys/ioctl.h>
#include <time.h>
// }}} headers

// math {{{
  inline u64
mhash64(const u64 v)
{
  return v * 11400714819323198485lu;
}

  inline u32
mhash32(const u32 v)
{
  return v * 2654435761u;
}

// From Daniel Lemire's blog (2013, lemire.me)
  u64
gcd64(u64 a, u64 b)
{
  if (a == 0)
    return b;
  if (b == 0)
    return a;

  const u32 shift = (u32)__builtin_ctzl(a | b);
  a >>= __builtin_ctzl(a);
  do {
    b >>= __builtin_ctzl(b);
    if (a > b) {
      const u64 t = b;
      b = a;
      a = t;
    }
    b = b - a;
  } while (b);
  return a << shift;
}
// }}} math

// timing {{{
  inline u64
time_nsec(void)
{
  struct timespec ts;
  // MONO_RAW is 5x to 10x slower than MONO
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ((u64)ts.tv_sec) * 1000000000lu + ((u64)ts.tv_nsec);
}

  inline double
time_sec(void)
{
  const u64 nsec = time_nsec();
  return ((double)nsec) * 1.0e-9;
}

  inline u64
time_diff_nsec(const u64 last)
{
  return time_nsec() - last;
}

  inline double
time_diff_sec(const double last)
{
  return time_sec() - last;
}

// need char str[64]
  inline void
time_stamp(char * str, const size_t size)
{
  time_t now;
  struct tm nowtm;
  time(&now);
  localtime_r(&now, &nowtm);
  strftime(str, size, "%F %T %z", &nowtm);
}

  inline void
time_stamp2(char * str, const size_t size)
{
  time_t now;
  struct tm nowtm;
  time(&now);
  localtime_r(&now, &nowtm);
  strftime(str, size, "%F-%H-%M-%S%z", &nowtm);
}
// }}} timing

// cpucache {{{
  inline void
cpu_pause(void)
{
#if defined(__x86_64__)
  _mm_pause();
#endif
}

  inline void
cpu_mfence(void)
{
  atomic_thread_fence(memory_order_seq_cst);
}

// compiler fence
  inline void
cpu_cfence(void)
{
  atomic_thread_fence(memory_order_acq_rel);
}

  inline void
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
// }}} crc32c

// debug {{{
  void
debug_break(void)
{
  usleep(100);
}

  void
debug_backtrace(void)
{
  void *array[100];
  const int size = backtrace(array, 100);
  dprintf(2, "Backtrace (%d):\n", size);
  // skip this call
  backtrace_symbols_fd(array + 1, size, 2);
}

static u64 * debug_watch_u64 = NULL;

  static void
watch_u64_handler(const int sig)
{
  (void)sig;
  const u64 v = debug_watch_u64 ? (*debug_watch_u64) : 0;
  fprintf(stderr, "[USR1] %lu (0x%lx)\n", v, v);
}

  void
watch_u64_usr1(u64 * const ptr)
{
  debug_watch_u64 = ptr;
  struct sigaction sa = {};
  sa.sa_handler = watch_u64_handler;
  sigemptyset(&(sa.sa_mask));
  sa.sa_flags = SA_RESTART;
  if (sigaction(SIGUSR1, &sa, NULL) == -1) {
    fprintf(stderr, "Failed to set signal handler for SIGUSR1\n");
  } else {
    fprintf(stderr, "to watch> kill -s SIGUSR1 %d\n", getpid());
  }
}

  void
debug_wait_gdb(void)
{
  debug_backtrace();
  volatile bool v = true;

  char timestamp[64];
  time_stamp(timestamp, 64);
  char threadname[64];
  pthread_getname_np(pthread_self(), threadname, 64);
  char hostname[64];
  gethostname(hostname, 64);

  const char * const pattern = "[Waiting GDB] %s %s @ %s\n"
    "    Attach me:   " ANSI_ESCAPE(31) "sudo -Hi gdb -p %d" ANSI_ESCAPE(0) "\n";
  fprintf(stderr, pattern, timestamp, threadname, hostname, getpid());
  fflush(stderr);
  // to continue: gdb> set var v = 0
#pragma nounroll
  while (v)
    sleep(1);
}

#ifndef NDEBUG
  inline void
debug_assert(const bool v)
{
  if (!v)
    debug_wait_gdb();
}
#endif

__attribute__((noreturn))
  void
debug_die(void)
{
  debug_wait_gdb();
  exit(0);
}

  static void
wait_gdb_handler(const int sig, siginfo_t * const info, void * const context)
{
  (void)info;
  (void)context;
  printf("[SIGNAL] %s\n", strsignal(sig));
  debug_wait_gdb();
}

__attribute__((constructor))
  static void
debug_init(void)
{
  void * stack = pages_alloc_4kb(16);
  //fprintf(stderr, "altstack %p\n", stack);
  stack_t ss = {.ss_sp = stack, .ss_flags = 0, .ss_size = PGSZ*16};
  if (sigaltstack(&ss, NULL))
    fprintf(stderr, "sigaltstack failed\n");

  struct sigaction sa = {};
  sa.sa_sigaction = wait_gdb_handler;
  sigemptyset(&(sa.sa_mask));
  sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
  const int fatals[] = {SIGSEGV, SIGFPE, SIGILL, SIGBUS, 0};
  for (int i = 0; fatals[i]; i++) {
    if (sigaction(fatals[i], &sa, NULL) == -1) {
      fprintf(stderr, "Failed to set signal handler for %s\n", strsignal(fatals[i]));
      fflush(stderr);
    }
  }
}

__attribute__((destructor))
  static void
debug_exit(void)
{
  // to get rid of valgrind warnings
  stack_t ss = {.ss_flags = SS_DISABLE};
  stack_t oss = {};
  sigaltstack(&ss, &oss);
  if (oss.ss_sp)
    pages_unmap(oss.ss_sp, PGSZ * 16);
}

  void
debug_dump_maps(FILE * const out)
{
  FILE * const in = fopen("/proc/self/smaps", "r");
  char * line0 = yalloc(1024);
  size_t size0 = 1024;
  while (!feof(in)) {
    const ssize_t r1 = getline(&line0, &size0, in);
    if (r1 < 0) break;
    fprintf(out, "%s", line0);
  }
  fflush(out);
  fclose(in);
}

static pid_t perf_pid = 0;

__attribute__((constructor))
  static void
debug_perf_init(void)
{
  const pid_t ppid = getppid();
  char tmp[256] = {};
  sprintf(tmp, "/proc/%d/cmdline", ppid);
  FILE * const fc = fopen(tmp, "r");
  const size_t nr = fread(tmp, 1, sizeof(tmp) - 1, fc);
  fclose(fc);
  // look for "perf record"
  if (nr < 12)
    return;
  tmp[nr] = '\0';
  for (u64 i = 0; i < nr; i++)
    if (tmp[i] == 0)
      tmp[i] = ' ';

  char * const perf = strstr(tmp, "perf record");
  if (perf) {
    fprintf(stderr, "%s: perf detected\n", __func__);
    perf_pid = ppid;
  }
}

  bool
debug_perf_switch(void)
{
  if (perf_pid > 0) {
    kill(perf_pid, SIGUSR2);
    return true;
  } else {
    return false;
  }
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

  inline void *
xalloc(const u64 align, const u64 size)
{
#ifdef ALLOCFAIL
  if (alloc_fail())
    return NULL;
#endif
  void * p;
  const int r = posix_memalign(&p, align, size);
  if (r == 0)
    return p;
  else
    return NULL;
}

// alloc cache-line aligned address
  inline void *
yalloc(const u64 size)
{
  return xalloc(64, size);
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

#ifndef HEAPCHECKING
  static void *
pages_do_alloc(const size_t size, const int flags)
{
  // vi /etc/security/limits.conf
  // * - memlock unlimited
  void * const p = mmap(NULL, size, PROT_READ | PROT_WRITE, flags, -1, 0);
  if (p == MAP_FAILED)
    return NULL;

  static bool use_mlock = true;
  if (use_mlock)
    if (mlock(p, size) != 0) {
      use_mlock = false;
      fprintf(stderr, "%s: mlock disabled\n", __func__);
    }

  return p;
}
#endif

  inline void *
pages_alloc_1gb(const size_t nr_1gb)
{
  const u64 sz = nr_1gb << 30;
#ifndef HEAPCHECKING
  return pages_do_alloc(sz, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | (30 << MAP_HUGE_SHIFT));
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
  return pages_do_alloc(sz, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | (21 << MAP_HUGE_SHIFT));
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

// process/thread {{{
static u32 process_ncpu;
static size_t cpu_set_size;

__attribute__((constructor))
  static void
process_init(void)
{
  // Linux's default is 1024 cpus
  process_ncpu = (u32)sysconf(_SC_NPROCESSORS_CONF);
  cpu_set_size = CPU_ALLOC_SIZE(process_ncpu);
  if (cpu_set_size > sizeof(cpu_set_t))
    fprintf(stderr, "%s: can use only %zu cores\n",
        __func__, sizeof(cpu_set_t) * 8);
}

  u64
process_get_rss(void)
{
  u64 size, rss = 0;
  FILE * const fp = fopen("/proc/self/statm", "r");
  if (fp == NULL)
    return 0;
  const int r = fscanf(fp, "%lu %lu", &size, &rss);
  fclose(fp);
  if (r != 2)
    return 0;
  return rss * (u64)sysconf(_SC_PAGESIZE);
}

  u32
process_affinity_core_count(void)
{
  cpu_set_t set;
  if (sched_getaffinity(0, cpu_set_size, &set) != 0)
    return process_ncpu;

  const u32 nr = (u32)CPU_COUNT_S(cpu_set_size, &set);
  return nr ? nr : process_ncpu;
}

  u32
process_affinity_core_list(const u32 max, u32 * const cores)
{
  memset(cores, 0, max * sizeof(cores[0]));
  cpu_set_t set;
  if (sched_getaffinity(0, cpu_set_size, &set) != 0)
    return 0;

  const u32 nr_affinity = (u32)CPU_COUNT_S(cpu_set_size, &set);
  const u32 nr = nr_affinity < max ? nr_affinity : max;
  u32 j = 0;
  for (u32 i = 0; i < process_ncpu; i++) {
    if (CPU_ISSET((int)i, &set))
      cores[j++] = i;

    if (j >= nr)
      break;
  }
  return j;
}

  u64
process_cpu_time_usec(void)
{
  struct rusage r;
  getrusage(RUSAGE_SELF, &r);
  const u64 usr = (((u64)r.ru_utime.tv_sec) * 1000000lu) + ((u64)r.ru_utime.tv_usec);
  const u64 sys = (((u64)r.ru_stime.tv_sec) * 1000000lu) + ((u64)r.ru_stime.tv_usec);
  return usr + sys;
}

  void
thread_set_affinity(const u32 cpu)
{
  cpu_set_t set;
  CPU_ZERO_S(cpu_set_size, &set);
  CPU_SET(cpu % process_ncpu, &set);
  sched_setaffinity(0, cpu_set_size, &set);
}

struct fork_join_info {
  u32 total;
  u32 ncores;
  u32 * cores;
  void *(*func)(void *);
  bool args;
  union {
    void * arg1;
    void ** argn;
  };
  au64 ferr;
  au64 jerr;
};

// DON'T CHANGE!
#define FORK_JOIN_RANK_BITS ((16)) // 16
#define FORK_JOIN_MAX ((1 << FORK_JOIN_RANK_BITS))
#define FORK_JOIN_FJI_BITS ((64 - FORK_JOIN_RANK_BITS)) // 48
struct fork_join_priv {
  union {
    struct {
      u64 rank : FORK_JOIN_RANK_BITS;
      u64 fji : FORK_JOIN_FJI_BITS;
    };
    void * ptr;
  };
};
static_assert(sizeof(struct fork_join_priv) == sizeof(void *), "fork_join_priv");

/*
 * fj(6):     T0
 *         /      \
 *       T0        T4
 *     /   \      /
 *    T0   T2    T4
 *   / \   / \   / \
 *  t0 t1 t2 t3 t4 t5
 */

// recursive tree fork-join
  static void *
thread_do_fork_join_worker(void * const ptr)
{
  struct fork_join_priv fjp = {.ptr = ptr};
  // GCC: Without explicitly casting from fjp.fji (a 45-bit u64 value),
  // the high bits will get truncated, which is always CORRECT in gcc.
  // Don't use gcc.
  struct fork_join_info * const fji = (typeof(fji))((u64)(fjp.fji));
  const u32 rank = fjp.rank;

  const u32 nchild = (u32)__builtin_ctz(rank ? rank : bits_p2_up_u32(fji->total));
  debug_assert(nchild <= FORK_JOIN_RANK_BITS);
  pthread_t tids[FORK_JOIN_RANK_BITS];
  if (nchild) {
    cpu_set_t set;
    CPU_ZERO_S(cpu_set_size, &set);
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    // fork top-down
    for (u32 i = nchild - 1; i < nchild; i--) {
      const u32 cr = rank + (1u << i);
      if (cr >= fji->total)
        continue; // should not break
      const u32 core = fji->cores[cr % fji->ncores];
      CPU_SET(core, &set);
      pthread_attr_setaffinity_np(&attr, cpu_set_size, &set);
      fjp.rank = cr;
      const int r = pthread_create(&tids[i], &attr, thread_do_fork_join_worker, fjp.ptr);
      if (r) { // fork failed
        memset(&tids[0], 0, sizeof(tids[0]) * (i+1));
        u32 nmiss = (1u << (i + 1)) - 1;
        if ((rank + nmiss) >= fji->total)
          nmiss = fji->total - 1 - rank;
        fji->ferr += nmiss;
        break;
      }
      CPU_CLR(core, &set);
    }
    pthread_attr_destroy(&attr);
  }

  char thname[16];
  sprintf(thname, "fj_%u", rank);
  pthread_setname_np(pthread_self(), thname);

  void * const ret = fji->func(fji->args ? fji->argn[rank] : fji->arg1);

  // join bottom-up
  for (u32 i = 0; i < nchild; i++) {
    const u32 cr = rank + (1u << i); // child rank
    if (cr >= fji->total)
      break; // safe to break
    if (tids[i]) {
      const int r = pthread_join(tids[i], NULL);
      if (r) { // error
        //fprintf(stderr, "pthread_join %u..%u = %d: %s\n", rank, cr, r, strerror(r));
        fji->jerr++;
      }
    }
  }
  return ret;
}

  u64
thread_fork_join(u32 nr, void *(*func) (void *), const bool args, void * const argx)
{
  if (nr > FORK_JOIN_MAX) {
    fprintf(stderr, "%s reduce nr to %u\n", __func__, FORK_JOIN_MAX);
    nr = FORK_JOIN_MAX;
  }

  u32 cores[process_ncpu];
  u32 ncores = process_affinity_core_list(process_ncpu, cores);
  if (ncores == 0) { // force to use all cores
    ncores = process_ncpu;
    for (u32 i = 0; i < process_ncpu; i++)
      cores[i] = i;
  }
  if (nr == 0)
    nr = ncores;

  struct fork_join_info fji;
  fji.total = nr;
  fji.cores = cores;
  fji.ncores = ncores;
  fji.func = func;
  fji.args = args;
  fji.arg1 = argx;
  fji.ferr = 0;
  fji.jerr = 0;
  struct fork_join_priv fjp = {.fji = (u64)(&fji), .rank = 0};

  // save current affinity
  cpu_set_t set0;
  sched_getaffinity(0, cpu_set_size, &set0);

  // master thread shares thread0's core
  cpu_set_t set;
  CPU_ZERO_S(cpu_set_size, &set);
  CPU_SET(fji.cores[0], &set);
  sched_setaffinity(0, cpu_set_size, &set);

  const u64 t0 = time_nsec();
  thread_do_fork_join_worker(fjp.ptr);
  const u64 dt = time_diff_nsec(t0);

  // restore original affinity
  sched_setaffinity(0, cpu_set_size, &set0);
  if (fji.ferr || fji.jerr)
    fprintf(stderr, "%s errors: fork %lu join %lu\n", __func__, fji.ferr, fji.jerr);
  return dt;
}

  int
thread_create_at(const u32 cpu, pthread_t * const thread, void *(*start_routine) (void *), void * const arg)
{
  const u32 cpu_id = cpu % process_ncpu;
  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
  cpu_set_t set;

  CPU_ZERO_S(cpu_set_size, &set);
  CPU_SET(cpu_id, &set);
  pthread_attr_setaffinity_np(&attr, cpu_set_size, &set);
  const int r = pthread_create(thread, &attr, start_routine, arg);
  pthread_attr_destroy(&attr);
  return r;
}

  inline u32
thread_get_core(void)
{
  return (u32)sched_getcpu();
}
// }}} process/thread

// locking {{{

// spinlock {{{
static_assert(sizeof(pthread_spinlock_t) <= sizeof(spinlock), "lock size");

  inline void
spinlock_init(spinlock * const lock)
{
  pthread_spinlock_t * const p = (typeof(p))lock;
  pthread_spin_init(p, PTHREAD_PROCESS_PRIVATE);
}

  inline void
spinlock_lock(spinlock * const lock)
{
  pthread_spinlock_t * const p = (typeof(p))lock;
  pthread_spin_lock(p);
}

  inline bool
spinlock_trylock(spinlock * const lock)
{
  pthread_spinlock_t * const p = (typeof(p))lock;
  return 0 == pthread_spin_trylock(p);
}

  inline bool
spinlock_trylock_nr(spinlock * const lock, u16 nr)
{
  pthread_spinlock_t * const p = (typeof(p))lock;
#pragma nounroll
  do {
    if (0 == pthread_spin_trylock(p))
      return true;
    cpu_pause();
  } while (nr--);
  return false;
}

  inline void
spinlock_unlock(spinlock * const lock)
{
  pthread_spinlock_t * const p = (typeof(p))lock;
  pthread_spin_unlock(p);
}
// }}} spinlock

// pthread mutex {{{
static_assert(sizeof(pthread_mutex_t) <= sizeof(mutex), "lock size");
  inline void
mutex_init(mutex * const lock)
{
  pthread_mutex_t * const p = (typeof(p))lock;
  pthread_mutex_init(p, NULL);
}

  inline void
mutex_lock(mutex * const lock)
{
  pthread_mutex_t * const p = (typeof(p))lock;
#pragma nounroll
  do {
    const int r = pthread_mutex_lock(p);
    if (r == 0)
      return;
    else if (r != EAGAIN)
      debug_die();
  } while (true);
}

  inline bool
mutex_trylock(mutex * const lock)
{
  pthread_mutex_t * const p = (typeof(p))lock;
#pragma nounroll
  do {
    const int r = pthread_mutex_trylock(p);
    if (r == 0)
      return true;
    else if (r == EBUSY)
      return false;
    else if (r != EAGAIN)
      debug_die();
  } while (true);
}

  inline void
mutex_unlock(mutex * const lock)
{
  pthread_mutex_t * const p = (typeof(p))lock;
#pragma nounroll
  do {
    const int r = pthread_mutex_unlock(p);
    if (r == 0)
      return;
    else if ((r != EAGAIN))
      debug_die();
  } while (true);
}
// }}} pthread mutex

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
  atomic_store(pvar, 0);
}

  inline bool
rwlock_trylock_read(rwlock * const lock)
{
  lock_t * const pvar = (typeof(pvar))lock;
  if ((atomic_fetch_add(pvar, 1) >> RWLOCK_WSHIFT) == 0) {
    return true;
  } else {
    atomic_fetch_sub(pvar, 1);
    return false;
  }
}

// actually nr + 1
  inline bool
rwlock_trylock_read_nr(rwlock * const lock, u16 nr)
{
  lock_t * const pvar = (typeof(pvar))lock;
  if ((atomic_fetch_add(pvar, 1) >> RWLOCK_WSHIFT) == 0)
    return true;

#pragma nounroll
  do { // someone already locked; wait for a little while
    cpu_pause();
    if ((atomic_load(pvar) >> RWLOCK_WSHIFT) == 0)
      return true;
  } while (nr--);

  atomic_fetch_sub(pvar, 1);
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
      cpu_pause();
    } while (atomic_load(pvar) >> RWLOCK_WSHIFT);
  } while (true);
}

  inline void
rwlock_unlock_read(rwlock * const lock)
{
  lock_t * const pvar = (typeof(pvar))lock;
  atomic_fetch_sub(pvar, 1);
}

  inline bool
rwlock_trylock_write(rwlock * const lock)
{
  lock_t * const pvar = (typeof(pvar))lock;
  lock_v v0 = atomic_load(pvar);
  return (v0 == 0) && atomic_compare_exchange_weak(pvar, &v0, RWLOCK_WBIT);
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
      cpu_pause();
    } while (atomic_load(pvar));
  } while (true);
}

  inline void
rwlock_unlock_write(rwlock * const lock)
{
  lock_t * const pvar = (typeof(pvar))lock;
  atomic_fetch_sub(pvar, RWLOCK_WBIT);
}

  inline void
rwlock_write_to_read(rwlock * const lock)
{
  lock_t * const pvar = (typeof(pvar))lock;
  // +R -W
  atomic_fetch_add(pvar, ((lock_v)1) - RWLOCK_WBIT);
}

#undef RWLOCK_WSHIFT
#undef RWLOCK_WBIT
// }}} rwlock

// }}} locking

// coroutine {{{

#if defined(__x86_64__)

// co {{{
// number pushes in co_switch_stack
#define CO_CONTEXT_SIZE ((6))

// for switch/exit: pass a return value to the target
asm (
    ".global co_switch_stack;"
    ".type co_switch_stack, @function;"
    ".align 16;"
    "co_switch_stack:"
    "push %rbp; push %rbx; push %r12;"
    "push %r13; push %r14; push %r15;"
    "mov  %rsp, (%rdi);"
    "mov  %rsi, %rsp;"
    "pop  %r15; pop  %r14; pop  %r13;"
    "pop  %r12; pop  %rbx; pop  %rbp;"
    "mov  %rdx, %rax;"
    "retq;"
    );

struct co {
  u64 rsp;
  void * priv;
  u64 * host; // set host to NULL to exit
  size_t stksz;
};

static __thread struct co * volatile co_curr = NULL; // NULL in host

// the stack sits under the struct co
  static void
co_init(struct co * const co, void * func, void * priv, u64 * const host,
    const u64 stacksize, void * func_exit)
{
  u64 * rsp = ((u64 *)co) - 4;
  rsp[0] = (u64)func;
  rsp[1] = (u64)func_exit;
  rsp[2] = (u64)debug_die;
  rsp[3] = 0;

  rsp -= CO_CONTEXT_SIZE;

  co->rsp = (u64)rsp;
  co->priv = priv;
  co->host = host;
  co->stksz = stacksize;
}

  static void
co_exit0(void)
{
  co_exit(0);
}

  struct co *
co_create(const u64 stacksize, void * func, void * priv, u64 * const host)
{
  const size_t alloc_size = stacksize + sizeof(struct co);
  u8 * const mem = yalloc(alloc_size);
  if (mem == NULL)
    return NULL;

#if COSTACKCHECK
  memset(mem, 0x5c, stacksize);
#endif

  struct co * const co = (typeof(co))(mem + stacksize);
  co_init(co, func, priv, host, stacksize, co_exit0);
  return co;
}

  inline void
co_reuse(struct co * const co, void * func, void * priv, u64 * const host)
{
  co_init(co, func, priv, host, co->stksz, co_exit0);
}

  inline struct co *
co_fork(void * func, void * priv)
{
  return co_curr ? co_create(co_curr->stksz, func, priv, co_curr->host) : NULL;
}

  inline void *
co_priv(void)
{
  return co_curr ? co_curr->priv : NULL;
}

// the host calls this to enter a coroutine.
  inline u64
co_enter(struct co * const to, const u64 retval)
{
  debug_assert(co_curr == NULL); // must entry from the host
  debug_assert(to && to->host);
  u64 * const save = to->host;
  co_curr = to;
  const u64 ret = co_switch_stack(save, to->rsp, retval);
  co_curr = NULL;
  return ret;
}

// switch from a coroutine to another coroutine
// co_curr must be valid
// the target will resume and receive the retval
  inline u64
co_switch_to(struct co * const to, const u64 retval)
{
  debug_assert(co_curr);
  debug_assert(co_curr != to);
  debug_assert(to && to->host);
  struct co * const save = co_curr;
  co_curr = to;
  return co_switch_stack(&(save->rsp), to->rsp, retval);
}

// switch from a coroutine to the host routine
// co_yield is now a c++ keyword...
  inline u64
co_back(const u64 retval)
{
  debug_assert(co_curr);
  struct co * const save = co_curr;
  co_curr = NULL;
  return co_switch_stack(&(save->rsp), *(save->host), retval);
}

// return to host and set host to NULL
__attribute__((noreturn))
  void
co_exit(const u64 retval)
{
  debug_assert(co_curr);
  const u64 hostrsp = *(co_curr->host);
  co_curr->host = NULL;
  struct co * const save = co_curr;
  co_curr = NULL;
  (void)co_switch_stack(&(save->rsp), hostrsp, retval);
  // return to co_enter
  debug_die();
}

// host is set to NULL on exit
  inline bool
co_valid(struct co * const co)
{
  return co->host != NULL;
}

// return NULL on host
  inline struct co *
co_self(void)
{
  return co_curr;
}

  inline void
co_destroy(struct co * const co)
{
  u8 * const mem = ((u8 *)co) - co->stksz;
  free(mem);
}
// }}} co

// corr {{{

struct corr {
  struct co co;
  struct corr * next;
  struct corr * prev;
};

//static __thread struct corr * corr_head = NULL; // NULL in host

// co-routine

// initial and link guest to the run-queue
  struct corr *
corr_create(const u64 stacksize, void * func, void * priv, u64 * const host)
{
  const size_t alloc_size = stacksize + sizeof(struct corr);
  u8 * const mem = yalloc(alloc_size);
  if (mem == NULL)
    return NULL;

#if COSTACKCHECK
  memset(mem, 0x5c, stacksize);
#endif

  struct corr * const co = (typeof(co))(mem + stacksize);
  co_init(&(co->co), func, priv, host, stacksize, corr_exit);
  co->next = co;
  co->prev = co;
  return co;
}

  struct corr *
corr_link(const u64 stacksize, void * func, void * priv, struct corr * const prev)
{
  const size_t alloc_size = stacksize + sizeof(struct corr);
  u8 * const mem = yalloc(alloc_size);
  if (mem == NULL)
    return NULL;

#if COSTACKCHECK
  memset(mem, 0x5c, stacksize);
#endif

  struct corr * const co = (typeof(co))(mem + stacksize);
  co_init(&(co->co), func, priv, prev->co.host, stacksize, corr_exit);
  co->next = prev->next;
  co->prev = prev;
  co->prev->next = co;
  co->next->prev = co;
  return co;
}

  inline void
corr_reuse(struct corr * const co, void * func, void * priv, u64 * const host)
{
  co_init(&(co->co), func, priv, host, co->co.stksz, corr_exit);
  co->next = co;
  co->prev = co;
}

  inline void
corr_relink(struct corr * const co, void * func, void * priv, struct corr * const prev)
{
  co_init(&(co->co), func, priv, prev->co.host, co->co.stksz, corr_exit);
  co->next = prev->next;
  co->prev = prev;
  co->prev->next = co;
  co->next->prev = co;
}

  inline void
corr_enter(struct corr * const co)
{
  (void)co_enter(&(co->co), 0);
}

  inline void
corr_yield(void)
{
  struct corr * const curr = (typeof(curr))co_curr;
  debug_assert(curr);
  if (curr && (curr->next != curr))
    (void)co_switch_to(&(curr->next->co), 0);
}

__attribute__((noreturn))
  inline void
corr_exit(void)
{
  debug_assert(co_curr);
#if COSTACKCHECK
  u8 * ptr = ((u8 *)(co_curr)) - co_curr->stksz;
  while ((*ptr) == 0x5c)
    ptr++;
  const u64 used = ((u8 *)co_curr) - ptr;
  fprintf(stderr, "%s stack usage %lu\n", __func__, used);
#endif

  struct corr * const curr = (typeof(curr))co_curr;
  if (curr->next != curr) { // have more corr
    struct corr * const next = curr->next;
    struct corr * const prev = curr->prev;
    next->prev = prev;
    prev->next = next;
    curr->next = NULL;
    curr->prev = NULL;
    curr->co.host = NULL; // invalidate
    (void)co_switch_to(&(next->co), 0);
  } else { // the last corr
    co_exit0();
  }
  debug_die();
}

  inline void
corr_destroy(struct corr * const co)
{
  co_destroy(&(co->co));
}
// }}} corr

#endif //__x86_64__

// }}} co

// bits {{{
  inline u32
bits_reverse_u32(const u32 v)
{
  const u32 v2 = bswap_32(v);
  const u32 v3 = ((v2 & 0xf0f0f0f0u) >> 4) | ((v2 & 0x0f0f0f0fu) << 4);
  const u32 v4 = ((v3 & 0xccccccccu) >> 2) | ((v3 & 0x33333333u) << 2);
  const u32 v5 = ((v4 & 0xaaaaaaaau) >> 1) | ((v4 & 0x55555555u) << 1);
  return v5;
}

  inline u64
bits_reverse_u64(const u64 v)
{
  const u64 v2 = bswap_64(v);
  const u64 v3 = ((v2 & 0xf0f0f0f0f0f0f0f0lu) >>  4) | ((v2 & 0x0f0f0f0f0f0f0f0flu) <<  4);
  const u64 v4 = ((v3 & 0xcccccccccccccccclu) >>  2) | ((v3 & 0x3333333333333333lu) <<  2);
  const u64 v5 = ((v4 & 0xaaaaaaaaaaaaaaaalu) >>  1) | ((v4 & 0x5555555555555555lu) <<  1);
  return v5;
}

  inline u64
bits_rotl_u64(const u64 v, const u64 n)
{
  const u64 sh = n & 0x3f;
  return (v << sh) | (v >> (64 - sh));
}

  inline u64
bits_rotr_u64(const u64 v, const u64 n)
{
  const u64 sh = n & 0x3f;
  return (v >> sh) | (v << (64 - sh));
}

  inline u32
bits_rotl_u32(const u32 v, const u64 n)
{
  const u64 sh = n & 0x1f;
  return (v << sh) | (v >> (32 - sh));
}

  inline u32
bits_rotr_u32(const u32 v, const u64 n)
{
  const u64 sh = n & 0x1f;
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
bits_p2_down(const u64 v)
{
  return v ? (1lu << (63lu - (u64)__builtin_clzl(v))) : v;
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

  inline u32
vi128_estimate(const u64 v)
{
  return v ? ((70u - ((u32)__builtin_clzl(v))) / 7u) : 1;
}

// return ptr after the generated bytes
  u8 *
vi128_encode_u64(u8 * dst, u64 v)
{
  while (v >> 7) {
    *(dst++) = (((u8)v) & 0x7f) | 0x80;
    v >>= 7; // from low bits to high bits
  }
  *(dst++) = (u8)v;
  return dst;
}

  u8 *
vi128_encode_u32(u8 * dst, u32 v)
{
  while (v >> 7) {
    *(dst++) = (((u8)v) & 0x7f) | 0x80;
    v >>= 7; // from low bits to high bits
  }
  *(dst++) = (u8)v;
  return dst;
}

// return ptr after the consumed bytes
  const u8 *
vi128_decode_u64(const u8 * src, u64 * const out)
{
  u64 r = 0;
  for (u32 shift = 0; shift < 64; shift += 7) {
    const u8 byte = *(src++);
    r |= (((u64)(byte & 0x7f)) << shift);
    if ((byte & 0x80) == 0) { // No more bytes to consume
      *out = r;
      return src;
    }
  }
  return NULL; // invalid
}

  const u8 *
vi128_decode_u32(const u8 * src, u32 * const out)
{
  u32 r = 0;
  for (u32 shift = 0; shift < 32; shift += 7) {
    const u8 byte = *(src++);
    r |= (((u32)(byte & 0x7f)) << shift);
    if ((byte & 0x80) == 0) { // No more bytes to consume
      *out = r;
      return src;
    }
  }
  return NULL; // invalid
}
// }}} bits

// bitmap {{{
// Partially thread-safe bitmap; call it Eventual Consistency?
struct bitmap {
  u64 bits;
  au64 ones;
  au64 bm[];
};

  inline struct bitmap *
bitmap_create(const u64 bits)
{
  struct bitmap * const bm = calloc(1, sizeof(*bm) + (bits_round_up(bits, 6) >> 3));
  bm->bits = bits;
  bm->ones = 0;
  return bm;
}

  inline bool
bitmap_test(const struct bitmap * const bm, const u64 idx)
{
  return (idx < bm->bits) && (bm->bm[idx >> 6] & (1lu << (idx & 0x3flu)));
}

  inline bool
bitmap_test_all1(struct bitmap * const bm)
{
  return bm->ones == bm->bits;
}

  inline bool
bitmap_test_all0(struct bitmap * const bm)
{
  return bm->ones == 0;
}

  inline void
bitmap_set1(struct bitmap * const bm, const u64 idx)
{
  if ((idx < bm->bits) && !bitmap_test(bm, idx)) {
    debug_assert(bm->ones < bm->bits);
    bm->bm[idx >> 6] |= (1lu << (idx & 0x3flu));
    bm->ones++;
  }
}

  inline void
bitmap_set0(struct bitmap * const bm, const u64 idx)
{
  if ((idx < bm->bits) && bitmap_test(bm, idx)) {
    debug_assert(bm->ones && (bm->ones <= bm->bits));
    bm->bm[idx >> 6] &= ~(1lu << (idx & 0x3flu));
    bm->ones--;
  }
}

  inline u64
bitmap_count(struct bitmap * const bm)
{
  return bm->ones;
}

  inline void
bitmap_set_all1(struct bitmap * const bm)
{
  memset(bm->bm, 0xff, bits_round_up(bm->bits, 6) >> 3);
  bm->ones = bm->bits;
}

  inline void
bitmap_set_all0(struct bitmap * const bm)
{
  memset(bm->bm, 0, bits_round_up(bm->bits, 6) >> 3);
  bm->ones = 0;
}

  inline void
bitmap_static_init(struct bitmap * const bm, const u64 bits)
{
  bm->bits = bits;
  bitmap_set_all0(bm);
}
// }}} bitmap

// bloom filter {{{
struct bf {
  u64 nr_probe;
  struct bitmap bitmap;
};

  struct bf *
bf_create(const u64 bpk, const u64 nkeys)
{
  const u64 nbits = bpk * nkeys;
  struct bf * const bf = malloc(sizeof(*bf) + (bits_round_up(nbits, 6) >> 3));
  bf->nr_probe = (u64)(log(2.0) * (double)bpk);
  bitmap_static_init(&(bf->bitmap), nbits);
  return bf;
}

  static inline u64
bf_inc(const u64 hash)
{
  return bits_rotl_u64(hash, 31);
}

  void
bf_add(struct bf * const bf, u64 hash64)
{
  u64 t = hash64;
  const u64 inc = bf_inc(hash64);
  const u64 bits = bf->bitmap.bits;
  for (u64 i = 0; i < bf->nr_probe; i++) {
    bitmap_set1(&(bf->bitmap), t % bits);
    t += inc;
  }
}

  bool
bf_test(const struct bf * const bf, u64 hash64)
{
  u64 t = hash64;
  const u64 inc = bf_inc(hash64);
  const u64 bits = bf->bitmap.bits;
  for (u64 i = 0; i < bf->nr_probe; i++) {
    if (!bitmap_test(&(bf->bitmap), t % bits))
      return false;
    t += inc;
  }
  return true;
}

  void
bf_clean(struct bf * const bf)
{
  bitmap_set_all0(&(bf->bitmap));
}

  void
bf_destroy(struct bf * const bf)
{
  free(bf);
}
// }}} bloom filter

// slab {{{
#define SLAB_OBJ0_OFFSET ((64))
struct slab_object {
  struct slab_object * next;
};

struct slab {
  spinlock lock;
  u64 obj_size;
  struct slab_object * obj_head;
  u64 blk_size; // size of each memory block
  u64 nr_ready; // available objects buffered
  u64 nr_alloc; // number of objects in use
  u64 objs_per_slab; // number of objects in a slab
  struct slab_object * blk_head; // list of all blocks
};

  static bool
slab_expand(struct slab * const slab)
{
  size_t blk_size;
  struct slab_object * const blk = pages_alloc_best(slab->blk_size, true, &blk_size);
  (void)blk_size;
  if (blk == NULL)
    return false;
  debug_assert(blk_size == slab->blk_size);
  blk->next = slab->blk_head;
  slab->blk_head = blk;
  slab->nr_ready += slab->objs_per_slab;

  u8 * const base = ((u8 *)blk) + SLAB_OBJ0_OFFSET;
  struct slab_object * iter = slab->obj_head;
  for (u64 i = slab->objs_per_slab; i; i--) {
    struct slab_object * const obj = (typeof(obj))(base + ((i - 1) * slab->obj_size));
    obj->next = iter;
    iter = obj;
  }
  slab->obj_head = iter;
  return true;
}

  struct slab *
slab_create(const u64 obj_size, const u64 blk_size)
{
  // obj must be 8-byte aligned
  // blk must be at least of page size and power of 2
  if ((obj_size % 8lu) || (blk_size < 4096lu) || (blk_size & (blk_size - 1)))
    return NULL;

  struct slab * const slab = malloc(sizeof(*slab));
  if (slab == NULL)
    return NULL;
  spinlock_init(&(slab->lock));
  slab->obj_size = obj_size;
  slab->obj_head = NULL;
  slab->blk_size = blk_size;
  slab->nr_ready = 0;
  slab->nr_alloc = 0;
  slab->objs_per_slab = (blk_size - SLAB_OBJ0_OFFSET) / obj_size;
  slab->blk_head = NULL;
  return slab;
}

  bool
slab_reserve_unsafe(struct slab * const slab, const u64 nr)
{
  while (slab->nr_ready < nr)
    if (slab_expand(slab) == false)
      return false;
  return true;
}

  void *
slab_alloc_unsafe(struct slab * const slab)
{
  if (slab->obj_head == NULL) {
    debug_assert(slab->nr_ready == 0);
    if (slab_expand(slab) == false)
      return NULL;
  }
  debug_assert(slab->obj_head);
  struct slab_object * const obj = slab->obj_head;
  slab->obj_head = obj->next;
  slab->nr_ready--;
  slab->nr_alloc++;
  return (void *)obj;
}

  void *
slab_alloc(struct slab * const slab)
{
  spinlock_lock(&(slab->lock));
  void * const ptr = slab_alloc_unsafe(slab);
  spinlock_unlock(&(slab->lock));
  return ptr;
}

  void
slab_free_unsafe(struct slab * const slab, void * const ptr)
{
  struct slab_object * const obj = (typeof(obj))ptr;
  obj->next = slab->obj_head;
  slab->obj_head = obj;
  slab->nr_alloc--;
  slab->nr_ready++;
}

  void
slab_free(struct slab * const slab, void * const ptr)
{
  spinlock_lock(&(slab->lock));
  slab_free_unsafe(slab, ptr);
  spinlock_unlock(&(slab->lock));
}

// unsafe
  u64
slab_get_inuse(struct slab * const slab)
{
  return slab->nr_alloc;
}

// unsafe
  u64
slab_get_ready(struct slab * const slab)
{
  return slab->nr_ready;
}

  void
slab_destroy(struct slab * const slab)
{
  if (slab == NULL)
    return;
  struct slab_object * iter = slab->blk_head;
  while (iter) {
    struct slab_object * const next = iter->next;
    pages_unmap(iter, slab->blk_size);
    iter = next;
  }
  free(slab);
}
// }}} slab

// qsort {{{
  static int
compare_u16(const void * const p1, const void * const p2)
{
  const u16 v1 = *((const u16 *)p1);
  const u16 v2 = *((const u16 *)p2);
  if (v1 < v2)
    return -1;
  else if (v1 > v2)
    return 1;
  else
    return 0;
}

  inline void
qsort_u16(u16 * const array, const size_t nr)
{
  qsort(array, nr, sizeof(array[0]), compare_u16);
}

  inline u16 *
bsearch_u16(const u16 v, const u16 * const array, const size_t nr)
{
  return (u16 *)bsearch(&v, array, nr, sizeof(u16), compare_u16);
}

  void
shuffle_u16(u16 * const array, const u64 nr)
{
  u64 i = nr - 1; // i from nr-1 to 1
  do {
    const u64 j = random_u64() % i; // j < i
    const u16 t = array[j];
    array[j] = array[i];
    array[i] = t;
  } while (--i);
}

  static int
compare_u32(const void * const p1, const void * const p2)
{
  const u32 v1 = *((const u32 *)p1);
  const u32 v2 = *((const u32 *)p2);
  if (v1 < v2)
    return -1;
  else if (v1 > v2)
    return 1;
  else
    return 0;
}

  inline void
qsort_u32(u32 * const array, const size_t nr)
{
  qsort(array, nr, sizeof(array[0]), compare_u32);
}

  inline u32 *
bsearch_u32(const u32 v, const u32 * const array, const size_t nr)
{
  return (u32 *)bsearch(&v, array, nr, sizeof(u32), compare_u32);
}

  void
shuffle_u32(u32 * const array, const u64 nr)
{
  u64 i = nr - 1; // i from nr-1 to 1
  do {
    const u64 j = random_u64() % i; // j < i
    const u32 t = array[j];
    array[j] = array[i];
    array[i] = t;
  } while (--i);
}

  static int
compare_u64(const void * const p1, const void * const p2)
{
  const u64 v1 = *((const u64 *)p1);
  const u64 v2 = *((const u64 *)p2);
  if (v1 < v2)
    return -1;
  else if (v1 > v2)
    return 1;
  else
    return 0;
}

  inline void
qsort_u64(u64 * const array, const size_t nr)
{
  qsort(array, nr, sizeof(array[0]), compare_u64);
}

  inline u64 *
bsearch_u64(const u64 v, const u64 * const array, const size_t nr)
{
  return (u64 *)bsearch(&v, array, nr, sizeof(u64), compare_u64);
}

  void
shuffle_u64(u64 * const array, const u64 nr)
{
  u64 i = nr - 1; // i from nr-1 to 1
  do {
    const u64 j = random_u64() % i; // j < i
    const u64 t = array[j];
    array[j] = array[i];
    array[i] = t;
  } while (--i);
}

  static int
compare_double(const void * const p1, const void * const p2)
{
  const double v1 = *((const double *)p1);
  const double v2 = *((const double *)p2);
  if (v1 < v2)
    return -1;
  else if (v1 > v2)
    return 1;
  else
    return 0;
}

  inline void
qsort_double(double * const array, const size_t nr)
{
  qsort(array, nr, sizeof(array[0]), compare_double);
}

  void
qsort_u64_sample(const u64 * const array0, const u64 nr, const u64 res, FILE * const out)
{
  const u64 datasize = nr * sizeof(array0[0]);
  u64 * const array = malloc(datasize);
  debug_assert(array);
  memcpy(array, array0, datasize);
  qsort_u64(array, nr);

  const double sized = (double)nr;
  const u64 srate = res ? res : 64;
  const u64 xstep = ({u64 step = nr / srate; step ? step : 1; });
  const u64 ystep = ({u64 step = (array[nr - 1] - array[0]) / srate; step ? step : 1; });
  u64 i = 0;
  fprintf(out, "%lu %06.2lf %lu\n", i, ((double)(i + 1)) * 100.0 / sized, array[i]);
  for (u64 j = 1; j < nr; j++) {
    if (((j - i) >= xstep) || (array[j] - array[i]) >= ystep) {
      i = j;
      fprintf(out, "%lu %06.2lf %lu\n", i, ((double)(i + 1)) * 100.0 / sized, array[i]);
    }
  }
  if (i != (nr - 1)) {
    i = nr - 1;
    fprintf(out, "%lu %06.2lf %lu\n", i, ((double)(i + 1)) * 100.0 / sized, array[i]);
  }
  free(array);
}

  void
qsort_double_sample(const double * const array0, const u64 nr, const u64 res, FILE * const out)
{
  const u64 datasize = nr * sizeof(double);
  double * const array = malloc(datasize);
  debug_assert(array);
  memcpy(array, array0, datasize);
  qsort_double(array, nr);

  const u64 srate = res ? res : 64;
  const double srate_d = (double)srate;
  const double sized = (double)nr;
  const u64 xstep = ({u64 step = nr / srate; step ? step : 1; });
  const double ystep = ({ double step = fabs((array[nr - 1] - array[0]) / srate_d); step != 0.0 ? step : 1.0; });
  u64 i = 0;
  fprintf(out, "%lu %06.2lf %020.9lf\n", i, ((double)(i + 1)) * 100.0 / sized, array[i]);
  for (u64 j = 1; j < nr; j++) {
    if (((j - i) >= xstep) || (array[j] - array[i]) >= ystep) {
      i = j;
      fprintf(out, "%lu %06.2lf %020.9lf\n", i, ((double)(i + 1)) * 100.0 / sized, array[i]);
    }
  }
  if (i != (nr - 1)) {
    i = nr - 1;
    fprintf(out, "%lu %06.2lf %020.9lf\n", i, ((double)(i + 1)) * 100.0 / sized, array[i]);
  }
  free(array);
}
// }}} qsort

// xlog {{{
struct xlog {
  u64 nr_rec;
  u64 nr_cap;
  u64 unit_size;
  u8 * ptr;
};

  struct xlog *
xlog_create(const u64 nr_init, const u64 unit_size)
{
  struct xlog * const xlog = yalloc(sizeof(*xlog));
  debug_assert(xlog);
  xlog->nr_rec = 0;
  xlog->nr_cap = nr_init ? nr_init : 4096;
  debug_assert(unit_size);
  xlog->unit_size = unit_size;

  xlog->ptr = malloc(xlog->unit_size * xlog->nr_cap);
  debug_assert(xlog->ptr);
  return xlog;
}

  static bool
xlog_enlarge(struct xlog * const xlog)
{
  const u64 new_cap = (xlog->nr_cap < (1lu<<20)) ? (xlog->nr_cap * 2) : (xlog->nr_cap + (1lu<<20));
  void * const new_ptr = realloc(xlog->ptr, xlog->unit_size * new_cap);
  if (new_ptr == NULL)
    return false;
  xlog->ptr = new_ptr;
  xlog->nr_cap = new_cap;
  return true;
}

  void
xlog_append(struct xlog * const xlog, const void * const rec)
{
  if ((xlog->nr_rec == xlog->nr_cap) && (!xlog_enlarge(xlog)))
    return;

  u8 * const ptr = xlog->ptr + (xlog->nr_rec * xlog->unit_size);
  memcpy(ptr, rec, xlog->unit_size);
  xlog->nr_rec++;
}

  void
xlog_append_cycle(struct xlog * const xlog, const void * const rec)
{
  if (xlog->nr_rec == xlog->nr_cap)
    xlog->nr_rec = 0;
  xlog_append(xlog, rec);
}

  void
xlog_reset(struct xlog * const xlog)
{
  xlog->nr_rec = 0;
}

  u64
xlog_read(struct xlog * const xlog, void * const buf, const u64 nr_max)
{
  const u64 nr = (xlog->nr_rec < nr_max) ? xlog->nr_rec : nr_max;
  memcpy(buf, xlog->ptr, nr * xlog->unit_size);
  return nr;
}

  void
xlog_dump(struct xlog * const xlog, FILE * const out)
{
  const size_t nd = fwrite(xlog->ptr, xlog->unit_size, xlog->nr_rec, out);
  (void)nd;
  debug_assert(nd == xlog->nr_rec);
}

  void
xlog_destroy(struct xlog * const xlog)
{
  free(xlog->ptr);
  free(xlog);
}

struct xlog_iter {
  const struct xlog * xlog;
  u64 next_id;
};

  struct xlog_iter *
xlog_iter_create(const struct xlog * const xlog)
{
  struct xlog_iter * const iter = malloc(sizeof(*iter));
  iter->xlog = xlog;
  iter->next_id = 0;
  return iter;
}

  bool
xlog_iter_next(struct xlog_iter * const iter, void * const out)
{
  const struct xlog * const xlog = iter->xlog;
  if (iter->next_id < xlog->nr_rec) {
    void * const ptr = xlog->ptr + (xlog->unit_size * iter->next_id);
    memcpy(out, ptr, xlog->unit_size);
    iter->next_id++;
    return true;
  } else {
    return false;
  }
}
// }}} xlog

// string {{{
// string to u64
  inline u64
a2u64(const void * const str)
{
  return strtoull(str, NULL, 10);
}

  inline u32
a2u32(const void * const str)
{
  return (u32)strtoull(str, NULL, 10);
}

  inline s64
a2s64(const void * const str)
{
  return strtoll(str, NULL, 10);
}

  inline s32
a2s32(const void * const str)
{
  return (s32)strtoll(str, NULL, 10);
}

// returns a NULL-terminated list of string tokens.
// After use you only need to free the returned pointer (char **).
  char **
string_tokens(const char * const str, const char * const delim)
{
  if (str == NULL)
    return NULL;
  size_t nptr_alloc = 32;
  char ** tokens = malloc(sizeof(tokens[0]) * nptr_alloc);
  if (tokens == NULL)
    return NULL;
  const size_t bufsize = strlen(str) + 1;
  char * const buf = malloc(bufsize);
  if (buf == NULL)
    goto fail_buf;

  memcpy(buf, str, bufsize);
  char * saveptr = NULL;
  char * tok = strtok_r(buf, delim, &saveptr);
  size_t ntoks = 0;
  while (tok) {
    if (ntoks >= nptr_alloc) {
      nptr_alloc += 32;
      char ** const r = realloc(tokens, sizeof(tokens[0]) * nptr_alloc);
      if (r == NULL)
        goto fail_realloc;

      tokens = r;
    }
    tokens[ntoks] = tok;
    ntoks++;
    tok = strtok_r(NULL, delim, &saveptr);
  }
  tokens[ntoks] = NULL;
  const size_t nptr = ntoks + 1; // append a NULL
  const size_t rsize = (sizeof(tokens[0]) * nptr) + bufsize;
  char ** const r = realloc(tokens, rsize);
  if (r == NULL)
    goto fail_realloc;

  tokens = r;
  char * const dest = (char *)(&(tokens[nptr]));
  memcpy(dest, buf, bufsize);
  for (u64 i = 0; i < ntoks; i++)
    tokens[i] += (dest - buf);

  free(buf);
  return tokens;

fail_realloc:
  free(buf);
fail_buf:
  free(tokens);
  return NULL;
}
// }}} string

// damp {{{
struct damp {
  u64 cap;
  u64 used;
  u64 next;
  u64 events;
  double dshort;
  double dlong;
  double hist[];
};

  struct damp *
damp_create(const u64 cap, const double dshort, const double dlong)
{
  struct damp * const d = malloc(sizeof(*d) + (sizeof(d->hist[0]) * cap));
  d->cap = cap;
  d->used = 0;
  d->next = 0;
  d->events = 0;
  d->dshort = dshort;
  d->dlong = dlong;
  return d;
}

  double
damp_average(const struct damp * const d)
{
  if (d->used == 0)
    return 0.0;
  const u64 start = d->next - d->used;
  double sum = 0.0;
  for (u64 i = 0; i < d->used; i++) {
    const u64 idx = (start + i) % d->cap;
    sum += d->hist[idx];
  }
  const double avg = sum / ((double)d->used);
  return avg;
}

  double
damp_min(const struct damp * const d)
{
  if (d->used == 0)
    return 0.0;
  const u64 start = d->next - d->used;
  double min = d->hist[start % d->cap];
  for (u64 i = 1; i < d->used; i++) {
    const u64 idx = (start + i) % d->cap;
    const double v = d->hist[idx];
    if (v < min) min = v;
  }
  return min;
}

  double
damp_max(const struct damp * const d)
{
  if (d->used == 0)
    return 0.0;
  const u64 start = d->next - d->used;
  double max = d->hist[start % d->cap];
  for (u64 i = 1; i < d->used; i++) {
    const u64 idx = (start + i) % d->cap;
    const double v = d->hist[idx];
    if (v > max) max = v;
  }
  return max;
}

  bool
damp_add_test(struct damp * const d, const double v)
{
  d->hist[d->next] = v;
  d->next = (d->next + 1) % d->cap;
  if (d->used < d->cap) d->used++;
  d->events++;

  // short-distance history
  const u64 end = d->next - 1;
  if (d->used >= 3) {
    const double v0 = d->hist[(end - 0) % d->cap];
    const double v1 = d->hist[(end - 1) % d->cap];
    const double v2 = d->hist[(end - 2) % d->cap];
    const double dd = v0 * d->dshort;
    const double d01 = fabs(v1 - v0);
    const double d02 = fabs(v2 - v0);
    if (d01 < dd && d02 < dd)
      return true;
  }

  // full-distance history
  const double avg = damp_average(d);
  const double dev = avg * d->dlong;
  if (d->used == d->cap) {
    double min = d->hist[0];
    double max = min;
    for (u64 i = 1; i < d->cap; i++) {
      if (d->hist[i] < min) min = d->hist[i];
      if (d->hist[i] > max) max = d->hist[i];
    }
    if (fabs(max - min) < dev)
      return true;
  }

  return d->events >= (d->cap * 2);
}

  void
damp_clean(struct damp * const d)
{
  d->used = 0;
  d->next = 0;
  d->events = 0;
}

  void
damp_destroy(struct damp * const d)
{
  free(d);
}
// }}} damp

// vctr {{{
struct vctr {
  size_t nr;
  union {
    size_t v;
    atomic_size_t av;
  } u[];
};

  struct vctr *
vctr_create(const size_t nr)
{
  struct vctr * const v = calloc(1, sizeof(*v) + (sizeof(v->u[0]) * nr));
  v->nr = nr;
  return v;
}

  inline size_t
vctr_size(struct vctr * const v)
{
  return v->nr;
}

  inline void
vctr_add(struct vctr * const v, const u64 i, const size_t n)
{
  if (i < v->nr)
    v->u[i].v += n;
}

  inline void
vctr_add1(struct vctr * const v, const u64 i)
{
  if (i < v->nr)
    v->u[i].v++;
}

  inline void
vctr_add_atomic(struct vctr * const v, const u64 i, const size_t n)
{
  if (i < v->nr)
    (void)atomic_fetch_add(&(v->u[i].av), n);
}

  inline void
vctr_add1_atomic(struct vctr * const v, const u64 i)
{
  if (i < v->nr)
    (void)atomic_fetch_add(&(v->u[i].av), 1);
}

  inline void
vctr_set(struct vctr * const v, const u64 i, const size_t n)
{
  if (i < v->nr)
    v->u[i].v = n;
}

  size_t
vctr_get(struct vctr * const v, const u64 i)
{
  return (i < v->nr) ?  v->u[i].v : 0;
}

  void
vctr_merge(struct vctr * const to, const struct vctr * const from)
{
  const size_t nr = to->nr < from->nr ? to->nr : from->nr;
  for (u64 i = 0; i < nr; i++)
    to->u[i].v += from->u[i].v;
}

  void
vctr_reset(struct vctr * const v)
{
  memset(v->u, 0, sizeof(v->u[0]) * v->nr);
}

  void
vctr_destroy(struct vctr * const v)
{
  free(v);
}
// }}} vctr

// rgen {{{

// struct {{{
enum rgen_type {
  GEN_CONST,     // constant
  GEN_INCS, GEN_INCU,    // +1
  GEN_SKIPS, GEN_SKIPU,  // +n
  GEN_DECS, GEN_DECU,    // -1
  GEN_EXPO,         // exponential
  GEN_ZIPF,         // Zipfian, 0 is the most popular.
  GEN_XZIPF,        // ScrambledZipfian. scatters the "popular" items across the itemspace.
  GEN_UNIZIPF,      // Uniform + Zipfian
  GEN_UNIFORM,      // Uniformly distributed in an interval [a,b]
  GEN_TRACE32,      // Read from a trace file with unit of u32.
  GEN_TRACE64,      // Read from a trace file with unit of u64.
};

struct rgen_linear {
  union {
    au64 ac;
    u64 uc;
  };
  u64 base;
  u64 mod;
  union {
    s64 inc;
    u64 inc_u64;
  };
};

struct rgen_expo {
  double gamma;
};

struct rgen_trace32 {
  FILE * fin;
  u64 idx;
  u64 avail;
  u64 bufnr;
  u32 * buf;
};

struct rgen_zipfian {
  u64 mod;
  u64 base;
  double quick1;
  double mod_d;
  double zetan;
  double alpha;
  double quick2;
  double eta;
  double theta;
};

struct rgen_uniform {
  u64 base;
  u64 mod;
  double mul;
};

struct rgen_unizipf {
  struct rgen_zipfian zipfian;
  u64 usize;
  u64 zsize;
  u64 base;
};

struct rgen_xzipfian {
  struct rgen_zipfian zipfian;
  u64 mul;
};

typedef u64 (*rgen_next_func)(struct rgen * const);

#define RGEN_ABUF_NR ((4lu))
struct rgen_worker_info {
  union {
    u64 * b64;
    u32 * b32;
  };
  union { // guards
    u64 * g64;
    u32 * g32;
  };
  union {
    u64 * bs64[RGEN_ABUF_NR];
    u32 * bs32[RGEN_ABUF_NR];
  };
  u64 reader_id;
  u64 padding0;
  u8 * mem;
  u64 mem_size;
  u64 alloc_size;
  abool avail[RGEN_ABUF_NR];
  abool running;
  rgen_next_func real_next;
  u64 buffer_nr;
  u64 cpu;
  pthread_t thread;
};

struct rgen {
  rgen_next_func next_wait;
  rgen_next_func next_nowait;
  union {
    struct rgen_linear       linear;
    struct rgen_expo         expo;
    struct rgen_trace32      trace32;
    struct rgen_zipfian      zipfian;
    struct rgen_uniform      uniform;
    struct rgen_unizipf      unizipf;
    struct rgen_xzipfian     xzipfian;
  };
  bool unit_u64;
  bool async_worker;
  enum rgen_type type;
  u64 min;
  u64 max;
  struct rgen_worker_info wi;
};
// }}} struct

// core random {{{
// Lehmer's generator is 2x faster than xorshift
/**
 * D. H. Lehmer, Mathematical methods in large-scale computing units.
 * Proceedings of a Second Symposium on Large Scale Digital Calculating
 * Machinery;
 * Annals of the Computation Laboratory, Harvard Univ. 26 (1951), pp. 141-146.
 *
 * P L'Ecuyer,  Tables of linear congruential generators of different sizes and
 * good lattice structure. Mathematics of Computation of the American
 * Mathematical
 * Society 68.225 (1999): 249-260.
 */
static __thread union {
  u128 v128;
  u64 v64[2];
} rseed_u128 = {.v64 = {4294967291, 1549556881}};

  inline u64
random_u64(void)
{
  const u64 r = rseed_u128.v64[1];
  rseed_u128.v128 *= 0xda942042e4dd58b5lu;
  return r;
}

  inline void
srandom_u64(const u64 seed)
{
  rseed_u128.v128 = (((u128)(~seed)) << 64) | (seed | 1);
  (void)random_u64();
}

  inline double
random_double(void)
{
  // random between [0.0 - 1.0]
  const u64 r = random_u64();
  return ((double)r) * (1.0 / ((double)(~0lu)));
}
// }}} core random

// genenators {{{

// simple ones {{{
  static u64
gen_constant(struct rgen * const gi)
{
  return gi->linear.base;
}

  struct rgen *
rgen_new_constant(const u64 c)
{
  struct rgen * const gi = calloc(1, sizeof(*gi));
  gi->unit_u64 = c > UINT32_MAX;
  gi->linear.base = c;
  gi->type = GEN_CONST;
  gi->min = gi->max = c;
  gi->next_nowait = gi->next_wait = gen_constant;
  return gi;
}

  static u64
gen_expo(struct rgen * const gi)
{
  const double d = - log(random_double()) / gi->expo.gamma;
  return (u64)d;
}

  struct rgen *
rgen_new_expo(const double percentile, const double range)
{
  struct rgen * const gi = calloc(1, sizeof(*gi));
  gi->unit_u64 = true;
  gi->expo.gamma = - log(1.0 - (percentile/100.0)) / range;
  gi->type = GEN_EXPO;
  gi->max = ~0lu;
  gi->next_nowait = gi->next_wait = gen_expo;
  return gi;
}
// }}} simple ones

// linear {{{
  struct rgen *
rgen_new_linear(const u64 min, const u64 max, const s64 inc,
    const enum rgen_type type, rgen_next_func func)
{
  debug_assert(max > min);
  struct rgen * const gi = calloc(1, sizeof(*gi));
  gi->unit_u64 = max > UINT32_MAX;
  gi->linear.uc = 0;
  gi->linear.base = inc >= 0 ? min : max;
  gi->linear.mod = max - min + 1;
  gi->linear.inc = inc;
  gi->type = type;
  gi->min = min;
  gi->max = max;
  gi->next_nowait = gi->next_wait = func;
  return gi;
}

  static u64
gen_linear_incs_helper(struct rgen * const gi)
{
  u64 v = atomic_fetch_add(&(gi->linear.ac), 1);
  const u64 mod = gi->linear.mod;
  if (v >= mod) {
    do {
      v -= mod;
    } while (v >= mod);
    if (v == 0)
      atomic_fetch_sub(&(gi->linear.ac), mod);
  }
  return v;
}

  static u64
gen_linear_incu_helper(struct rgen * const gi)
{
  u64 v = gi->linear.uc++;
  const u64 mod = gi->linear.mod;
  if (v == mod) {
    gi->linear.uc -= mod;
    v = 0;
  }
  return v;
}

  static u64
gen_incs(struct rgen * const gi)
{
  return gi->linear.base + gen_linear_incs_helper(gi);
}

  struct rgen *
rgen_new_incs(const u64 min, const u64 max)
{
  return rgen_new_linear(min, max, 1, GEN_INCS, gen_incs);
}

  static u64
gen_incu(struct rgen * const gi)
{
  return gi->linear.base + gen_linear_incu_helper(gi);
}

  struct rgen *
rgen_new_incu(const u64 min, const u64 max)
{
  return rgen_new_linear(min, max, 1, GEN_INCU, gen_incu);
}

  static u64
gen_skips(struct rgen * const gi)
{
  if (gi->linear.inc >= 0) {
    const u64 v = atomic_fetch_add(&(gi->linear.ac), gi->linear.inc_u64);
    return gi->linear.base + (v % gi->linear.mod);
  } else {
    const u64 v = atomic_fetch_sub(&(gi->linear.ac), gi->linear.inc_u64);
    return gi->linear.base - (v % gi->linear.mod);
  }
}

  struct rgen *
rgen_new_skips(const u64 min, const u64 max, const s64 inc)
{
  return rgen_new_linear(min, max, inc, GEN_SKIPS, gen_skips);
}

  static u64
gen_skipu(struct rgen * const gi)
{
  const u64 v = gi->linear.uc % gi->linear.mod;
  if (gi->linear.inc >= 0) {
    gi->linear.uc += gi->linear.inc_u64;
    return gi->linear.base + v;
  } else {
    gi->linear.uc -= gi->linear.inc_u64;
    return gi->linear.base - v;
  }
}

  struct rgen *
rgen_new_skipu(const u64 min, const u64 max, const s64 inc)
{
  return rgen_new_linear(min, max, inc, GEN_SKIPU, gen_skipu);
}

  static u64
gen_decs(struct rgen * const gi)
{
  return gi->linear.base - gen_linear_incs_helper(gi);
}

  struct rgen *
rgen_new_decs(const u64 min, const u64 max)
{
  return rgen_new_linear(min, max, -1, GEN_DECS, gen_decs);
}

  static u64
gen_decu(struct rgen * const gi)
{
  return gi->linear.base - gen_linear_incu_helper(gi);
}

  struct rgen *
rgen_new_decu(const u64 min, const u64 max)
{
  return rgen_new_linear(min, max, -1, GEN_DECU, gen_decu);
}
// }}} linear

// zipf {{{
  static u64
gen_zipfian(struct rgen * const gi)
{
  // simplified: no increamental update
  const struct rgen_zipfian * const gz = &(gi->zipfian);
  const double u = random_double();
  const double uz = u * gz->zetan;
  if (uz < 1.0)
    return gz->base;
  else if (uz < gz->quick1)
    return gz->base + 1;

  const double x = gz->mod_d * pow((gz->eta * u) + gz->quick2, gz->alpha);
  const u64 ret = gz->base + (u64)x;
  return ret;
}

struct zeta_range_info {
  au64 seq;
  u64 nth;
  u64 start;
  u64 count;
  double theta;
  double sums[];
};

  static void *
zeta_range_worker(void * const ptr)
{
  struct zeta_range_info * const zi = (typeof(zi))ptr;
  const u64 seq = atomic_fetch_add(&(zi->seq), 1);
  const u64 start = zi->start;
  const double theta = zi->theta;
  const u64 count = zi->count;
  const u64 nth = zi->nth;
  double local_sum = 0.0;
  for (u64 i = seq; i < count; i += nth)
    local_sum += (1.0 / pow((double)(start + i + 1), theta));

  zi->sums[seq] = local_sum;
  return NULL;
}

  static double
zeta_range(const u64 start, const u64 count, const double theta)
{
  const u32 ncores = process_affinity_core_count();
  const u32 needed = (u32)((count >> 20) + 1); // 1m per core
  const u32 nth = needed < ncores ? needed : ncores;
  double sum = 0.0;
  debug_assert(nth > 0);
  const size_t zisize = sizeof(struct zeta_range_info) + (sizeof(double) * nth);
  struct zeta_range_info * const zi = malloc(zisize);
  if (zi == NULL) { // rollback
    for (u64 i = 0; i < count; i++)
      sum += (1.0 / pow((double)(start + i + 1), theta));
    return sum;
  }
  memset(zi, 0, zisize);
  zi->nth = nth;
  zi->start = start;
  zi->count = count;
  zi->theta = theta;
  thread_fork_join(nth, zeta_range_worker, false, zi);
  for (u64 i = 0; i < nth; i++)
    sum += zi->sums[i];
  free(zi);
  return sum;
}

static const u64 zetalist_u64[] = {0,
  0x4040437dd948c1d9lu, 0x4040b8f8009bce85lu,
  0x4040fe1121e564d6lu, 0x40412f435698cdf5lu,
  0x404155852507a510lu, 0x404174d7818477a7lu,
  0x40418f5e593bd5a9lu, 0x4041a6614fb930fdlu,
  0x4041bab40ad5ec98lu, 0x4041cce73d363e24lu,
  0x4041dd6239ebabc3lu, 0x4041ec715f5c47belu,
  0x4041fa4eba083897lu, 0x4042072772fe12bdlu,
  0x4042131f5e380b72lu, 0x40421e53630da013lu,
};

static const double * zetalist_double = (typeof(zetalist_double))zetalist_u64;
static const u64 zetalist_step = 0x10000000000lu;
static const u64 zetalist_count = 16;
//static const double zetalist_theta = 0.99;

  static double
zeta(const u64 n, const double theta)
{
  //assert(theta == 0.99);
  const u64 zlid0 = n / zetalist_step;
  const u64 zlid = (zlid0 > zetalist_count) ? zetalist_count : zlid0;
  const double sum0 = zetalist_double[zlid];
  const u64 start = zlid * zetalist_step;
  const u64 count = n - start;
  const double sum1 = zeta_range(start, count, theta);
  return sum0 + sum1;
}

  struct rgen *
rgen_new_zipfian(const u64 min, const u64 max)
{
#define ZIPFIAN_CONSTANT ((0.99))  // DONT change this number
  struct rgen * const gi = calloc(1, sizeof(*gi));
  gi->unit_u64 = max > UINT32_MAX;
  struct rgen_zipfian * const gz = &(gi->zipfian);

  const u64 mod = max - min + 1;
  gz->mod = mod;
  gz->mod_d = (double)mod;
  gz->base = min;
  gz->theta = ZIPFIAN_CONSTANT;
  gz->quick1 = 1.0 + pow(0.5, gz->theta);
  const double zeta2theta = zeta(2, ZIPFIAN_CONSTANT);
  gz->alpha = 1.0 / (1.0 - ZIPFIAN_CONSTANT);
  const double zetan = zeta(mod, ZIPFIAN_CONSTANT);
  gz->zetan = zetan;
  gz->eta = (1.0 - pow(2.0 / (double)mod, 1.0 - ZIPFIAN_CONSTANT)) / (1.0 - (zeta2theta / zetan));
  gz->quick2 = 1.0 - gz->eta;

  gi->type = GEN_ZIPF;
  gi->min = min;
  gi->max = max;
  gi->next_nowait = gi->next_wait = gen_zipfian;
  return gi;
#undef ZIPFIAN_CONSTANT
}

  static u64
gen_xzipfian(struct rgen * const gi)
{
  const u64 z = gen_zipfian(gi);
  const u64 xz = z * gi->xzipfian.mul;
  return gi->zipfian.base + (xz % gi->zipfian.mod);
}

  struct rgen *
rgen_new_xzipfian(const u64 min, const u64 max)
{
  struct rgen * gi = rgen_new_zipfian(min, max);
  const u64 gold = (gi->zipfian.mod / 21 * 13) | 1;
  for (u64 mul = gold;; mul += 2) {
    if (gcd64(mul, gi->zipfian.mod) == 1) {
      gi->xzipfian.mul = mul;
      break;
    }
  }
  gi->unit_u64 = max > UINT32_MAX;
  gi->type = GEN_XZIPF;
  gi->next_nowait = gi->next_wait = gen_xzipfian;
  return gi;
}

  static u64
gen_unizipf(struct rgen * const gi)
{
  //// aggregated hot spots
  //const u64 z = gen_zipfian(gi) * gi->unizipf.usize;
  //const u64 u = random_u64() % gi->unizipf.usize;
  //// scattered hot spots
  const u64 z = gen_zipfian(gi);
  const u64 u = (random_u64() % gi->unizipf.usize) * gi->unizipf.zsize;

  return gi->unizipf.base + z + u;
}

  struct rgen *
rgen_new_unizipf(const u64 min, const u64 max, const u64 ufactor)
{
  const u64 nr = max - min + 1;
  if (ufactor == 1) // covers both special gens
    return rgen_new_zipfian(min, max);
  else if ((ufactor == 0) || ((nr / ufactor) <= 1))
    return rgen_new_uniform(min, max);

  const u64 znr = nr / ufactor;
  struct rgen * gi = rgen_new_zipfian(0, znr - 1);
  gi->unit_u64 = max > UINT32_MAX;
  gi->unizipf.usize = ufactor;
  gi->unizipf.zsize = nr / ufactor;
  gi->unizipf.base = min;
  gi->min = min;
  gi->max = max;
  gi->next_nowait = gi->next_wait = gen_unizipf;
  return gi;
}
// }}} zipf

// others {{{
  static u64
gen_uniform(struct rgen * const gi)
{
  return gi->uniform.base + (u64)(((double)random_u64()) * gi->uniform.mul);
}

  struct rgen *
rgen_new_uniform(const u64 min, const u64 max)
{
  struct rgen * const gi = calloc(1, sizeof(*gi));
  gi->unit_u64 = max > UINT32_MAX;
  gi->uniform.base = min;
  const u64 mod = max - min + 1;
  gi->uniform.mod = mod;
  // 5.4..e-20 * (1 << 64) == 1 - epsilon
  gi->uniform.mul = ((double)mod) * 5.421010862427521e-20;

  gi->type = GEN_UNIFORM;
  gi->min = min;
  gi->max = max;
  gi->next_nowait = gi->next_wait = gen_uniform;
  return gi;
}

  static u64
gen_trace32(struct rgen * const gi)
{
  struct rgen_trace32 * const pt = &(gi->trace32);
  if (pt->idx >= pt->avail) {
    if (feof(pt->fin))
      rewind(pt->fin);
    pt->idx = 0;
    pt->avail = fread(pt->buf, sizeof(u32), pt->bufnr, pt->fin);
    debug_assert(pt->avail);
  }
  const u64 r = pt->buf[pt->idx];
  pt->idx++;
  return r;
}

  struct rgen *
rgen_new_trace32(const char * const filename, const u64 bufsize)
{
  struct rgen * const gi = calloc(1, sizeof(*gi));
  struct rgen_trace32 * const pt = &(gi->trace32);
  pt->fin = fopen(filename, "rb");
  if (pt->fin == NULL) {
    free(gi);
    return NULL;
  }
  pt->idx = 0;
  pt->bufnr = bits_round_up(bufsize, 4) / sizeof(u32);
  pt->buf = malloc(pt->bufnr * sizeof(u32));
  debug_assert(pt->buf);
  pt->avail = fread(pt->buf, sizeof(u32), pt->bufnr, pt->fin);
  if (pt->avail == 0) {
    free(gi);
    return NULL;
  }
  posix_fadvise(fileno(pt->fin), 0, 0, POSIX_FADV_SEQUENTIAL);
  gi->type = GEN_TRACE32;
  gi->max = ~0lu;
  gi->next_nowait = gi->next_wait = gen_trace32;
  return gi;
}
// }}} others

// }}} generators

// rgen helper {{{
  inline u64
rgen_min(struct rgen * const gen)
{
  return gen->min;
}

  inline u64
rgen_max(struct rgen * const gen)
{
  return gen->max;
}

  inline u64
rgen_next_wait(struct rgen * const gen)
{
  return gen->next_wait(gen);
}

  inline u64
rgen_next_nowait(struct rgen * const gen)
{
  return gen->next_nowait(gen);
}

  static void
rgen_clean_async_buffers(struct rgen_worker_info * const info)
{
  if (info->mem == NULL)
    return;
  pages_unmap(info->mem, info->alloc_size);
  info->mem = NULL;
  for (u64 j = 0; j < RGEN_ABUF_NR; j++)
    info->bs64[j] = NULL;
}

  void
rgen_destroy(struct rgen * const gen)
{
  if (gen == NULL)
    return;
  if (gen->async_worker) {
    struct rgen_worker_info * const info = &(gen->wi);
    atomic_store(&(info->running), false);
    pthread_join(info->thread, NULL);
    rgen_clean_async_buffers(info);
  }
  if (gen->type == GEN_TRACE32) {
    fclose(gen->trace32.fin);
    free(gen->trace32.buf);
  }
  free(gen);
}

  void
rgen_helper_message(void)
{
  fprintf(stderr, "%s Usage: rgen <type> ...\n", __func__);
  fprintf(stderr, "%s example: rgen const <value>\n", __func__);
  fprintf(stderr, "%s example: rgen expo <perc> <range>\n", __func__);
  fprintf(stderr, "%s example: rgen unizipf <min> <max> <ufactor>\n", __func__);
  fprintf(stderr, "%s example: rgen uniform <min> <max>\n", __func__);
  fprintf(stderr, "%s example: rgen zipfian <min> <max>\n", __func__);
  fprintf(stderr, "%s example: rgen xzipfian <min> <max>\n", __func__);
  fprintf(stderr, "%s example: rgen incs <min> <max>\n", __func__);
  fprintf(stderr, "%s example: rgen incu <min> <max>\n", __func__);
  fprintf(stderr, "%s example: rgen decs <min> <max>\n", __func__);
  fprintf(stderr, "%s example: rgen decu <min> <max>\n", __func__);
  fprintf(stderr, "%s example: rgen skips <min> <max> <inc>\n", __func__);
  fprintf(stderr, "%s example: rgen skipu <min> <max> <inc>\n", __func__);
  fprintf(stderr, "%s example: rgen trace32 <filename> <bufsize>\n", __func__);
}

  int
rgen_helper(const int argc, char ** const argv, struct rgen ** const gen_out)
{
  if ((argc < 1) || (strcmp("rgen", argv[0]) != 0))
    return -1;
  struct rgen * gen = NULL;
  int ret = -1;

  if ((0 == strcmp(argv[1], "const")) && (argc >= 3)) {
    gen = rgen_new_constant(a2u64(argv[2]));
    ret = 3;
  } else if ((0 == strcmp(argv[1], "expo")) && (argc >= 4)) {
    gen = rgen_new_expo(atof(argv[2]), atof(argv[3]));
    ret = 4;
  } else if ((0 == strcmp(argv[1], "unizipf")) && (argc >= 5)) {
    gen = rgen_new_unizipf(a2u64(argv[2]), a2u64(argv[3]), a2u64(argv[4]));
    ret = 5;
  } else if ((0 == strcmp(argv[1], "uniform")) && (argc >= 4)) {
    gen = rgen_new_uniform(a2u64(argv[2]), a2u64(argv[3]));
    ret = 4;
  } else if ((0 == strcmp(argv[1], "zipfian")) && (argc >= 4)) {
    gen = rgen_new_zipfian(a2u64(argv[2]), a2u64(argv[3]));
    ret = 4;
  } else if ((0 == strcmp(argv[1], "xzipfian")) && (argc >= 4)) {
    gen = rgen_new_xzipfian(a2u64(argv[2]), a2u64(argv[3]));
    ret = 4;
  } else if ((0 == strcmp(argv[1], "incs")) && (argc >= 4)) {
    gen = rgen_new_incs(a2u64(argv[2]), a2u64(argv[3]));
    ret = 4;
  } else if ((0 == strcmp(argv[1], "incu")) && (argc >= 4)) {
    gen = rgen_new_incu(a2u64(argv[2]), a2u64(argv[3]));
    ret = 4;
  } else if ((0 == strcmp(argv[1], "decs")) && (argc >= 4)) {
    gen = rgen_new_decs(a2u64(argv[2]), a2u64(argv[3]));
    ret = 4;
  } else if ((0 == strcmp(argv[1], "decu")) && (argc >= 4)) {
    gen = rgen_new_decu(a2u64(argv[2]), a2u64(argv[3]));
    ret = 4;
  } else if ((0 == strcmp(argv[1], "skips")) && (argc >= 5)) {
    gen = rgen_new_skips(a2u64(argv[2]), a2u64(argv[3]), a2s64(argv[4]));
    ret = 5;
  } else if ((0 == strcmp(argv[1], "skipu")) && (argc >= 5)) {
    gen = rgen_new_skipu(a2u64(argv[2]), a2u64(argv[3]), a2s64(argv[4]));
    ret = 5;
  } else if ((0 == strcmp(argv[1], "trace32")) && (argc >= 4)) {
    gen = rgen_new_trace32(argv[2], a2u64(argv[3]));
    ret = 4;
  }
  *gen_out = gen;
  return ret;
}
// }}} rgen helper

// async {{{
  static void *
rgen_worker(void * const ptr)
{
  struct rgen * const gen = (typeof(gen))ptr;
  struct rgen_worker_info * const info = &(gen->wi);
  const u64 cpu = info->cpu;
  srandom_u64((cpu + 3) * 97);
  const u64 nr = info->buffer_nr;
#pragma nounroll
  while (true) {
    for (u64 i = 0; i < RGEN_ABUF_NR; i++) {
#pragma nounroll
      while (atomic_load(&(info->avail[i])) == true) {
        usleep(10);
        if (atomic_load(&(info->running)) == false)
          return NULL;
      }
      if (gen->unit_u64) {
        u64 * const buf64 = info->bs64[i];
        for (u64 j = 0; j < nr; j++)
          buf64[j] = info->real_next(gen);
      } else {
        u32 * const buf32 = info->bs32[i];
        for (u64 j = 0; j < nr; j++)
          buf32[j] = (u32)(info->real_next(gen));
      }
      atomic_store(&(info->avail[i]), true);
    }
  }
  return NULL;
}

  static void
rgen_async_wait_at(struct rgen * const gen, const u64 id)
{
  abool * const pavail = &(gen->wi.avail[id]);
#pragma nounroll
  while (atomic_load(pavail) == false)
    usleep(1);
}

  void
rgen_async_wait(struct rgen * const gen)
{
  if (gen->async_worker == false)
    return;
  rgen_async_wait_at(gen, gen->wi.reader_id);
}

  void
rgen_async_wait_all(struct rgen * const gen)
{
  if (gen->async_worker == false)
    return;
  for (u64 i = 0; i < RGEN_ABUF_NR; i++)
    rgen_async_wait_at(gen, i);
}

  static u64
rgen_async_next_wait32(struct rgen * const gen)
{
  struct rgen_worker_info * const info = &(gen->wi);
  const u64 r = (u64)(*(info->b32));
  info->b32++;
  if (info->b32 == info->g32) {
    atomic_store(&(info->avail[info->reader_id]), false);
    info->reader_id = (info->reader_id + 1) % RGEN_ABUF_NR;
    info->b32 = info->bs32[info->reader_id];
    info->g32 = info->b32 + info->buffer_nr;
    rgen_async_wait(gen);
  }
  return r;
}

  static u64
rgen_async_next_wait64(struct rgen * const gen)
{
  struct rgen_worker_info * const info = &(gen->wi);
  const u64 r = *(info->b64);
  info->b64++;
  if (info->b64 == info->g64) {
    atomic_store(&(info->avail[info->reader_id]), false);
    info->reader_id = (info->reader_id + 1) % RGEN_ABUF_NR;
    info->b64 = info->bs64[info->reader_id];
    info->g64 = info->b64 + info->buffer_nr;
    rgen_async_wait(gen);
  }
  return r;
}

  static u64
rgen_async_next_nowait32(struct rgen * const gen)
{
  struct rgen_worker_info * const info = &(gen->wi);
  const u64 r = (u64)(*(info->b32));
  info->b32++;
  if (info->b32 == info->g32) {
    info->reader_id = (info->reader_id + 1) % RGEN_ABUF_NR;
    info->b32 = info->bs32[info->reader_id];
    info->g32 = info->b32 + info->buffer_nr;
  }
  return r;
}

  static u64
rgen_async_next_nowait64(struct rgen * const gen)
{
  struct rgen_worker_info * const info = &(gen->wi);
  const u64 r = *(info->b64);
  info->b64++;
  if (info->b64 == info->g64) {
    info->reader_id = (info->reader_id + 1) % RGEN_ABUF_NR;
    info->b64 = info->bs64[info->reader_id];
    info->g64 = info->b64 + info->buffer_nr;
  }
  return r;
}

  struct rgen *
rgen_dup(struct rgen * const gen0)
{
  if (gen0->async_worker)
    return NULL;
  struct rgen * const gen = malloc(sizeof(*gen));
  memcpy(gen, gen0, sizeof(*gen));
  struct rgen_worker_info * const info = &(gen->wi);
  memset(info, 0, sizeof(*info));
  if (gen->type == GEN_TRACE32) {
    FILE * const f2 = fdopen(dup(fileno(gen0->trace32.fin)), "rb");
    posix_fadvise(fileno(f2), 0, 0, POSIX_FADV_SEQUENTIAL);
    gen->trace32.fin = f2;
    gen->trace32.idx = 0;
    gen->trace32.avail = 0;
  }
  return gen;
}

  static void *
rgen_async_convert_mem_worker(void * const ptr)
{
  struct rgen_worker_info * const info = (typeof(info))ptr;
  info->mem = pages_alloc_best(info->mem_size, true, &(info->alloc_size));
  return NULL;
}

  bool
rgen_async_convert(struct rgen * const gen, const u32 cpu)
{
  if (gen == NULL || gen->async_worker)
    return false; // already converted

  struct rgen_worker_info * const info = &(gen->wi);
  memset(info, 0, sizeof(*info));

  info->mem_size = 1lu << 30;
  pthread_t pt_mem;
  thread_create_at(cpu, &pt_mem, rgen_async_convert_mem_worker, info);
  pthread_join(pt_mem, NULL);
  if (info->mem == NULL) {
    fprintf(stderr, "cannot allocate memory for the async worker\n");
    return false; // insufficient memory
  }

  info->real_next = gen->next_wait;
  const u64 usize = gen->unit_u64 ? sizeof(u64) : sizeof(u32);
  info->buffer_nr = info->mem_size / (RGEN_ABUF_NR * usize);
  info->cpu = cpu;
  atomic_store(&(info->running), true);
  for (u64 j = 0; j < RGEN_ABUF_NR; j++) {
    info->bs64[j] = (u64 *)(&(info->mem[j * info->buffer_nr * usize]));
    atomic_store(&(info->avail[j]), false);
  }
  info->b64 = info->bs64[0]; // i == 0;
  info->g64 = info->b64 + info->buffer_nr;
  gen->next_wait = gen->unit_u64 ? rgen_async_next_wait64 : rgen_async_next_wait32;
  gen->next_nowait = gen->unit_u64 ? rgen_async_next_nowait64 : rgen_async_next_nowait32;
  if (thread_create_at(cpu, &(info->thread), rgen_worker, gen) == 0) {
    char thname[32];
    sprintf(thname, "rgen_async_%u", cpu);
    pthread_setname_np(info->thread, thname);
    info->reader_id = 0;
    gen->async_worker = true;
    return true;
  } else {
    rgen_clean_async_buffers(info);
    return false;
  }
}
#undef RGEN_ABUF_NR
// }}} async

// }}} rgen

// rcu {{{

// multi-rcu {{{

// bits 63 -- 16 value (pointer)
// bits 15       valid
// bits 14 -- 0  count (refcount)
#define RCU_COUNT_MASK   ((0x0000000000007ffflu))
#define RCU_VALID_MASK   ((0x0000000000008000lu))
#define RCU_VALUE_MASK   ((0xffffffffffff0000lu))
#define RCU_VALUE_SHIFT  ((16))

// node {{{
struct rcu_node {
  au64 x[8];
};

  void
rcu_node_init(struct rcu_node * const node)
{
  atomic_store(&(node->x[0]), RCU_VALID_MASK); // valid null pointer
  atomic_store(&(node->x[1]), RCU_VALUE_MASK); // invalid non-null pointer
}

  struct rcu_node *
rcu_node_create(void)
{
  struct rcu_node * const node = malloc(sizeof(*node));
  rcu_node_init(node);
  return node;
}

  void *
rcu_node_ref(struct rcu_node * const node)
{
  do {
    for (u64 i = 0; i < 2; i++) {
      u64 x = node->x[i];
      if (x & RCU_VALID_MASK) {
        if (atomic_compare_exchange_weak(&(node->x[i]), &x, x + 1))
          return (void *)(x >> RCU_VALUE_SHIFT);
      }
    }
  } while (true);
}

  void
rcu_node_unref(struct rcu_node * const node, void * const ptr)
{
  for (u64 i = 0; i < 2; i++) {
    const u64 x = node->x[i];
    if ((x >> RCU_VALUE_SHIFT) == ((u64)ptr)) {
      (void)atomic_fetch_sub(&(node->x[i]), 1);
      return;
    }
  }
  debug_die();
}

  void
rcu_node_update(struct rcu_node * const node, void * const ptr)
{
  const u64 xx = (((u64)ptr) << RCU_VALUE_SHIFT) | RCU_VALID_MASK;
  for (u64 i = 0; i < 2; i++) {
    if ((node->x[i] & RCU_VALID_MASK) == 0) {
      atomic_store(&(node->x[i]), xx);
      au64 * const v = &(node->x[1-i]);
      debug_assert(((*v) >> RCU_VALUE_SHIFT) != ((u64)ptr));
      (void)atomic_fetch_sub(v, RCU_VALID_MASK);
#pragma nounroll
      while (atomic_load(v) & RCU_COUNT_MASK)
        cpu_pause();
      return;
    }
  }
  debug_die();
}
// }}} node

struct rcu {
  u64 nr;
  u64 mask;
  u64 padding[6];
  struct rcu_node nodes[];
};

  void
rcu_init(struct rcu * const rcu, const u64 nr)
{
  rcu->nr = nr;
  rcu->mask = nr - 1;
  for (u64 i = 0; i < nr; i++)
    rcu_node_init(&(rcu->nodes[i]));
}

  struct rcu *
rcu_create(const u64 nr)
{
  struct rcu * const rcu = yalloc(sizeof(*rcu) + (nr * sizeof(rcu->nodes[0])));
  rcu_init(rcu, nr);
  return rcu;
}

  void *
rcu_ref(struct rcu * const rcu, const u64 magic)
{
  struct rcu_node * const node = &(rcu->nodes[magic & rcu->mask]);
  return rcu_node_ref(node);
}

  void
rcu_unref(struct rcu * const rcu, void * const ptr, const u64 magic)
{
  struct rcu_node * const node = &(rcu->nodes[magic & rcu->mask]);
  rcu_node_unref(node, ptr);
}

  void
rcu_update(struct rcu * const rcu, void * const ptr)
{
  const u64 xx = (((u64)ptr) << RCU_VALUE_SHIFT) | RCU_VALID_MASK;
  const u64 nr = rcu->nr;
  for (u64 i = 0; i < nr; i++) {
    struct rcu_node * const node = &(rcu->nodes[i]);
    for (u64 j = 0; j < 2; j++) {
      if ((node->x[j] & RCU_VALID_MASK) == 0) {
        // enable node pointer
        atomic_store(&(node->x[j]), xx);
        au64 * const v = &(node->x[1-j]);
        debug_assert(((*v) >> RCU_VALUE_SHIFT) != ((u64)ptr));
        (void)atomic_fetch_sub(v, RCU_VALID_MASK);
        break;
      }
    }
  }
  cpu_cfence();
  // wait
  for (u64 i = 0; i < nr; i++) {
    struct rcu_node * const node = &(rcu->nodes[i]);
    for (u64 j = 0; j < 2; j++) {
      const u64 x = node->x[j];
      if ((x & RCU_VALID_MASK) == 0) {
        au64 * const v = &(node->x[j]);
#pragma nounroll
        while (atomic_load(v) & RCU_COUNT_MASK)
          cpu_pause();
        break;
      }
    }
  }
}

#undef RCU_COUNT_MASK
#undef RCU_VALID_MASK
#undef RCU_VALUE_MASK
#undef RCU_VALUE_SHIFT
// }}} multi-rcu

// qsbr {{{
#define QSBR_STATES_NR ((22)) // 3*8-2 == 22; 5*8-2 == 38; 7*8-2 == 54
#define QSBR_BITMAP_FULL ((1lu << QSBR_STATES_NR) - 1)
#define QSBR_SHARDS_BITS ((3))
#define QSBR_SHARDS_NR  (((1lu) << QSBR_SHARDS_BITS))
#define QSBR_CAPACITY ((QSBR_STATES_NR * QSBR_SHARDS_NR))
#define QSBR_MHASH_SHIFT ((64 - QSBR_SHARDS_BITS))

// Quiescent-State-Based Reclamation RCU
struct qsbr {
  volatile u64 target;
  u64 padding0[7];
  struct qshard {
    spinlock lock;
    u64 bitmap;
    volatile u64 * ptrs[QSBR_STATES_NR];
  } shards[QSBR_SHARDS_NR];
  volatile u64 * wait_ptrs[QSBR_CAPACITY];
};

  struct qsbr *
qsbr_create(void)
{
  struct qsbr * const q = yalloc(sizeof(*q));
  memset(q, 0, sizeof(*q));
  for (u64 i = 0; i < QSBR_SHARDS_NR; i++)
    spinlock_init(&q->shards[i].lock);
  return q;
}

  static inline struct qshard *
qsbr_shard(struct qsbr * const q, volatile u64 * const ptr)
{
  const u32 sid = mhash64((u64)ptr) >> QSBR_MHASH_SHIFT;
  debug_assert(sid < QSBR_SHARDS_NR);
  return &(q->shards[sid]);
}

  bool
qsbr_register(struct qsbr * const q, volatile u64 * const ptr)
{
  debug_assert(ptr);
  struct qshard * const shard = qsbr_shard(q, ptr);
  spinlock_lock(&(shard->lock));
  cpu_cfence();

  if (shard->bitmap < QSBR_BITMAP_FULL) {
    const u32 pos = (u32)__builtin_ctzl(~(shard->bitmap));
    debug_assert(pos < QSBR_STATES_NR);
    shard->bitmap |= (1lu << pos);
    shard->ptrs[pos] = ptr;
    cpu_cfence();
    spinlock_unlock(&(shard->lock));
    return true;
  }
  spinlock_unlock(&(shard->lock));
  return false;
}

  void
qsbr_unregister(struct qsbr * const q, volatile u64 * const ptr)
{
  if (ptr == NULL)
    return;
  struct qshard * const shard = qsbr_shard(q, ptr);
#pragma nounroll
  while (spinlock_trylock_nr(&(shard->lock), 64) == false) {
    (*ptr) = q->target;
    cpu_pause();
  }

  cpu_cfence();
  u64 bits = shard->bitmap;
  debug_assert(bits < QSBR_BITMAP_FULL);
  while (bits) { // bits contains ones
    const u32 pos = (u32)__builtin_ctzl(bits);
    debug_assert(pos < QSBR_STATES_NR);
    if (shard->ptrs[pos] == ptr) {
      shard->bitmap &= ~(1lu << pos);
      shard->ptrs[pos] = NULL;
      cpu_cfence();
      spinlock_unlock(&(shard->lock));
      return;
    }
    bits &= ~(1lu << pos);
  }
  debug_die();
  spinlock_unlock(&(shard->lock));
}

// waiters needs external synchronization
  void
qsbr_wait(struct qsbr * const q, const u64 target)
{
  q->target = target;
  for (u64 i = 0; i < QSBR_SHARDS_NR; i++)
    spinlock_lock(&(q->shards[i].lock));
  cpu_cfence();

  // collect wait_ptrs
  volatile u64 ** const wait_ptrs = q->wait_ptrs;
  u64 nwait = 0;
  for (u64 i = 0; i < QSBR_SHARDS_NR; i++) {
    struct qshard * const shard = &(q->shards[i]);
    u64 bits = shard->bitmap;
    while (bits) { // bits contains ones
      const u32 pos = (u32)__builtin_ctzl(bits);
      debug_assert(pos < QSBR_STATES_NR);
      if (*(shard->ptrs[pos]) != target)
        wait_ptrs[nwait++] = shard->ptrs[pos];
      bits &= ~(1lu << pos);
    }
  }

  // wait
  while (nwait) {
    for (u64 i = nwait - 1; i + 1; i--) { // nwait - 1 to 0
      if ((*(wait_ptrs[i])) == target) {
        // erase i
        if (i < (nwait - 1))
          wait_ptrs[i] = wait_ptrs[nwait - 1];
        nwait--;
      }
    }
  }
  cpu_cfence();
  for (u64 i = 0; i < QSBR_SHARDS_NR; i++)
    spinlock_unlock(&(q->shards[i].lock));
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

// }}} rcu

// forker {{{

// forker-papi {{{
#ifdef FORKER_PAPI
#include <papi.h>
#define FORKER_PAPI_MAX_EVENTS ((32))
__attribute__((constructor))
  static void
forker_papi_init(void)
{
  PAPI_library_init(PAPI_VER_CURRENT);
  PAPI_thread_init(pthread_self);
}

  static void *
forker_thread_func(void * const ptr)
{
  struct forker_worker_info * const wi = (typeof(wi))ptr;
  struct forker_papi_info * const papi_info = wi->papi_info;
  bool papi = false;
  int es = PAPI_NULL;
  if (papi_info && papi_info->nr && (PAPI_create_eventset(&es) == PAPI_OK)) {
    if (PAPI_OK == PAPI_add_events(es, papi_info->events, papi_info->nr)) {
      PAPI_start(es);
      papi = true;
    } else {
      PAPI_destroy_eventset(&es);
    }
  }
  void * const ret = wi->thread_func(ptr);
  if (papi) {
    u64 v[FORKER_PAPI_MAX_EVENTS];
    if (PAPI_OK == PAPI_stop(es, (long long *)v)) {
      for (u64 i = 0; i < papi_info->nr; i++) {
        vctr_set(wi->papi_vctr, i, v[i]);
      }
    }
    PAPI_destroy_eventset(&es);
  }
  return ret;
}

  static struct forker_papi_info *
forker_papi_prepare(void)
{
  char ** const tokens = string_tokens(getenv("FORKER_PAPI_EVENTS"), ",");
  if (tokens == NULL)
    return NULL;
  u64 nr_events = 0;
  int events[FORKER_PAPI_MAX_EVENTS]; // can't handle too much
  for (u64 i = 0; tokens[i] && (nr_events < FORKER_PAPI_MAX_EVENTS); i++)
    if (PAPI_OK == PAPI_event_name_to_code(tokens[i], &(events[nr_events])))
      nr_events++;

  struct forker_papi_info * const pi = malloc(sizeof(*pi) + (sizeof(pi->events[0]) * nr_events));
  pi->nr = nr_events;
  memcpy(pi->events, events, sizeof(pi->events[0]) * nr_events);
  return pi;
}

  static void
forker_papi_report(struct forker_papi_info * const papi_info,
    struct forker_worker_info ** const infov, const u64 cc, FILE * const out)
{
  if (papi_info == NULL)
    return;
  struct vctr * const va = vctr_create(papi_info->nr);
  for (u64 i = 0; i < cc; i++) {
    debug_assert(infov[i]->papi_vctr);
    vctr_merge(va, infov[i]->papi_vctr);
  }
  fprintf(out, "PAPI");
  char name[1024];
  for (u64 i = 0; i < papi_info->nr; i++) {
    PAPI_event_code_to_name(papi_info->events[i], name);
    fprintf(out, " %s %lu", name, vctr_get(va, i));
  }
  vctr_destroy(va);
}
#undef FORKER_PAPI_MAX_EVENTS
#else // no papi

  static void *
forker_thread_func(void * const ptr)
{
  struct forker_worker_info * const wi = (typeof(wi))ptr;
  return wi->thread_func(ptr);
}

  static struct forker_papi_info *
forker_papi_prepare(void)
{
  return NULL;
}

  static void
forker_papi_report(struct forker_papi_info * const papi_info,
    struct forker_worker_info ** const infov, const u64 cc, FILE * const out)
{
  (void)papi_info;
  (void)infov;
  (void)cc;
  (void)out;
  return;
}
#endif
// }}} forker-papi

  int
forker_pass(const int argc, char ** const argv, char ** const pref,
    struct pass_info * const pi, const int nr_wargs0)
{
#define FORKER_GEN_OPT_SYNC   ((0))
#define FORKER_GEN_OPT_WAIT   ((1))
#define FORKER_GEN_OPT_NOWAIT ((2))
  // pass <nth> <end-type> <magic> <repeat> <rgen_opt> <nr_wargs> ...
#define PASS_NR_ARGS ((7))
  if ((argc < PASS_NR_ARGS) || (strcmp(argv[0], "pass") != 0))
    return -1;

  const u32 c = a2u32(argv[1]);
  const u32 cc = c ? c : process_affinity_core_count();
  const u32 end_type = a2u32(argv[2]);
  const u64 magic = a2u64(argv[3]);
  const u32 repeat = a2u32(argv[4]);
  const u32 rgen_opt = a2u32(argv[5]);
  const int nr_wargs = atoi(argv[6]);
  if ((end_type > 1) || (rgen_opt > 2) || (nr_wargs != nr_wargs0))
    return -1;
  if (argc < (PASS_NR_ARGS + nr_wargs))
    return -1;

  const u32 nr_cores = process_affinity_core_count();
  u32 cores[nr_cores];
  process_affinity_core_list(nr_cores, cores);
  struct damp * const damp = damp_create(7, 0.004, 0.05);
  struct forker_papi_info * const papi_info = forker_papi_prepare();
  const char * const ascfg = getenv("FORKER_ASYNC_SHIFT");
  const u32 async_shift = ascfg ? ((u32)a2s32(ascfg)) : 1;

  char out[1024] = {};
  // per-worker data
  struct forker_worker_info info[cc];
  struct forker_worker_info *infov[cc];
  for (u32 i = 0; i < cc; i++) {
    memset(&(info[i]), 0, sizeof(info[i]));
    infov[i] = &(info[i]);
    info[i].thread_func = pi->wf;
    info[i].api = pi->api;
    info[i].map = pi->map;
    info[i].gen = rgen_dup(pi->gen0);
    info[i].seed = (i + 73) * 117;
    info[i].end_type = end_type;
    if (end_type == FORKER_END_COUNT) // else: endtime will be set later
      info[i].end_magic = magic;
    info[i].worker_id = i;
    info[i].conc = cc;

    // user args
    info[i].argc = nr_wargs;
    info[i].argv = argv + PASS_NR_ARGS;

    info[i].vctr = vctr_create(pi->vctr_size);
    if (papi_info) {
      info[i].papi_info = papi_info;
      info[i].papi_vctr = vctr_create(papi_info->nr);
    }

    if (rgen_opt != FORKER_GEN_OPT_SYNC) {
      const bool rconv = rgen_async_convert(info[i].gen, cores[i % nr_cores] + async_shift);
      (void)rconv;
      debug_assert(rconv);
    }
    info[i].rgen_next = (rgen_opt == FORKER_GEN_OPT_NOWAIT) ? info[i].gen->next_nowait : info[i].gen->next_wait;
  }

  bool done = false;
  const u64 t0 = time_nsec();
  // until: repeat times, or done determined by damp
  for (u32 r = 0; repeat ? (r < repeat) : (done == false); r++) {
    // prepare
    const u64 dt1 = time_diff_nsec(t0);
    for (u32 i = 0; i < cc; i++) {
      vctr_reset(info[i].vctr);
      if (info[i].papi_vctr)
        vctr_reset(info[i].papi_vctr);
      rgen_async_wait_all(info[i].gen);
    }

    // set end-time
    if (end_type == FORKER_END_TIME) {
      const u64 end_time = time_nsec() + (1000000000lu * magic);
      for (u32 i = 0; i < cc; i++)
        info[i].end_magic = end_time;
    }

    struct rusage rs0, rs1;
    getrusage(RUSAGE_SELF, &rs0);

    debug_perf_switch();
    const u64 dt = thread_fork_join(cc, forker_thread_func, true, (void **)infov);
    debug_perf_switch();

    getrusage(RUSAGE_SELF, &rs1);
    fprintf(stderr, "rss_kb %+ld ", rs1.ru_maxrss - rs0.ru_maxrss);

    struct vctr * const va = vctr_create(pi->vctr_size);
    for (u64 i = 0; i < cc; i++)
      vctr_merge(va, infov[i]->vctr);
    done = pi->af(va, dt, damp, out);
    vctr_destroy(va);

    forker_papi_report(papi_info, infov, cc, stderr);

    // stderr messages
    fprintf(stderr, " try %d %.2lf %.2lf ",
        r, ((double)dt1) * 1e-9, ((double)dt) * 1e-9);
    for (int i = 0; pref[i]; i++)
      fprintf(stderr, "%s ", pref[i]);
    for (int i = 0; i < (PASS_NR_ARGS + nr_wargs); i++)
      fprintf(stderr, "%s ", argv[i]);
    fprintf(stderr, "%s", out);
    fflush(stderr);
  }

  // clean up
  damp_destroy(damp);
  if (papi_info)
    free(papi_info);
  for (u64 i = 0; i < cc; i++) {
    rgen_destroy(info[i].gen);
    vctr_destroy(info[i].vctr);
    if (info[i].papi_vctr)
      vctr_destroy(info[i].papi_vctr);
  }

  // done messages
  for (int i = 0; pref[i]; i++)
    fprintf(stdout, "%s ", pref[i]);
  for (int i = 0; i < (PASS_NR_ARGS + nr_wargs); i++)
    fprintf(stdout, "%s ", argv[i]);
  fprintf(stdout, "%s", out);
  fflush(stdout);
  return PASS_NR_ARGS + nr_wargs;
#undef PASS_NR_ARGS
#undef FORKER_GEN_OPT_SYNC
#undef FORKER_GEN_OPT_WAIT
#undef FORKER_GEN_OPT_NOWAIT
}

  int
forker_passes(int argc, char ** argv, char ** const pref0,
    struct pass_info * const pi, const int nr_wargs0)
{
  char * pref[64];
  int np = 0;
  while (pref0[np]) {
    pref[np] = pref0[np];
    np++;
  }
  const int n1 = np;

  const int argc0 = argc;
  do {
    struct rgen * gen = NULL;
    if ((argc < 1) || (strcmp(argv[0], "rgen") != 0))
      break;

    const int n2 = rgen_helper(argc, argv, &gen);
    if (n2 < 0)
      return n2;

    memcpy(&(pref[n1]), argv, sizeof(argv[0]) * (size_t)n2);

    pref[n1 + n2] = NULL;
    argc -= n2;
    argv += n2;

    while ((argc > 0) && (strcmp(argv[0], "pass") == 0)) {
      pi->gen0 = gen;
      const int n3 = forker_pass(argc, argv, pref, pi, nr_wargs0);
      if (n3 < 0)
        return n3;

      argc -= n3;
      argv += n3;
    }

    rgen_destroy(gen);
  } while (argc > 0);
  return argc0 - argc;
}

  void
forker_passes_message(void)
{
  fprintf(stderr, "%s Usage: {rgen ... {pass ...}}\n", __func__);
  rgen_helper_message();
  fprintf(stderr, "%s Usage: pass <nth> " ANSI_ESCAPE(31) "<magic-type>" ANSI_ESCAPE(0), __func__);
  fprintf(stderr, " <magic> <repeat> " ANSI_ESCAPE(34) "<rgen-opt>" ANSI_ESCAPE(0));
  fprintf(stderr, " <nr-wargs> [<warg1> <warg2> ...]\n");
  fprintf(stderr, "%s " ANSI_ESCAPE(31) "magic-type: 0:time, 1:count" ANSI_ESCAPE(0) "\n", __func__);
  fprintf(stderr, "%s repeat: 0:auto\n", __func__);
  fprintf(stderr, "%s " ANSI_ESCAPE(34) "rgen-opt: 0:sync, 1:wait, 2:nowait" ANSI_ESCAPE(0) "\n", __func__);
  fprintf(stderr, "Compile with env FORKER_PAPI=y to enable papi (don't use with perf)\n");
  fprintf(stderr, "Run with env FORKER_PAPI_EVENTS=e1,e2,... to specify events\n");
  fprintf(stderr, "Run with env FORKER_ASYNC_SHIFT=s (?=1) to bind async-workers at core x+s\n");
}

  bool
forker_main(int argc, char ** argv, int(*test_func)(const int, char ** const))
{
  if (argc < 2)
    return false;

  if (strcmp(argv[0], "-") != 0) {
    const int fd1 = open(argv[0], O_CREAT | O_WRONLY | O_TRUNC, 00644);
    if (fd1 >= 0) {
      dup2(fd1, 1);
      close(fd1);
    }
  }

  if (strcmp(argv[1], "-") != 0) {
    const int fd2 = open(argv[1], O_CREAT | O_WRONLY | O_TRUNC, 00644);
    if (fd2 >= 0) {
      dup2(fd2, 2);
      close(fd2);
    }
  }
  // record args
  for (int i = 0; i < argc; i++)
    fprintf(stderr, " %s", argv[i]);

  fprintf(stderr, "\n");
  fflush(stderr);

  argc -= 2;
  argv += 2;

  while (argc) {
    if (strcmp(argv[0], "api") != 0) {
      fprintf(stderr, "%s need `api' keyword to start benchmark\n", __func__);
      return false;
    }
    const int consume = test_func(argc, argv);
    if (consume < 0)
      return false;

    debug_assert(consume <= argc);
    argc -= consume;
    argv += consume;
  }

  return true;
}
// }}} forker

// fdm: marker
