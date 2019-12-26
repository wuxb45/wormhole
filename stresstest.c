/*
 * Copyright (c) 2018-2019  Wu, Xingbo <wuxb45@gmail.com>
 *
 * All rights reserved. No warranty, explicit or implicit, provided.
 */
#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdatomic.h>
#include <byteswap.h>
#include "lib.h"
#include "wh.h"

atomic_uint_least64_t seqno = 0;
u64 nloader = 0;
struct kv ** keys = NULL;
u64 nkeys = 0;
atomic_uint_least64_t tot = 0;
atomic_uint_least64_t wfail = 0;
u64 endtime = 0;

  static void *
kv_load_worker(struct wormhole * const wh)
{
  srandom_u64(time_nsec() * time_nsec() * time_nsec());
  struct wormref * const ref = wormhole_ref(wh);
  const u64 seq = atomic_fetch_add(&seqno, 1);
  const u64 n0 = nkeys / nloader * seq;
  const u64 nz = (seq == (nloader - 1)) ? nkeys : (nkeys / nloader * (seq + 1));
  //printf("load worker %lu %lu\n", n0, nz-1);

  struct rgen * const gi = rgen_new_uniform(8, 64); // avg 36 bytes
  char * buf = malloc(1024);
  debug_assert(buf);
  u64 * buf64 = (typeof(buf64))buf;
  for (u64 i = n0; i < nz; i++) {
    const u64 klen = rgen_next_wait(gi);
    const u64 klen8 = (klen + 7) >> 3;
    /*
       buf64[0] = bswap_64(i); // little endian
       for (u64 j = 1; j < klen8; j++)
       buf64[j] = random_u64();
     */
    const u64 rkey = random_u64();
    for (u64 j = 0; j < klen8; j++)
      buf64[j] = (rkey >> j) & 0x0101010101010101lu;

    keys[i] = kv_create(buf, klen, buf, 8);
    if (keys[i] == NULL)
      exit(0);
    wormhole_set(ref, keys[i]);
  }
  free(buf);
  rgen_destroy(gi);
  wormhole_unref(ref);
  return NULL;
}

  static void *
kv_unload_worker(struct wormhole * const wh)
{
  struct wormref * const ref = wormhole_ref(wh);
  const u64 seq = atomic_fetch_add(&seqno, 1);
  const u64 n0 = nkeys / nloader * seq;
  const u64 nz = (seq == (nloader - 1)) ? nkeys : (nkeys / nloader * (seq + 1));
  //printf("unload worker %lu %lu\n", n0, nz-1);

  for (u64 i = n0; i < nz; i++) {
    wormhole_del(ref, keys[i]);
    free(keys[i]);
  }
  wormhole_unref(ref);
  return NULL;
}

  static void
kv_plus1(struct kv * const kv0, void * const priv)
{
  (void)priv;
  if (kv0) { // can be NULL
    u64 * ptr = kv_vptr(kv0);
    ++(*ptr);
  }
}

  static void *
kv_probe_worker(struct wormhole * const wh)
{
  srandom_u64(time_nsec() * time_nsec() * time_nsec());
  struct wormref * ref = wormhole_ref(wh);
  const bool rgen_sel = time_nsec() & 1;
  struct rgen * const gi = rgen_sel ? rgen_new_uniform(0, nkeys-1) : rgen_new_zipfian(0, nkeys-1);
  struct kv * next = keys[rgen_next_wait(gi)];
  u64 rnext = rgen_next_wait(gi);
  struct kv * const getbuf = malloc(1000);
  debug_assert(getbuf);
  struct sbuf * const sbuf = malloc(1000);
  debug_assert(sbuf);
  struct wormhole_iter * iter;
  u64 wfail1 = 0;
#define BATCHSIZE ((4096))
  do {
    for (u64 i = 0; i < BATCHSIZE; i++) {
      // reading kv keys leads to unnecessary cache misses
      // use prefetch to minimize overhead on workload generation
      struct kv * const key = next;
      next = keys[rnext];
      cpu_prefetchr(next, 0);
      cpu_prefetchr(((u8 *)next) + 64, 0);
      rnext = rgen_next_wait(gi);
      cpu_prefetchr(&(keys[rnext]), 0);

      // do probe
      // customize your benchmark: do a mix of wh operations with switch-cases
      const u64 r = random_u64() % 16;
      //ctrs[r]++;
      switch (r) {
      case 0: case 1:
        (void)wormhole_probe(ref, key);
        break;
      case 2: case 3:
        (void)wormhole_get(ref, key, getbuf);
        break;
      case 4: case 5: case 6:
        iter = wormhole_iter_create(ref);
        debug_assert(iter);
        wormhole_iter_seek(iter, key);
        wormhole_iter_next(iter, getbuf);
        wormhole_iter_peek(iter, getbuf);
        wormhole_iter_skip(iter, 2);
        wormhole_iter_inplace(iter, kv_plus1, NULL);
        wormhole_iter_destroy(iter);
        break;
      case 7: case 8:
        (void)wormhole_unref(ref);
        ref = wormhole_ref(wh);
        break;
      case 9: case 10:
        (void)wormhole_del(ref, key);
        break;
      case 11: case 12:
        wormhole_inplace(ref, key, kv_plus1, NULL);
        break;
      case 13: case 14: case 15:
        if (!wormhole_set(ref, key))
          wfail1++;
        break;
      default:
        break;
      }
    }
    tot += BATCHSIZE;
  } while (time_nsec() < endtime);
  wfail += wfail1;
  wormhole_unref(ref);
  rgen_destroy(gi);
  free(getbuf);
  free(sbuf);
  return NULL;
}


  int
main(int argc, char ** argv)
{
  if (argc < 2) {
    fprintf(stderr, "usage: <#keys> [<#load-/unload-threads>=1] [<#threads>=1] [<rounds>=10] [<epochs>=10]\n");
    return 0;
  }

  // gen keys and load (4)
  struct wormhole * const wh = wormhole_create(NULL);
  if (wh == NULL) {
    fprintf(stderr, "wormhole_create failed\n");
    exit(0);
  }

  // generate keys
  nkeys = a2u64(argv[1]);
  keys = malloc(sizeof(struct kv *) * nkeys);
  debug_assert(keys);
  nloader = (argc >= 3) ? a2u64(argv[2]) : 1; // # of loaders/unloaders
  const u64 nworker = (argc >= 4) ? a2u64(argv[3]) : 1;
  const u64 nrounds = (argc >= 5) ? a2u64(argv[4]) : 10; // default 10
  const u64 nepochs = (argc >= 6) ? a2u64(argv[5]) : 10; // default 10
  printf("stresstest: th %lu r %lu e %lu\n", nworker, nrounds, nepochs);

  for (u64 e = 0; e < nepochs; e++) {
    seqno = 0;
    const u64 dtl = thread_fork_join(nloader, (void *)kv_load_worker, false, (void *)wh);
    printf("load th %lu mops %.2lf\n", nloader, ((double)nkeys) * 1e3 / ((double)dtl));

    debug_perf_switch();
    for (u64 r = 0; r < nrounds; r++) {
      tot = 0;
      wfail = 0;
      endtime = time_nsec() + 2e9;
      const u64 dt = thread_fork_join(nworker, (void *)kv_probe_worker, false, (void *)wh);
      const double mops = ((double)tot) * 1e3 / ((double)dt);
      char ts[64];
      time_stamp(ts, 64);
      const u64 rssk = process_get_rss() >> 12;
      printf("%s e %lu r %lu th %lu tot %lu mops %.2lf rss %lukB wfail %lu\n",
          ts, e, r, nworker, tot, mops, rssk, wfail);
      debug_perf_switch();
    }
    seqno = 0;
    const u64 dtu = thread_fork_join(nloader, (void *)kv_unload_worker, false, (void *)wh);
    printf("unload th %lu mops %.2lf\n", nloader, ((double)nkeys) *1e3 / ((double)dtu));
  }

  free(keys);
  wormhole_destroy(wh);
  return 0;
}
