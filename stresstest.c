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
#include <immintrin.h>
#include <stdatomic.h>
#include <time.h>
#include <byteswap.h>
#include "wh.h"

atomic_uint_least64_t seqno = 0;
u64 nth = 0;
struct kv ** keys = NULL;
u64 nkeys = 0;
atomic_uint_least64_t tot = 0;
u64 endtime = 0;

  static void *
kv_load_worker(struct wormhole * const wh)
{
  srandom_u64(time_nsec() * time_nsec() * time_nsec());
  struct wormref * const ref = wormhole_ref(wh);
  const u64 seq = atomic_fetch_add(&seqno, 1);
  const u64 n0 = nkeys / nth * seq;
  const u64 nz = (seq == (nth - 1)) ? nkeys : (nkeys / nth * (seq + 1));
  printf("load worker %lu %lu\n", n0, nz-1);

  char * buf = malloc(1024);
  u64 * buf64 = (typeof(buf64))buf;
  for (u64 i = n0; i < nz; i++) {
    const u64 klen = 8 + (random_u64() & 0x3f);
    const u64 klen8 = (klen + 7) >> 3;
    buf64[0] = bswap_64(i); // little endian
    for (u64 j = 1; j < klen8; j++)
      buf64[j] = random_u64();

    keys[i] = kv_create(buf, klen, buf, 8); // vlen == 8
    wormhole_set(ref, keys[i]);
  }
  free(buf);
  wormhole_unref(ref);
  return NULL;
}

  static void
kv_plus1(struct kv * const kv0, void * const priv)
{
  (void)priv;
  // WARNING! the inplace function should never change struct-kv's metadata and key
  u64 * pv = kv_vptr(kv0);
  (*pv)++;
}

  static void *
kv_probe_worker(struct wormhole * const wh)
{
  srandom_u64(time_nsec() * time_nsec() * time_nsec());
  struct wormref * ref = wormhole_ref(wh);
  struct kv * next = keys[random_u64() % nkeys];
  u64 rnext = random_u64() % nkeys;
  struct kv * const getbuf = malloc(1000);
  struct sbuf * const sbuf = malloc(1000);
  struct wormhole_iter * iter;
#define BATCHSIZE ((4096))
  do {
    for (u64 i = 0; i < BATCHSIZE; i++) {
      // reading kv keys leads to unnecessary cache misses
      // use prefetch to minimize overhead on workload generation
      struct kv * const key = next;
      next = keys[rnext];
      __builtin_prefetch(next, 0);
      __builtin_prefetch(((u8 *)next) + 64, 0);
      rnext = random_u64() % nkeys;
      __builtin_prefetch(&(keys[rnext]), 0);

      // do probe
      // customize your benchmark: do a mix of wh operations with switch-cases
      const u64 r = random_u64() % 16;
      //ctrs[r]++;
      switch (r) {
      case 0:
        (void)wormhole_probe(ref, key);
        break;
      case 1:
        (void)wormhole_get(ref, key, getbuf);
        break;
      case 2:
        (void)wormhole_getv(ref, key, sbuf);
        break;
      case 3:
        (void)wormhole_getu64(ref, key);
        break;
      case 4: case 5: case 6:
        iter = wormhole_iter_create(ref);
        wormhole_iter_seek(iter, key);
        for (u64 n = 0; n < r; n++)
          wormhole_iter_next(iter, getbuf);
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
        (void)wormhole_inplace(ref, key, kv_plus1, NULL);
        break;
      case 13: case 14: case 15:
        (void)wormhole_set(ref, key);
        break;
      default:
        break;
      }
    }
    tot += BATCHSIZE;
  } while (time_nsec() < endtime);
  wormhole_unref(ref);
  free(getbuf);
  free(sbuf);
  return NULL;
}


  int
main(int argc, char ** argv)
{
  if (argc < 4) {
    printf("usage: <#keys> <#load-threads> <#threads> [<rounds>]\n");
    printf("  Example: %s 1000000 4 10\n", argv[0]);
    printf("  Better to use only one numa node with numactl -N 0\n");
    printf("  Better to run X thread on X cores\n");
    return 0;
  }

  // generate keys
  nkeys = strtoull(argv[1], NULL, 10);
  keys = malloc(sizeof(struct kv *) * nkeys);

  // gen keys and load (4)
  struct wormhole * const wh = wormhole_create(NULL);
  nth = strtoull(argv[2], NULL, 10);
  const double dtl = thread_fork_join(nth, (void *)kv_load_worker, false, (void *)wh);
  printf("gen and load x%lu  %.2lf mops\n", nth, ((double)nkeys) / dtl * 1e-6);

  nth = strtoull(argv[3], NULL, 10);
  printf("stresstest with %lu threads.\n", nth);
  u64 todo = (argc >= 5) ? strtoull(argv[4], NULL, 10) : ~0lu; // default is forever
  while (todo--) {
    tot = 0;
    endtime = time_nsec() + 2e9;
    const double dt = thread_fork_join(nth, (void *)kv_probe_worker, false, (void *)wh);
    const double mops = ((double)tot) / dt * 1e-6;
    time_t now;
    time(&now);
    struct tm nowtm;
    localtime_r(&now, &nowtm);
    char timestamp[64] = {};
    strftime(timestamp, 64, "%F %T %Z (%z)", &nowtm);
    printf("%s stresstest x%lu %.2lf mops\n", timestamp, nth, mops);
  }

  // final clean up for valgrind
  for (u64 i = 0; i < nkeys; i++)
    free(keys[i]);
  free(keys);
  wormhole_destroy(wh);
  return 0;
}
