/*
 * Copyright (c) 2018-2019  Wu, Xingbo <wuxb45@gmail.com>
 *
 * All rights reserved. No warranty, explicit or implicit, provided.
 */
#define _GNU_SOURCE
#include "lib.h"
#include "kv.h"
#include "wh.h"
#include "ctypes.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

au64 seqno = 0;
u64 nloader = 0;
struct kv ** keys = NULL;
u64 nkeys = 0;
au64 tot = 0;
au64 wfail = 0;
u64 endtime = 0;

struct kvmap_info {
  const struct kvmap_api * api;
  void * map;
  bool has_iter;
};

  static void *
kv_load_worker(const struct kvmap_info * const info)
{
  const struct kvmap_api * const api = info->api;
  void * const map = info->map;
  srandom_u64(time_nsec() * time_nsec() * time_nsec());
  void * const ref = kvmap_ref(api, map);
  const u64 seq = atomic_fetch_add(&seqno, 1);
  const u64 n0 = nkeys / nloader * seq;
  const u64 nz = (seq == (nloader - 1)) ? nkeys : (nkeys / nloader * (seq + 1));
  //printf("load worker %lu %lu\n", n0, nz-1);

  struct rgen * const gi = rgen_new_uniform(8, 64); // avg 36 bytes
  char * buf = malloc(1024);
  debug_assert(buf);
  u64 * buf64 = (typeof(buf64))buf;
  for (u64 i = n0; i < nz; i++) {
    const u64 klen = rgen_next(gi);
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
    kvmap_kv_set(api, ref, keys[i]);
  }
  free(buf);
  rgen_destroy(gi);
  kvmap_unref(api, ref);
  return NULL;
}

  static void *
kv_unload_worker(const struct kvmap_info * const info)
{
  const struct kvmap_api * const api = info->api;
  void * const map = info->map;
  const u64 seq = atomic_fetch_add(&seqno, 1);
  const u64 n0 = nkeys / nloader * seq;
  const u64 nz = (seq == (nloader - 1)) ? nkeys : (nkeys / nloader * (seq + 1));

  void * const ref = kvmap_ref(api, map);
  for (u64 i = n0; i < nz; i++) {
    kvmap_kv_del(api, ref, keys[i]);
    free(keys[i]);
  }
  kvmap_unref(api, ref);
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
kv_stress_worker(const struct kvmap_info * const info)
{
  const struct kvmap_api * const api = info->api;
  void * const map = info->map;
  srandom_u64(time_nsec() * time_nsec() * time_nsec());
  void * ref = kvmap_ref(api, map);
  const bool rgen_sel = (random_u64() & 0x1000) == 0;
  struct rgen * const gi = rgen_sel ? rgen_new_uniform(0, nkeys-1) : rgen_new_zipfian(0, nkeys-1);
  struct kv * next = keys[rgen_next(gi)];
  u64 rnext = rgen_next(gi);
  struct kv * const getbuf = malloc(1000);
  debug_assert(getbuf);
  struct sbuf * const sbuf = malloc(1000);
  debug_assert(sbuf);
  void * iter = NULL;
  u64 wfail1 = 0;
#define BATCHSIZE ((4096))
  do {
    for (u64 i = 0; i < BATCHSIZE; i++) {
      // reading kv keys leads to unnecessary cache misses
      // use prefetch to minimize overhead on workload generation
      struct kv * const key = next;
      next = keys[rnext];
      cpu_prefetch0(next);
      cpu_prefetch0(((u8 *)next) + 64);
      rnext = rgen_next(gi);
      cpu_prefetch0(&(keys[rnext]));

      // do probe
      // customize your benchmark: do a mix of wh operations with switch-cases
      const u64 r = random_u64() % 16;
      //ctrs[r]++;
      switch (r) {
      case 0: case 1:
        kvmap_kv_probe(api, ref, key);
        break;
      case 2: case 3:
        kvmap_kv_get(api, ref, key, getbuf);
        break;
      case 4: case 5: case 6:
        if (info->has_iter) {
          iter = api->iter_create(ref);
          debug_assert(iter);
          kvmap_kv_iter_seek(api, iter, key);
          api->iter_next(iter, getbuf);
          api->iter_peek(iter, getbuf);
          api->iter_skip(iter, 2);
          api->iter_inp(iter, kv_plus1, NULL);
          api->iter_destroy(iter);
        }
        break;
      case 7: case 8:
        (void)kvmap_unref(api, ref);
        ref = kvmap_ref(api, map);
        break;
      case 9: case 10:
        (void)kvmap_kv_del(api, ref, key);
        break;
      case 11: case 12:
        if (api->inpr)
          kvmap_kv_inpr(api, ref, key, kv_plus1, NULL);
        break;
      case 13: case 14: case 15:
        if (!kvmap_kv_set(api, ref, key))
          wfail1++;
        break;
      default:
        break;
      }
    }
    tot += BATCHSIZE;
  } while (time_nsec() < endtime);
  wfail += wfail1;
  kvmap_unref(api, ref);
  rgen_destroy(gi);
  free(getbuf);
  free(sbuf);
  return NULL;
}

  static void
helper_msg(void)
{
  fprintf(stderr, "usage: [api ...] <#keys> [<#load-/unload-threads>=1] [<#threads>=1] [<rounds>=10] [<epochs>=10]\n");
  fprintf(stderr, "example: ./stresstest.out api wormhole 1000000 4 4\n");
  kvmap_api_helper_message();
}

  int
main(int argc, char ** argv)
{
  argc--;
  argv++;
  if (argc < 1) {
    helper_msg();
    exit(0);
  }

  const struct kvmap_api * api = NULL;
  void * map = NULL;
  if (!strcmp(argv[0], "api")) {
    const int n = kvmap_api_helper(argc, argv, NULL, true, &api, &map);
    if (n > 0) {
      argc -= n;
      argv += n;
    } else {
      helper_msg();
      exit(0);
    }
  } else {
    api = &kvmap_api_wormhole;
    map = wormhole_create(NULL);
  }
  const bool has_point = api->get && api->probe && api->del && api->set;
  if (!has_point) {
    fprintf(stderr, "api not supported\n");
    exit(0);
  }
  if (!api->inpr) {
    fprintf(stderr, "inplace function not found: ignored\n");
  }
  const bool has_iter = api->iter_create && api->iter_seek && api->iter_peek &&
                        api->iter_skip && api->iter_next && api->iter_inp && api->iter_destroy;
  if (!has_iter) {
    fprintf(stderr, "iter functions not complete: ignored\n");
  }

  // generate keys
  nkeys = a2u64(argv[0]);
  keys = malloc(sizeof(struct kv *) * nkeys);
  debug_assert(keys);
  nloader = (argc >= 2) ? a2u64(argv[1]) : 1; // # of loaders/unloaders
  const u64 nworker = (argc >= 3) ? a2u64(argv[2]) : 1;
  const u64 nrounds = (argc >= 4) ? a2u64(argv[3]) : 10; // default 10
  const u64 nepochs = (argc >= 5) ? a2u64(argv[4]) : 10; // default 10
  printf("stresstest: nkeys %lu th %lu r %lu e %lu\n", nkeys, nworker, nrounds, nepochs);
  struct kvmap_info info = {.api = api, .map = map, .has_iter = has_iter};

  for (u64 e = 0; e < nepochs; e++) {
    seqno = 0;
    const u64 dtl = thread_fork_join(nloader, (void *)kv_load_worker, false, &info);
    printf("load th %lu mops %.2lf\n", nloader, ((double)nkeys) * 1e3 / ((double)dtl));
    api->fprint(map, stdout);

    debug_perf_switch();
    for (u64 r = 0; r < nrounds; r++) {
      tot = 0;
      wfail = 0;
      endtime = time_nsec() + 2e9;
      const u64 dt = thread_fork_join(nworker, (void *)kv_stress_worker, false, &info);
      const double mops = ((double)tot) * 1e3 / ((double)dt);
      char ts[64];
      time_stamp(ts, 64);
      const long rssk = process_get_rss();
      printf("%s e %lu r %lu th %lu tot %lu mops %.2lf rss %ldkB wfail %lu\n",
          ts, e, r, nworker, tot, mops, rssk, wfail);
      debug_perf_switch();
    }
    seqno = 0;
    const u64 dtu = thread_fork_join(nloader, (void *)kv_unload_worker, false, &info);
    printf("unload th %lu mops %.2lf\n", nloader, ((double)nkeys) *1e3 / ((double)dtu));
  }

  free(keys);
  api->destroy(map);
  return 0;
}
