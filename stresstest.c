/*
 * Copyright (c) 2016-2020  Wu, Xingbo <wuxb45@gmail.com>
 *
 * All rights reserved. No warranty, explicit or implicit, provided.
 */
#define _GNU_SOURCE

#include "lib.h"
#include "kv.h"
#include "wh.h"
#include "ctypes.h"

struct stress_info {
  u64 nkeys;
  u32 nloader;
  u32 nunldr;
  u32 nth;
  u32 cpt;
  bool has_iter;

  au64 seqno;
  struct kv ** keys;

  const struct kvmap_api * api;
  void * map;
  au64 tot;
  au64 wfail;
  u64 endtime;
};

  static void *
stress_load_worker(void * ptr)
{
  struct stress_info * const si = (typeof(si))ptr;
  srandom_u64(time_nsec() * time_nsec() / time_nsec());
  void * const ref = kvmap_ref(si->api, si->map);
  const u64 seq = atomic_fetch_add(&si->seqno, 1);
  const u64 n0 = si->nkeys / si->nloader * seq;
  const u64 nz = (seq == (si->nloader - 1)) ? si->nkeys : (si->nkeys / si->nloader * (seq + 1));
  //printf("load worker %lu %lu\n", n0, nz-1);

  char * buf = malloc(128);
  debug_assert(buf);
  u64 * buf64 = (typeof(buf64))buf;
  for (u64 i = n0; i < nz; i++) {
    const u32 klen = (u32)(random_u64() & 0x3flu) + 8;
    const u32 klen8 = (klen + 7) >> 3;
    /*
       buf64[0] = bswap_64(i); // little endian
       for (u64 j = 1; j < klen8; j++)
       buf64[j] = random_u64();
     */
    const u64 rkey = random_u64();
    for (u32 j = 0; j < klen8; j++)
      buf64[j] = (rkey >> j) & 0x0101010101010101lu;

    si->keys[i] = kv_create(buf, klen, buf, 8);
    if (si->keys[i] == NULL)
      exit(0);
    kvmap_kv_put(si->api, ref, si->keys[i]);
  }
  free(buf);
  kvmap_unref(si->api, ref);
  return NULL;
}

  static void *
stress_unload_worker(void * ptr)
{
  struct stress_info * const si = (typeof(si))ptr;
  const u64 seq = atomic_fetch_add(&si->seqno, 1);
  const u64 n0 = si->nkeys / si->nunldr * seq;
  const u64 nz = (seq == (si->nunldr - 1)) ? si->nkeys : (si->nkeys / si->nunldr * (seq + 1));

  void * const ref = kvmap_ref(si->api, si->map);
  for (u64 i = n0; i < nz; i++) {
    kvmap_kv_del(si->api, ref, si->keys[i]);
    free(si->keys[i]);
  }
  kvmap_unref(si->api, ref);
  return NULL;
}

  static void
stress_inp_plus1(struct kv * const kv0, void * const priv)
{
  (void)priv;
  if (kv0) { // can be NULL
    u64 * ptr = kv_vptr(kv0);
    ++(*ptr);
  }
}

  static struct kv *
stress_merge_plus1(struct kv * const kv0, void * const priv)
{
  (void)priv;
  if (kv0) { // can be NULL
    u64 * ptr = kv_vptr(kv0);
    ++(*ptr);
    return kv0;
  } else {
    u64 * ptr = kv_vptr((struct kv *)priv);
    *ptr = 0;
    return priv;
  }
}

  static void
stress_func(struct stress_info * const si)
{
  srandom_u64(time_nsec() * time_nsec() / time_nsec());
  const struct kvmap_api * const api = si->api;
  void * ref = kvmap_ref(api, si->map);
  struct kv * next = si->keys[random_u64() % si->nkeys];
  u64 rnext = random_u64() % si->nkeys;
  struct kv * const tmp = malloc(128);
  struct kref tmpkref;
  struct kvref tmpkvref;
  debug_assert(tmp);
  void * iter = NULL;
  if (api->iter_park) {
    iter = api->iter_create(ref);
    api->iter_park(iter);
  }
  u64 wfail1 = 0;
  u64 nops = 0;
#define BATCHSIZE ((4096))
  do {
    for (u64 i = 0; i < BATCHSIZE; i++) {
      // reading kv keys leads to unnecessary cache misses
      // use prefetch to minimize overhead on workload generation
      struct kv * const key = next;
      next = si->keys[rnext];
      cpu_prefetch0(next);
      cpu_prefetch0(((u8 *)next) + 64);
      rnext = random_u64() % si->nkeys;
      cpu_prefetch0(&(si->keys[rnext]));

      // do probe
      // customize your benchmark: do a mix of wh operations with switch-cases
      const u64 r = random_u64() % 16;
      switch (r) {
      case 0:
        kvmap_kv_probe(api, ref, key);
        break;
      case 1:
        kvmap_kv_get(api, ref, key, tmp);
        break;
      case 2:
        if (si->has_iter) {
          if (api->iter_park == NULL)
            iter = api->iter_create(ref);
          debug_assert(iter);
          kvmap_kv_iter_seek(api, iter, key);
          api->iter_next(iter, tmp);
          api->iter_peek(iter, tmp);
          api->iter_skip(iter, 2);
          // this is unsafe; only reader's lock is acquired
          if (api->iter_inp)
            api->iter_inp(iter, stress_inp_plus1, NULL);
          // kref
          if (api->iter_kref)
            api->iter_kref(iter, &tmpkref);
          // kvref
          if (api->iter_kvref)
            api->iter_kvref(iter, &tmpkvref);
          // done
          if (api->iter_park)
            api->iter_park(iter);
          else
            api->iter_destroy(iter);
        }
        break;
      case 3:
        if (api->refpark) {
          api->park(ref);
          api->resume(ref);
        }
        break;
      case 4:
        if (api->iter_park)
          api->iter_destroy(iter);
        (void)kvmap_unref(api, ref);
        ref = kvmap_ref(api, si->map);
        if (api->iter_park)
          iter = api->iter_create(ref);
        break;
      case 5:
        if (api->merge) {
          kv_dup2_key(key, tmp);
          tmp->vlen = 8;
          kvmap_kv_merge(api, ref, key, stress_merge_plus1, tmp);
        }
        break;
      case 6:
        if ((random_u64() & 0x7fffu) == 0x22 && api->delr)
          (void)kvmap_kv_delr(api, ref, si->keys[rnext], (rnext + 10) < si->nkeys ? si->keys[rnext + 10] : NULL);
        else
          kvmap_kv_probe(api, ref, key);
        break;
      case 7: case 8: case 9:
        (void)kvmap_kv_del(api, ref, key);
        break;
      case 10: case 11:
        if (api->inpw)
          kvmap_kv_inpw(api, ref, key, stress_inp_plus1, NULL);
        break;
      case 12: case 13: case 14: case 15:
        if (!kvmap_kv_put(api, ref, key))
          wfail1++;
        break;
      default:
        break;
      }
    }
    nops += BATCHSIZE;
  } while (time_nsec() < si->endtime);
  si->wfail += wfail1;
  if (api->iter_park)
    api->iter_destroy(iter);
  kvmap_unref(api, ref);
  free(tmp);
  si->tot += nops;
}

  static void
stress_co_worker(void)
{
  struct stress_info * const si = (typeof(si))co_priv();
  debug_assert(si);
  stress_func(si);
}

  static void *
stress_thread_worker(void * ptr)
{
  struct stress_info * const si = (typeof(si))ptr;
  if (si->cpt) {
    u64 hostrsp = 0;
    struct corr * crs[32];
    do { // to work smoothly with ALLOCFAIL
      crs[0] = corr_create(16*PGSZ, stress_co_worker, si, &hostrsp);
    } while (crs[0] == NULL);
    for (u32 j = 1; j < si->cpt; j++) {
      do { // to work smoothly with ALLOCFAIL
        crs[j] = corr_link(16*PGSZ, stress_co_worker, si, crs[j-1]);
      } while (crs[j] == NULL);
    }

    corr_enter(crs[0]);
    for (u32 j = 0; j < si->cpt; j++)
      corr_destroy(crs[j]);
  } else {
    stress_func(si);
  }
  return NULL;
}

  int
main(int argc, char ** argv)
{
  struct stress_info si = {.nkeys = 10000, .nloader = 1, .nunldr = 1, .nth = 1, .cpt = 0};
  argc--;
  argv++;
  int n = -1;
  if ((n = kvmap_api_helper(argc, argv, NULL, &si.api, &si.map)) < 0) {
    fprintf(stderr, "usage: api ... [<#keys>=10000 [<#load-threads>=1 [<#unload-threads>=1 [<#threads>=1 [<#co-per-thread>=0 (disabled) [<rounds>=1 [<epochs>=1]]]]]]]\n");
    kvmap_api_helper_message();
    exit(0);
  }
  argc -= n;
  argv += n;

  const bool has_point = si.api->get && si.api->probe && si.api->del && si.api->put;
  if (!has_point) {
    fprintf(stderr, "api not supported\n");
    exit(0);
  }
  if (!si.api->inpw)
    fprintf(stderr, "api->inpw function not found: ignored\n");
  if (!si.api->merge)
    fprintf(stderr, "api->merge function not found: ignored\n");
  if (!si.api->delr)
    fprintf(stderr, "api->delr function not found: ignored\n");

  si.has_iter = si.api->iter_create && si.api->iter_seek && si.api->iter_peek &&
    si.api->iter_skip && si.api->iter_next && si.api->iter_destroy;
  if (!si.has_iter)
    fprintf(stderr, "iter functions not complete: ignored\n");

  // generate keys
  if (argc >= 1)
    si.nkeys = a2u64(argv[0]);
  si.keys = malloc(sizeof(struct kv *) * si.nkeys);
  debug_assert(si.keys);
  if (argc >= 2)
    si.nloader = a2u32(argv[1]);
  if (argc >= 3)
    si.nunldr = a2u32(argv[2]);
  if (argc >= 4)
    si.nth = a2u32(argv[3]);
  if (argc >= 5)
    si.cpt = a2u32(argv[4]);
  if (si.cpt > 32)
    si.cpt = 32;
#if !defined(CORR)
  if (si.cpt > 1)
    fprintf(stderr, TERMCLR(35) "CORR not enabled. Compile with -DCORR to enable it.\n" TERMCLR(0));
#endif // CORR
  const u64 nr = (argc >= 6) ? a2u64(argv[5]) : 1; // default 1
  const u64 ne = (argc >= 7) ? a2u64(argv[6]) : 1; // default 1
  printf("stresstest: nkeys %lu ldr %u uldr %u th %u cpt %u r %lu e %lu\n",
      si.nkeys, si.nloader, si.nunldr, si.nth, si.cpt, nr, ne);

  for (u64 e = 0; e < ne; e++) {
    si.seqno = 0;
    const u64 dtl = thread_fork_join(si.nloader, (void *)stress_load_worker, false, &si);
    printf("load th %u mops %.2lf\n", si.nloader, ((double)si.nkeys) * 1e3 / ((double)dtl));
    if (si.api->fprint)
      si.api->fprint(si.map, stdout);

    debug_perf_switch();
    for (u64 r = 0; r < nr; r++) {
      si.tot = 0;
      si.wfail = 0;
      si.endtime = time_nsec() + 2000000000lu;
      const u64 dt = thread_fork_join(si.nth, (void *)stress_thread_worker, false, &si);
      const double mops = ((double)si.tot) * 1e3 / ((double)dt);
      char ts[64];
      time_stamp(ts, 64);
      const long rss = process_get_rss();
      printf("%s e %lu r %lu th %u cpt %u tot %lu mops %.2lf rss %ldkB wfail %lu\n",
          ts, e, r, si.nth, si.cpt, si.tot, mops, rss, si.wfail);
      debug_perf_switch();
    }
    si.seqno = 0;
    if (si.nunldr == 0) { // use clean
      const u64 t0 = time_nsec();
      si.api->clean(si.map);
      const u64 dtu = time_diff_nsec(t0);
      for (u64 i = 0; i < si.nkeys; i++)
        free(si.keys[i]);
      printf("clean mops %.2lf\n", ((double)si.nkeys) *1e3 / ((double)dtu));
    } else {
      const u64 dtu = thread_fork_join(si.nunldr, (void *)stress_unload_worker, false, &si);
      printf("unload th %u mops %.2lf\n", si.nunldr, ((double)si.nkeys) *1e3 / ((double)dtu));
    }
  }

  free(si.keys);
  si.api->destroy(si.map);
  return 0;
}
